"""
parser.py — Модуль парсинга файлов журналов событий Windows (.evtx)
читает бинарные .evtx файлы, извлекает из каждой записи ключевые поля
(Event ID, временная метка, источник, данные события) и возвращает
список унифицированных словарей для дальнейшего анализа.
"""

import os
from datetime import datetime, timezone
import Evtx.Evtx as evtx
from lxml import etree


# Пространство имён XML, используемое в .evtx файлах
NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'


def parse_evtx(file_path: str) -> list[dict]:
    """
    Парсит один .evtx файл и возвращает список событий.

    Каждое событие — словарь с полями:
        - event_id (int): идентификатор события
        - timestamp (datetime): время события в UTC
        - channel (str): журнал-источник (Security, System и т.д.)
        - computer (str): имя компьютера
        - provider (str): источник/провайдер события
        - event_data (dict): дополнительные поля события (зависят от Event ID)
        - raw_xml (str): исходный XML записи (для отладки)

    Args:
        file_path: путь к .evtx файлу

    Returns:
        Список словарей с данными событий
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Файл не найден: {file_path}")

    events = []

    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = etree.fromstring(xml_str.encode('utf-8'))

                # Извлекаем основные поля из блока <System>
                system = root.find(f'{NS}System')
                if system is None:
                    continue

                event_id = _get_event_id(system)
                timestamp = _get_timestamp(system)
                channel = _get_text(system, f'{NS}Channel')
                computer = _get_text(system, f'{NS}Computer')
                provider = _get_provider(system)

                # Извлекаем данные события из <EventData> или <UserData>
                event_data = _get_event_data(root)

                events.append({
                    'event_id': event_id,
                    'timestamp': timestamp,
                    'channel': channel,
                    'computer': computer,
                    'provider': provider,
                    'event_data': event_data,
                    'raw_xml': xml_str,
                })

            except Exception as e:
                # Пропускаем повреждённые записи, но считаем их
                continue

    return events


def parse_multiple(file_paths: list[str]) -> list[dict]:
    """
    Парсит несколько .evtx файлов и объединяет результаты.
    Сортирует итоговый список по времени события.
    """
    all_events = []
    for path in file_paths:
        print(f"  [*] Парсинг: {os.path.basename(path)}")
        events = parse_evtx(path)
        print(f"      Извлечено событий: {len(events)}")
        all_events.extend(events)

    # Сортируем по времени
    all_events.sort(key=lambda e: e['timestamp'] or datetime.min.replace(tzinfo=timezone.utc))
    return all_events


# ──────────────────────────────────────────────
#  Вспомогательные функции извлечения полей
# ──────────────────────────────────────────────

def _get_event_id(system) -> int:
    """Извлекает Event ID (учитывая возможный атрибут Qualifiers)."""
    el = system.find(f'{NS}EventID')
    if el is not None and el.text:
        return int(el.text)
    return 0


def _get_timestamp(system) -> datetime | None:
    """Извлекает временную метку из атрибута SystemTime."""
    tc = system.find(f'{NS}TimeCreated')
    if tc is not None:
        raw = tc.get('SystemTime', '')
        if raw:
            raw = raw.strip()

            # Убираем часовой пояс в конце (+00:00 или Z)
            if '+' in raw:
                raw = raw.split('+')[0]
            elif raw.endswith('Z'):
                raw = raw.rstrip('Z')

            # Заменяем пробел на T если нужно
            raw = raw.replace(' ', 'T')

            # Отделяем дробную часть и обрезаем до 6 знаков
            if '.' in raw:
                main_part, frac = raw.split('.', 1)
                frac = frac[:6].ljust(6, '0')
                raw = f"{main_part}.{frac}"
                fmt = '%Y-%m-%dT%H:%M:%S.%f'
            else:
                fmt = '%Y-%m-%dT%H:%M:%S'

            try:
                return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                return None
    return None


def _get_text(parent, tag: str) -> str:
    """Безопасно извлекает текст из XML-элемента."""
    el = parent.find(tag)
    return el.text.strip() if el is not None and el.text else ''


def _get_provider(system) -> str:
    """Извлекает имя провайдера события."""
    el = system.find(f'{NS}Provider')
    if el is not None:
        return el.get('Name', '')
    return ''


def _get_event_data(root) -> dict:
    """
    Извлекает данные из блока <EventData> или <UserData>.

    <EventData> содержит элементы <Data Name="...">значение</Data>.
    Возвращает словарь {имя_поля: значение}.
    """
    data = {}

    # Пробуем <EventData>
    event_data = root.find(f'{NS}EventData')
    if event_data is not None:
        for item in event_data.findall(f'{NS}Data'):
            name = item.get('Name', 'unnamed')
            value = item.text or ''
            data[name] = value
        return data

    # Пробуем <UserData> — используется некоторыми провайдерами
    user_data = root.find(f'{NS}UserData')
    if user_data is not None:
        for child in user_data:
            for item in child:
                tag = item.tag.split('}')[-1] if '}' in item.tag else item.tag
                data[tag] = item.text or ''
        return data

    return data