"""
reporter.py — Модуль формирования отчётов

Генерирует HTML-отчёт с результатами анализа:
сводка, таймлайн событий, детали по каждому срабатыванию,
коррелированные инциденты.
"""

import os
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

from correlator import Alert, CorrelatedAlert
from rules import Severity


def generate_html_report(results: dict, output_path: str, template_dir: str = "templates"):
    """
    Генерирует HTML-отчёт по результатам анализа.

    Args:
        results: словарь от EventCorrelator.analyze()
        output_path: путь для сохранения HTML-файла
        template_dir: папка с шаблоном report.html
    """
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=True,
    )

    # Регистрируем фильтры для шаблона
    env.filters['severity_color'] = _severity_color
    env.filters['severity_icon'] = _severity_icon
    env.filters['format_time'] = _format_time

    template = env.get_template("report.html")

    # Подготавливаем данные для шаблона
    template_data = {
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'total_events': results['total_events'],
        'summary': results['summary'],
        'alerts': _prepare_alerts(results['alerts']),
        'correlated': _prepare_correlated(results['correlated']),
        'timeline': _build_timeline(results['alerts']),
    }

    html = template.render(**template_data)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"\n[✓] Отчёт сохранён: {os.path.abspath(output_path)}")


def generate_csv_report(results: dict, output_path: str):
    """
    Генерирует CSV-отчёт (упрощённый) для импорта в Excel.
    """
    import csv

    with open(output_path, 'w', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f, delimiter=';')
        writer.writerow([
            'Время', 'Правило', 'Event ID', 'Критичность',
            'Категория', 'Компьютер', 'Детали'
        ])

        for alert in results['alerts']:
            writer.writerow([
                _format_time(alert.timestamp),
                f"{alert.rule.rule_id} — {alert.rule.name}",
                alert.event['event_id'],
                alert.rule.severity.value,
                alert.rule.category.value,
                alert.event.get('computer', 'N/A'),
                alert.details,
            ])

    print(f"[✓] CSV-отчёт сохранён: {os.path.abspath(output_path)}")


# ──────────────────────────────────────────────
#  Подготовка данных для шаблона
# ──────────────────────────────────────────────

def _prepare_alerts(alerts: list[Alert]) -> list[dict]:
    """Преобразует алерты в словари для шаблона."""
    prepared = []
    for alert in alerts:
        prepared.append({
            'rule_id': alert.rule.rule_id,
            'name': alert.rule.name,
            'description': alert.rule.description,
            'event_id': alert.event['event_id'],
            'timestamp': alert.timestamp,
            'severity': alert.rule.severity.value,
            'category': alert.rule.category.value,
            'computer': alert.event.get('computer', 'N/A'),
            'channel': alert.event.get('channel', 'N/A'),
            'details': alert.details,
            'event_data': alert.event.get('event_data', {}),
        })
    return prepared


def _prepare_correlated(correlated: list[CorrelatedAlert]) -> list[dict]:
    """Преобразует коррелированные алерты в словари для шаблона."""
    prepared = []
    for corr in correlated:
        prepared.append({
            'name': corr.name,
            'description': corr.description,
            'severity': corr.severity.value,
            'category': corr.category.value,
            'start_time': corr.start_time,
            'end_time': corr.end_time,
            'source_ip': corr.source_ip,
            'target_account': corr.target_account,
            'event_count': corr.event_count,
            'alerts_count': len(corr.alerts),
        })
    return prepared


def _build_timeline(alerts: list[Alert]) -> list[dict]:
    """
    Строит таймлайн — список событий, сгруппированных по часам.
    Используется для визуализации активности во времени.
    """
    hourly = {}
    for alert in alerts:
        if alert.timestamp:
            hour_key = alert.timestamp.strftime('%Y-%m-%d %H:00')
            if hour_key not in hourly:
                hourly[hour_key] = {
                    'hour': hour_key,
                    'total': 0,
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                }
            hourly[hour_key]['total'] += 1
            hourly[hour_key][alert.rule.severity.value] += 1

    return sorted(hourly.values(), key=lambda x: x['hour'])


# ──────────────────────────────────────────────
#  Фильтры для Jinja2-шаблона
# ──────────────────────────────────────────────

def _severity_color(severity: str) -> str:
    """Возвращает CSS-цвет для уровня критичности."""
    colors = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#ca8a04',
        'low': '#2563eb',
        'info': '#6b7280',
    }
    return colors.get(severity, '#6b7280')

def _severity_color(severity: str) -> str:
    """Возвращает CSS-цвет для уровня критичности."""
    colors = {
        'critical': '#D44D5C',
        'high': '#E3B5A4',
        'medium': '#ca8a04',
        'low': '#9f7aea',
        'info': '#773344',
    }
    return colors.get(severity, '#773344')

def _severity_icon(severity: str) -> str:
    """Возвращает символ-иконку для уровня критичности."""
    icons = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🔵',
        'info': '⚪',
    }
    return icons.get(severity, '⚪')

def _format_time(dt) -> str:
    """Форматирует datetime в читаемую строку."""
    if dt is None:
        return 'N/A'
    if isinstance(dt, datetime):
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return str(dt)