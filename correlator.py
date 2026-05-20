"""
correlator.py — Модуль корреляции событий

Анализирует поток событий, применяет правила детекции из rules.py,
а затем выявляет сложные паттерны атак, которые невозможно обнаружить
по одиночным событиям (например, брутфорс = серия неудачных входов).
"""

from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dataclasses import dataclass, field

from rules import (
    DetectionRule, DETECTION_RULES, match_rule,
    Severity, Category
)


@dataclass
class Alert:
    """
    Одно срабатывание (алерт) — результат обнаружения подозрительной активности.

    Attributes:
        rule: правило, которое сработало
        event: событие, вызвавшее срабатывание
        timestamp: время события
        details: человекочитаемое описание с конкретными данными
    """
    rule: DetectionRule
    event: dict
    timestamp: datetime
    details: str


@dataclass
class CorrelatedAlert:
    """
    Коррелированный алерт — группа связанных срабатываний,
    объединённых в один инцидент.

    Например: 15 событий «Неудачный вход» → один алерт «Брутфорс».
    """
    name: str
    description: str
    severity: Severity
    category: Category
    alerts: list[Alert] = field(default_factory=list)
    start_time: datetime | None = None
    end_time: datetime | None = None
    source_ip: str = ""
    target_account: str = ""
    event_count: int = 0


class EventCorrelator:
    """
    Основной класс анализа.

    Принимает список событий, прогоняет через правила детекции,
    затем выполняет корреляцию для выявления сложных атак.
    """

    # Порог брутфорса: количество неудачных входов за указанный период
    BRUTE_FORCE_THRESHOLD = 5
    BRUTE_FORCE_WINDOW = timedelta(minutes=10)

    # Порог разведки: количество команд разведки за указанный период
    RECON_THRESHOLD = 3
    RECON_WINDOW = timedelta(minutes=5)

    def __init__(self, events: list[dict]):
        self.events = events
        self.alerts: list[Alert] = []
        self.correlated: list[CorrelatedAlert] = []

    def analyze(self) -> dict:
        """
        Главный метод — выполняет полный анализ.

        Returns:
            Словарь с результатами:
                - total_events: всего событий проанализировано
                - alerts: список одиночных срабатываний
                - correlated: список коррелированных инцидентов
                - summary: сводка по категориям и критичности
        """
        print("\n[1/3] Применение правил детекции...")
        self._apply_rules()
        print(f"      Найдено срабатываний: {len(self.alerts)}")

        print("[2/3] Корреляция событий...")
        self._correlate_brute_force()
        self._correlate_account_compromise()
        self._correlate_recon_burst()
        self._correlate_log_clear_after_activity()
        print(f"      Выявлено инцидентов: {len(self.correlated)}")

        print("[3/3] Формирование сводки...")
        summary = self._build_summary()

        return {
            'total_events': len(self.events),
            'alerts': self.alerts,
            'correlated': self.correlated,
            'summary': summary,
        }

    # ──────────────────────────────────────────────
    #  Этап 1: Применение одиночных правил
    # ──────────────────────────────────────────────

    def _apply_rules(self):
        """Проверяет каждое событие на соответствие каждому правилу."""
        for event in self.events:
            for rule in DETECTION_RULES:
                if match_rule(rule, event):
                    details = self._format_details(rule, event)
                    alert = Alert(
                        rule=rule,
                        event=event,
                        timestamp=event['timestamp'],
                        details=details,
                    )
                    self.alerts.append(alert)

    def _format_details(self, rule: DetectionRule, event: dict) -> str:
        """Формирует человекочитаемое описание срабатывания."""
        ed = event.get('event_data', {})
        parts = [rule.description]

        # Добавляем релевантные поля в зависимости от категории
        if rule.category == Category.BRUTE_FORCE:
            account = ed.get('TargetUserName', 'N/A')
            ip = ed.get('IpAddress', 'N/A')
            parts.append(f"Учётная запись: {account}, IP: {ip}")

        elif rule.category in (Category.LATERAL_MOVEMENT, Category.CREDENTIAL_ACCESS):
            account = ed.get('TargetUserName', ed.get('SubjectUserName', 'N/A'))
            ip = ed.get('IpAddress', ed.get('WorkstationName', 'N/A'))
            parts.append(f"Учётная запись: {account}, Источник: {ip}")

        elif rule.category == Category.ACCOUNT_MANIPULATION:
            target = ed.get('TargetUserName', 'N/A')
            subject = ed.get('SubjectUserName', 'N/A')
            parts.append(f"Цель: {target}, Выполнил: {subject}")

        elif rule.category == Category.PRIVILEGE_ESCALATION:
            member = ed.get('MemberName', ed.get('MemberSid', 'N/A'))
            group = ed.get('TargetUserName', 'N/A')
            parts.append(f"Пользователь: {member}, Группа: {group}")


        elif rule.category == Category.PERSISTENCE:
            if ed.get('ServiceName'):
                svc = ed.get('ServiceName', 'N/A')
                path = ed.get('ImagePath', 'N/A')
                account = ed.get('AccountName', 'N/A')
                parts.append(f"Служба: {svc}, Путь: {path}, Учётная запись: {account}")
            else:
                process = ed.get('NewProcessName', 'N/A')
                cmd = ed.get('CommandLine', 'N/A')
                user = ed.get('SubjectUserName', 'N/A')
                parts.append(f"Процесс: {process}, Команда: {cmd}, Пользователь: {user}")


        elif rule.category in (Category.SUSPICIOUS_PROCESS, Category.RECONNAISSANCE):
            process = ed.get('NewProcessName', ed.get('Image', 'N/A'))
            cmd = ed.get('CommandLine', 'N/A')
            user = ed.get('SubjectUserName', ed.get('User', 'N/A'))
            parts.append(f"Процесс: {process}, Команда: {cmd}, Пользователь: {user}")

        elif rule.category == Category.SUSPICIOUS_POWERSHELL:
            script = ed.get('ScriptBlockText', '')
            preview = script[:200] + '...' if len(script) > 200 else script
            parts.append(f"Фрагмент скрипта: {preview}")

        elif rule.category == Category.LOG_TAMPERING:
            subject = ed.get('SubjectUserName', 'N/A')
            parts.append(f"Выполнил: {subject}")

        return " | ".join(parts)

    # ──────────────────────────────────────────────
    #  Этап 2: Корреляция — выявление сложных атак
    # ──────────────────────────────────────────────

    def _correlate_brute_force(self):
        """
        Выявляет брутфорс: N+ неудачных входов с одного IP
        или к одной учётной записи за короткий период.
        """
        failed_logins = [a for a in self.alerts if a.rule.rule_id == "R001"]
        if len(failed_logins) < self.BRUTE_FORCE_THRESHOLD:
            return

        # Группируем по IP-адресу источника
        by_ip = defaultdict(list)
        for alert in failed_logins:
            ip = alert.event.get('event_data', {}).get('IpAddress', 'unknown')
            by_ip[ip].append(alert)

        for ip, ip_alerts in by_ip.items():
            if len(ip_alerts) < self.BRUTE_FORCE_THRESHOLD:
                continue

            # Сортируем по времени и ищем всплески
            ip_alerts.sort(key=lambda a: a.timestamp or datetime.min.replace(tzinfo=timezone.utc))
            window_start = 0

            for window_end in range(len(ip_alerts)):
                while (ip_alerts[window_end].timestamp - ip_alerts[window_start].timestamp
                       > self.BRUTE_FORCE_WINDOW):
                    window_start += 1

                count = window_end - window_start + 1
                if count >= self.BRUTE_FORCE_THRESHOLD:
                    target = ip_alerts[window_end].event.get(
                        'event_data', {}).get('TargetUserName', 'N/A')

                    corr = CorrelatedAlert(
                        name="Атака брутфорс",
                        description=f"Обнаружено {count} неудачных попыток входа "
                                    f"с IP {ip} за {self.BRUTE_FORCE_WINDOW.seconds // 60} минут.",
                        severity=Severity.HIGH,
                        category=Category.BRUTE_FORCE,
                        alerts=ip_alerts[window_start:window_end + 1],
                        start_time=ip_alerts[window_start].timestamp,
                        end_time=ip_alerts[window_end].timestamp,
                        source_ip=ip,
                        target_account=target,
                        event_count=count,
                    )
                    self.correlated.append(corr)
                    break  # Один коррелированный алерт на IP

    def _correlate_account_compromise(self):
        """
        Выявляет компрометацию учётной записи:
        создание учётки (4720) + добавление в админы (4732)
        в короткий промежуток.
        """
        creations = [a for a in self.alerts if a.rule.rule_id == "R005"]
        escalations = [a for a in self.alerts if a.rule.rule_id == "R006"]

        for creation in creations:
            created_user = creation.event.get('event_data', {}).get('TargetUserName', '')
            for escalation in escalations:
                esc_time = escalation.timestamp
                create_time = creation.timestamp

                if esc_time and create_time:
                    diff = abs((esc_time - create_time).total_seconds())
                    if diff <= 300:  # 5 минут
                        corr = CorrelatedAlert(
                            name="Создание привилегированной учётной записи",
                            description=f"Учётная запись '{created_user}' создана и добавлена "
                                        f"в группу администраторов в течение 5 минут.",
                            severity=Severity.CRITICAL,
                            category=Category.PRIVILEGE_ESCALATION,
                            alerts=[creation, escalation],
                            start_time=create_time,
                            end_time=esc_time,
                            target_account=created_user,
                            event_count=2,
                        )
                        self.correlated.append(corr)

    def _correlate_recon_burst(self):
        """
        Выявляет всплеск разведки: N+ команд разведки за короткий период.
        """
        recon_alerts = [a for a in self.alerts if a.rule.rule_id == "R013"]
        if len(recon_alerts) < self.RECON_THRESHOLD:
            return

        recon_alerts.sort(key=lambda a: a.timestamp or datetime.min.replace(tzinfo=timezone.utc))
        window_start = 0

        for window_end in range(len(recon_alerts)):
            while (recon_alerts[window_end].timestamp - recon_alerts[window_start].timestamp
                   > self.RECON_WINDOW):
                window_start += 1

            count = window_end - window_start + 1
            if count >= self.RECON_THRESHOLD:
                user = recon_alerts[window_end].event.get(
                    'event_data', {}).get('SubjectUserName', 'N/A')

                corr = CorrelatedAlert(
                    name="Всплеск разведки",
                    description=f"Обнаружено {count} команд разведки за "
                                f"{self.RECON_WINDOW.seconds // 60} минут. "
                                f"Пользователь: {user}.",
                    severity=Severity.HIGH,
                    category=Category.RECONNAISSANCE,
                    alerts=recon_alerts[window_start:window_end + 1],
                    start_time=recon_alerts[window_start].timestamp,
                    end_time=recon_alerts[window_end].timestamp,
                    target_account=user,
                    event_count=count,
                )
                self.correlated.append(corr)
                break

    def _correlate_log_clear_after_activity(self):
        """
        Выявляет заметание следов: очистка журнала после
        подозрительной активности.
        """
        log_clears = [a for a in self.alerts
                      if a.rule.category == Category.LOG_TAMPERING]
        suspicious = [a for a in self.alerts
                      if a.rule.severity in (Severity.HIGH, Severity.CRITICAL)
                      and a.rule.category != Category.LOG_TAMPERING]

        for clear in log_clears:
            preceding = [s for s in suspicious
                         if s.timestamp and clear.timestamp
                         and 0 < (clear.timestamp - s.timestamp).total_seconds() <= 3600]

            if preceding:
                corr = CorrelatedAlert(
                    name="Заметание следов после атаки",
                    description=f"Журнал очищен после {len(preceding)} подозрительных "
                                f"событий в течение предыдущего часа.",
                    severity=Severity.CRITICAL,
                    category=Category.LOG_TAMPERING,
                    alerts=[*preceding, clear],
                    start_time=preceding[0].timestamp,
                    end_time=clear.timestamp,
                    event_count=len(preceding) + 1,
                )
                self.correlated.append(corr)

    # ──────────────────────────────────────────────
    #  Этап 3: Сводка
    # ──────────────────────────────────────────────

    def _build_summary(self) -> dict:
        """Формирует сводную статистику по результатам анализа."""
        by_severity = defaultdict(int)
        by_category = defaultdict(int)

        for alert in self.alerts:
            by_severity[alert.rule.severity.value] += 1
            by_category[alert.rule.category.value] += 1

        return {
            'by_severity': dict(by_severity),
            'by_category': dict(by_category),
            'total_alerts': len(self.alerts),
            'total_correlated': len(self.correlated),
            'critical_count': by_severity.get('critical', 0),
            'high_count': by_severity.get('high', 0),
        }