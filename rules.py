"""
rules.py — Модуль правил детекции подозрительной активности
Каждое правило описывает один тип подозрительного события:
какой Event ID отслеживать, в каком журнале, какие условия должны
совпасть в полях EventData, и какой уровень критичности присвоить.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Уровни критичности обнаруженных событий."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(Enum):
    """Категории угроз для классификации находок."""
    BRUTE_FORCE = "Брутфорс"
    ACCOUNT_MANIPULATION = "Манипуляция учётными записями"
    PRIVILEGE_ESCALATION = "Эскалация привилегий"
    LOG_TAMPERING = "Уничтожение следов"
    SUSPICIOUS_PROCESS = "Подозрительный процесс"
    SUSPICIOUS_POWERSHELL = "Подозрительный PowerShell"
    LATERAL_MOVEMENT = "Перемещение по сети"
    PERSISTENCE = "Закрепление в системе"
    RECONNAISSANCE = "Разведка"
    CREDENTIAL_ACCESS = "Доступ к учётным данным"


@dataclass
class DetectionRule:
    """
    Одно правило детекции.
    Attributes:
        rule_id: уникальный идентификатор правила (например, 'R001')
        name: краткое название правила
        description: что означает срабатывание
        event_id: отслеживаемый Event ID
        channel: журнал (Security, System и т.д.), пустая строка = любой
        severity: уровень критичности
        category: категория угрозы
        field_conditions: условия на поля EventData
                          ключ = имя поля, значение = список допустимых значений
                          (если поле содержит любое из значений — условие выполнено)
        field_exclusions: поля, при наличии которых правило НЕ срабатывает
    """
    rule_id: str
    name: str
    description: str
    event_id: int
    channel: str
    severity: Severity
    category: Category
    field_conditions: dict = field(default_factory=dict)
    field_exclusions: dict = field(default_factory=dict)


def match_rule(rule: DetectionRule, event: dict) -> bool:
    """
    Проверяет, соответствует ли событие данному правилу.
    Returns:
        True если событие подпадает под правило
    """
    # Проверка Event ID
    if event['event_id'] != rule.event_id:
        return False

    # Проверка канала (журнала)
    if rule.channel and event['channel'].lower() != rule.channel.lower():
        return False

    # Проверка условий на поля EventData
    event_data = event.get('event_data', {})

    for field_name, allowed_values in rule.field_conditions.items():
        actual_value = event_data.get(field_name, '').lower()
        if not any(v.lower() in actual_value for v in allowed_values):
            return False

    # Проверка исключений
    for field_name, excluded_values in rule.field_exclusions.items():
        actual_value = event_data.get(field_name, '').lower()
        if any(v.lower() in actual_value for v in excluded_values):
            return False

    return True


# ──────────────────────────────────────────────
#  Набор правил детекции
# ──────────────────────────────────────────────

DETECTION_RULES = [

    # === АУТЕНТИФИКАЦИЯ ===

    DetectionRule(
        rule_id="R001",
        name="Неудачная попытка входа",
        description="Зафиксирована неудачная попытка аутентификации. "
                    "Множественные срабатывания могут указывать на брутфорс.",
        event_id=4625,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.BRUTE_FORCE,
    ),

    DetectionRule(
        rule_id="R002",
        name="Успешный вход через RDP",
        description="Обнаружен удалённый вход по протоколу RDP (Logon Type 10). "
                    "Может быть легитимным, но требует проверки источника.",
        event_id=4624,
        channel="Security",
        severity=Severity.LOW,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={"LogonType": ["10"]},
    ),

    DetectionRule(
        rule_id="R003",
        name="Сетевой вход (Pass-the-Hash)",
        description="Обнаружен сетевой вход (Logon Type 3). "
                    "Используется при lateral movement и атаках Pass-the-Hash.",
        event_id=4624,
        channel="Security",
        severity=Severity.LOW,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={"LogonType": ["3"]},
    ),

    DetectionRule(
        rule_id="R004",
        name="Вход с явными учётными данными",
        description="Процесс выполнил вход с явным указанием логина и пароля. "
                    "Характерно для использования runas, PsExec или lateral movement.",
        event_id=4648,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.LATERAL_MOVEMENT,
    ),

    # === УПРАВЛЕНИЕ УЧЁТНЫМИ ЗАПИСЯМИ ===

    DetectionRule(
        rule_id="R005",
        name="Создание новой учётной записи",
        description="Создана новая локальная учётная запись. "
                    "Злоумышленники создают учётные записи для закрепления в системе.",
        event_id=4720,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.ACCOUNT_MANIPULATION,
    ),

    DetectionRule(
        rule_id="R006",
        name="Учётная запись добавлена в группу администраторов",
        description="Пользователь добавлен в локальную группу администраторов. "
                    "Это классический приём эскалации привилегий.",
        event_id=4732,
        channel="Security",
        severity=Severity.CRITICAL,
        category=Category.PRIVILEGE_ESCALATION,
        field_conditions={"TargetSid": ["S-1-5-32-544"]},
    ),

    DetectionRule(
        rule_id="R007",
        name="Сброс пароля учётной записи",
        description="Выполнен сброс пароля пользователя. "
                    "Может указывать на захват учётной записи.",
        event_id=4724,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.ACCOUNT_MANIPULATION,
    ),

    DetectionRule(
        rule_id="R008",
        name="Учётная запись активирована",
        description="Ранее отключённая учётная запись была активирована.",
        event_id=4722,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.ACCOUNT_MANIPULATION,
    ),

    # === УНИЧТОЖЕНИЕ СЛЕДОВ ===

    DetectionRule(
        rule_id="R009",
        name="Очистка журнала Security",
        description="Журнал Security был очищен. "
                    "Это почти всегда указывает на попытку скрыть следы атаки.",
        event_id=1102,
        channel="Security",
        severity=Severity.CRITICAL,
        category=Category.LOG_TAMPERING,
    ),

    DetectionRule(
        rule_id="R010",
        name="Очистка системного журнала",
        description="Один из системных журналов был очищен.",
        event_id=104,
        channel="System",
        severity=Severity.HIGH,
        category=Category.LOG_TAMPERING,
    ),

    # === ПОДОЗРИТЕЛЬНЫЕ ПРОЦЕССЫ ===

    DetectionRule(
        rule_id="R011",
        name="Запуск средства сбора учётных данных",
        description="Обнаружен запуск процесса, связанного с дампом учётных данных "
                    "(mimikatz, procdump, sekurlsa и др.).",
        event_id=4688,
        channel="Security",
        severity=Severity.CRITICAL,
        category=Category.CREDENTIAL_ACCESS,
        field_conditions={
            "NewProcessName": [
                "mimikatz", "procdump", "sekurlsa",
                "gsecdump", "wce.exe", "pwdump",
                "lazagne", "safetykatz",
            ]
        },
    ),

    DetectionRule(
        rule_id="R012",
        name="Запуск средства удалённого выполнения",
        description="Обнаружен запуск утилиты удалённого управления "
                    "(PsExec, RemCom и др.).",
        event_id=4688,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={
            "NewProcessName": [
                "psexec", "remcom", "paexec",
                "csexec", "smbexec",
            ]
        },
    ),

    DetectionRule(
        rule_id="R013",
        name="Запуск команды разведки",
        description="Обнаружен запуск утилиты, типичной для разведки в сети: "
                    "whoami, net user, net group, nltest, ipconfig, systeminfo.",
        event_id=4688,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.RECONNAISSANCE,
        field_conditions={
            "NewProcessName": [
                "whoami", "nltest", "net.exe",
                "net1.exe", "ipconfig", "systeminfo",
                "tasklist", "qprocess", "nslookup",
                "arp.exe", "netstat",
            ]
        },
    ),

    DetectionRule(
        rule_id="R014",
        name="Использование certutil для загрузки файлов",
        description="certutil используется с параметрами загрузки. "
                    "Атакующие часто применяют его как LOLBin для скачивания вредоносов.",
        event_id=4688,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "NewProcessName": ["certutil"],
            "CommandLine": ["-urlcache", "-split", "download"],
        },
    ),

    # === POWERSHELL ===

    DetectionRule(
        rule_id="R015",
        name="Подозрительный PowerShell-скрипт (ScriptBlock)",
        description="В PowerShell ScriptBlock Logging обнаружены подозрительные "
                    "конструкции: кодированные команды, загрузка в память, обход политик.",
        event_id=4104,
        channel="Microsoft-Windows-PowerShell/Operational",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_POWERSHELL,
        field_conditions={
            "ScriptBlockText": [
                "invoke-mimikatz", "invoke-expression", "iex(",
                "downloadstring", "downloadfile", "frombase64string",
                "encodedcommand", "-enc ", "-e ",
                "bypass", "hidden", "invoke-shellcode",
                "invoke-obfuscation", "amsibypass",
                "net.webclient", "bitstransfer",
                "invoke-webrequest", "start-bitstransfer",
            ]
        },
    ),

    # === ЗАКРЕПЛЕНИЕ В СИСТЕМЕ ===

    DetectionRule(
        rule_id="R016",
        name="Установка новой службы",
        description="Зарегистрирована новая системная служба. "
                    "Вредоносное ПО часто устанавливается как служба для автозапуска.",
        event_id=7045,
        channel="System",
        severity=Severity.HIGH,
        category=Category.PERSISTENCE,
    ),

    DetectionRule(
        rule_id="R017",
        name="Запланированная задача создана",
        description="Создана новая запланированная задача через schtasks. "
                    "Используется для закрепления и отложенного запуска.",
        event_id=4688,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.PERSISTENCE,
        field_conditions={
            "NewProcessName": ["schtasks"],
            "CommandLine": ["/create"],
        },
    ),

# === SYSMON-ПРАВИЛА ===

    DetectionRule(
        rule_id="R101",
        name="[Sysmon] Запуск подозрительного процесса",
        description="Sysmon зафиксировал запуск процесса, связанного с хакерскими утилитами.",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.CRITICAL,
        category=Category.CREDENTIAL_ACCESS,
        field_conditions={
            "Image": [
                "mimikatz", "procdump", "sekurlsa",
                "gsecdump", "wce.exe", "pwdump",
                "lazagne", "safetykatz", "sharpdump",
                "rubeus", "kekeo",
            ]
        },
    ),

    DetectionRule(
        rule_id="R102",
        name="[Sysmon] Запуск средства удалённого выполнения",
        description="Sysmon зафиксировал запуск утилиты удалённого управления.",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={
            "Image": [
                "psexec", "remcom", "paexec",
                "csexec", "smbexec", "meterpreter",
            ]
        },
    ),

    DetectionRule(
        rule_id="R103",
        name="[Sysmon] Команда разведки",
        description="Sysmon зафиксировал запуск утилиты разведки.",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.MEDIUM,
        category=Category.RECONNAISSANCE,
        field_conditions={
            "Image": [
                "whoami", "nltest", "net.exe",
                "net1.exe", "ipconfig", "systeminfo",
                "tasklist", "qprocess", "nslookup",
                "arp.exe", "netstat",
            ]
        },
    ),

    DetectionRule(
        rule_id="R104",
        name="[Sysmon] Доступ к процессу LSASS",
        description="Обнаружена попытка доступа к процессу lsass.exe. "
                    "Это основной метод извлечения учётных данных из памяти (Mimikatz и аналоги).",
        event_id=10,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.CRITICAL,
        category=Category.CREDENTIAL_ACCESS,
        field_conditions={
            "TargetImage": ["lsass.exe"],
        },
    ),

    DetectionRule(
        rule_id="R105",
        name="[Sysmon] Подозрительное сетевое соединение",
        description="Процесс установил сетевое соединение. "
                    "Проверьте, является ли целевой адрес легитимным.",
        event_id=3,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.MEDIUM,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={
            "Image": [
                "powershell", "cmd.exe", "mshta",
                "wscript", "cscript", "rundll32",
                "regsvr32", "meterpreter",
            ]
        },
    ),

    DetectionRule(
        rule_id="R106",
        name="[Sysmon] Внедрение в удалённый поток",
        description="Обнаружено создание удалённого потока в другом процессе (CreateRemoteThread). "
                    "Типичная техника внедрения кода.",
        event_id=8,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.CREDENTIAL_ACCESS,
    ),

    DetectionRule(
        rule_id="R107",
        name="[Sysmon] Использование именованного канала",
        description="Обнаружено подключение к именованному каналу. "
                    "PsExec, Cobalt Strike и другие инструменты используют именованные каналы.",
        event_id=18,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.MEDIUM,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={
            "PipeName": [
                "psexec", "paexec", "remcom",
                "csexec", "msse-", "status_",
                "msagent_", "postex_", "lsadump",
            ]
        },
    ),

    DetectionRule(
        rule_id="R108",
        name="[Sysmon] Подозрительная командная строка",
        description="Sysmon зафиксировал запуск процесса с подозрительными параметрами.",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "CommandLine": [
                "invoke-mimikatz", "sekurlsa", "lsadump",
                "downloadstring", "frombase64string",
                "-encodedcommand", "invoke-shellcode",
                "certutil -urlcache", "bitsadmin /transfer",
            ]
        },
    ),

    DetectionRule(
        rule_id="R109",
        name="[Sysmon] mshta.exe запущен с сетевым контентом",
        description="mshta.exe использован для выполнения удалённого контента. "
                    "Популярная техника Living-off-the-Land.",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "Image": ["mshta"],
            "CommandLine": ["http", "vbscript", "javascript"],
        },
    ),

# === ДОПОЛНИТЕЛЬНЫЕ ПРАВИЛА SECURITY ===

    DetectionRule(
        rule_id="R018",
        name="Вход с учётной записью по умолчанию",
        description="Обнаружен вход с учётной записью Administrator или Guest. "
                    "Эти учётные записи должны быть отключены в защищённых средах.",
        event_id=4624,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={"TargetUserName": ["administrator", "guest"]},
    ),

    DetectionRule(
        rule_id="R019",
        name="Изменение политики аудита",
        description="Политика аудита системы была изменена. "
                    "Злоумышленники отключают аудит для сокрытия следов.",
        event_id=4719,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.LOG_TAMPERING,
    ),

    DetectionRule(
        rule_id="R020",
        name="Изменение групповой политики",
        description="Объект групповой политики был изменён. "
                    "Может использоваться для массового распространения вредоносных настроек.",
        event_id=5136,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.PERSISTENCE,
    ),

    DetectionRule(
        rule_id="R021",
        name="Использование привилегий на вход",
        description="Зафиксировано использование специальных привилегий при входе.",
        event_id=4672,
        channel="Security",
        severity=Severity.LOW,
        category=Category.PRIVILEGE_ESCALATION,
    ),

    DetectionRule(
        rule_id="R022",
        name="Блокировка учётной записи",
        description="Учётная запись была заблокирована из-за множества неудачных попыток входа.",
        event_id=4740,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.BRUTE_FORCE,
    ),

    DetectionRule(
        rule_id="R023",
        name="Разблокировка учётной записи",
        description="Ранее заблокированная учётная запись была разблокирована администратором.",
        event_id=4767,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.ACCOUNT_MANIPULATION,
    ),

    DetectionRule(
        rule_id="R024",
        name="Удаление учётной записи",
        description="Учётная запись была удалена из системы.",
        event_id=4726,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.ACCOUNT_MANIPULATION,
    ),

    DetectionRule(
        rule_id="R025",
        name="Использование mshta.exe",
        description="Запущен mshta.exe — часто используется для выполнения вредоносных HTA-скриптов.",
        event_id=4688,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={"NewProcessName": ["mshta"]},
    ),

    DetectionRule(
        rule_id="R026",
        name="Использование rundll32 с подозрительными параметрами",
        description="rundll32.exe запущен с параметрами, характерными для вредоносной активности.",
        event_id=4688,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "NewProcessName": ["rundll32"],
            "CommandLine": ["javascript", "vbscript", "shell32", "url.dll"],
        },
    ),

    DetectionRule(
        rule_id="R027",
        name="Использование regsvr32 для загрузки",
        description="regsvr32.exe использован с параметром /s или /i:URL — техника AppLocker Bypass.",
        event_id=4688,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "NewProcessName": ["regsvr32"],
            "CommandLine": ["/i:http", "/i:ftp", "scrobj"],
        },
    ),

    DetectionRule(
        rule_id="R028",
        name="Использование bitsadmin для загрузки",
        description="bitsadmin использован для загрузки файлов — популярная LOLBin-техника.",
        event_id=4688,
        channel="Security",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "NewProcessName": ["bitsadmin"],
            "CommandLine": ["/transfer", "/addfile", "http"],
        },
    ),

    DetectionRule(
        rule_id="R029",
        name="Использование wmic для выполнения",
        description="wmic использован для запуска процессов — техника удалённого выполнения.",
        event_id=4688,
        channel="Security",
        severity=Severity.MEDIUM,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={
            "NewProcessName": ["wmic"],
            "CommandLine": ["process call create", "/node:"],
        },
    ),

    DetectionRule(
        rule_id="R030",
        name="Остановка службы безопасности",
        description="Остановлена служба, связанная с безопасностью (антивирус, фаервол, мониторинг).",
        event_id=7036,
        channel="System",
        severity=Severity.HIGH,
        category=Category.LOG_TAMPERING,
        field_conditions={
            "param1": [
                "windows defender", "windefend", "mpssvc",
                "wscsvc", "securityhealthservice",
                "sense", "carbonblack", "crowdstrike",
                "symantec", "mcafee", "kaspersky",
                "sophos", "eset", "avast", "avg",
            ],
            "param2": ["stopped"],
        },
    ),

    # === ДОПОЛНИТЕЛЬНЫЕ SYSMON-ПРАВИЛА ===

    DetectionRule(
        rule_id="R110",
        name="[Sysmon] Изменение файла в системной директории",
        description="Sysmon зафиксировал создание или изменение файла в системной директории Windows.",
        event_id=11,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.MEDIUM,
        category=Category.PERSISTENCE,
        field_conditions={
            "TargetFilename": [
                "\\windows\\system32\\", "\\windows\\syswow64\\",
                "\\windows\\temp\\", "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup",
            ],
        },
    ),

    DetectionRule(
        rule_id="R111",
        name="[Sysmon] Изменение реестра (автозагрузка)",
        description="Обнаружено изменение ключа реестра, связанного с автозапуском. "
                    "Классический метод закрепления вредоносного ПО.",
        event_id=13,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.PERSISTENCE,
        field_conditions={
            "TargetObject": [
                "\\currentversion\\run", "\\currentversion\\runonce",
                "\\currentversion\\policies\\explorer\\run",
                "\\currentversion\\windows\\load",
                "\\environment\\userinitmprlogonscript",
            ],
        },
    ),

    DetectionRule(
        rule_id="R112",
        name="[Sysmon] DNS-запрос к подозрительному домену",
        description="Обнаружен DNS-запрос к домену, связанному с вредоносной инфраструктурой.",
        event_id=22,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.MEDIUM,
        category=Category.LATERAL_MOVEMENT,
        field_conditions={
            "QueryName": [
                ".onion.", ".tor2web.", ".i2p.",
                "pastebin.com", "raw.githubusercontent.com",
                ".duckdns.org", ".no-ip.com", ".dynu.com",
            ],
        },
    ),

    DetectionRule(
        rule_id="R113",
        name="[Sysmon] Загрузка DLL из нестандартной директории",
        description="Процесс загрузил DLL из временной или пользовательской директории. "
                    "Может указывать на DLL Side-Loading или инъекцию.",
        event_id=7,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.MEDIUM,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "ImageLoaded": [
                "\\temp\\", "\\tmp\\", "\\downloads\\",
                "\\appdata\\local\\temp\\", "\\public\\",
            ],
        },
    ),

    DetectionRule(
        rule_id="R114",
        name="[Sysmon] WMI-событие создано",
        description="Создана WMI-подписка на события. "
                    "Используется для закрепления и отложенного выполнения команд.",
        event_id=19,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.PERSISTENCE,
    ),

    DetectionRule(
        rule_id="R115",
        name="[Sysmon] Подмена родительского процесса",
        description="Обнаружен процесс с нетипичным родителем. "
                    "Может указывать на Parent PID Spoofing.",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        severity=Severity.HIGH,
        category=Category.SUSPICIOUS_PROCESS,
        field_conditions={
            "ParentImage": ["winlogon.exe", "services.exe", "lsass.exe"],
            "Image": ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        },
    ),
]


def get_rules_by_category(category: Category) -> list[DetectionRule]:
    """Возвращает все правила указанной категории."""
    return [r for r in DETECTION_RULES if r.category == category]


def get_rules_by_severity(min_severity: Severity) -> list[DetectionRule]:
    """Возвращает правила с критичностью не ниже указанной."""
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                      Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(min_severity)
    return [r for r in DETECTION_RULES
            if severity_order.index(r.severity) >= min_index]