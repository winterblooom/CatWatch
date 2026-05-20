# 🐱 CatWatch

**Инструмент анализа журналов событий Windows (Event Log) на предмет подозрительной активности.**

Курсовая работа по дисциплине «Компьютерная экспертиза» | РТУ МИРЭА

## Возможности

- Парсинг файлов .evtx (Security, System, Sysmon, PowerShell)
- 39 правил детекции подозрительной активности (17 для Security/System + 9 для Sysmon)
- 4 паттерна корреляции событий (брутфорс, эскалация привилегий, разведка, заметание следов)
- Генерация HTML-отчёта с визуализацией:
  - круговая диаграмма распределения по категориям
  - таймлайн активности
  - фильтрация и поиск по срабатываниям
  - автоматическое заключение эксперта с оценкой уровня риска
- Экспорт в CSV для дальнейшего анализа

## Категории обнаруживаемых угроз

- Брутфорс (подбор паролей)
- Манипуляция учётными записями
- Эскалация привилегий
- Перемещение по сети (Lateral Movement)
- Запуск подозрительных процессов
- Подозрительный PowerShell
- Закрепление в системе (Persistence)
- Разведка (Discovery)
- Доступ к учётным данным
- Уничтожение следов

## Установка

```bash
git clone https://github.com/username/CatWatch.git
cd CatWatch
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Использование

Анализ одного файла:
```bash
python main.py -i Security.evtx
```

Анализ нескольких файлов:
```bash
python main.py -i Security.evtx System.evtx -o report.html
```

Анализ всей папки с журналами:
```bash
python main.py -i ./logs/ -o report.html --csv alerts.csv
```

Тестовый запуск (без реальных .evtx):
```bash
python generate_test_data.py
```

## Экспорт журналов Windows для анализа

Для экспорта журналов с рабочей станции выполните в PowerShell от администратора:
```powershell
wevtutil epl Security Security.evtx
wevtutil epl System System.evtx
```

## Структура проекта
```bash
CatWatch/
├── main.py                  — точка входа, CLI-интерфейс
├── parser.py                — парсинг .evtx файлов
├── rules.py                 — правила детекции (39 правил)
├── correlator.py            — корреляция событий
├── reporter.py              — генерация HTML/CSV отчётов
├── generate_test_data.py    — генератор тестового сценария атаки
├── requirements.txt         — зависимости проекта
├── README.md                — документация проекта
├── templates/
│   └── report.html          — шаблон HTML-отчёта
└── test_logs/               — папка для .evtx файлов
```


## Технологии

- Python 3.12
- python-evtx — парсинг бинарных .evtx файлов
- lxml — обработка XML-структур событий
- Jinja2 — шаблонизация HTML-отчётов
- colorama — цветной вывод в консоль