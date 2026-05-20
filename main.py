"""
main.py — Точка входа CatWatch

Обрабатывает аргументы командной строки, запускает парсинг,
анализ и генерацию отчёта.
"""

import argparse
import os
import sys
import glob
from datetime import datetime, timezone

from colorama import init, Fore, Style

from parser import parse_evtx, parse_multiple
from correlator import EventCorrelator
from reporter import generate_html_report, generate_csv_report


# Инициализация цветного вывода для Windows
init(autoreset=True)

BANNER = f"""
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
"""


def main():
    print(BANNER)

    args = parse_arguments()

    # Собираем список файлов для анализа
    evtx_files = collect_files(args.input)
    if not evtx_files:
        print(f"{Fore.RED}[✗] Не найдено .evtx файлов по указанному пути.{Style.RESET_ALL}")
        sys.exit(1)

    print(f"{Fore.GREEN}[✓] Найдено файлов для анализа: {len(evtx_files)}{Style.RESET_ALL}")
    for f in evtx_files:
        print(f"    • {os.path.basename(f)}")

    # Этап 1: Парсинг
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"  ЭТАП 1: ПАРСИНГ ЖУРНАЛОВ")
    print(f"{'='*50}{Style.RESET_ALL}")

    events = parse_multiple(evtx_files)
    print(f"\n{Fore.GREEN}[✓] Всего извлечено событий: {len(events)}{Style.RESET_ALL}")

    if not events:
        print(f"{Fore.YELLOW}[!] Файлы не содержат событий. Проверьте входные данные.{Style.RESET_ALL}")
        sys.exit(0)

    # Этап 2: Анализ
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"  ЭТАП 2: АНАЛИЗ И КОРРЕЛЯЦИЯ")
    print(f"{'='*50}{Style.RESET_ALL}")

    correlator = EventCorrelator(events)
    results = correlator.analyze()

    # Вывод сводки в консоль
    print_summary(results)

    # Этап 3: Генерация отчёта
    print(f"\n{Fore.CYAN}{'='*50}")
    print(f"  ЭТАП 3: ГЕНЕРАЦИЯ ОТЧЁТА")
    print(f"{'='*50}{Style.RESET_ALL}")

    # Определяем путь к шаблонам
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(script_dir, 'templates')

    # HTML-отчёт
    html_path = args.output or generate_output_name('html')
    generate_html_report(results, html_path, template_dir)

    # CSV-отчёт (если запрошен)
    if args.csv:
        csv_path = args.csv
        generate_csv_report(results, csv_path)

    # Итог
    print(f"\n{Fore.GREEN}{'='*50}")
    print(f"  АНАЛИЗ ЗАВЕРШЁН")
    print(f"{'='*50}{Style.RESET_ALL}")
    print(f"  Событий проанализировано: {results['total_events']}")
    print(f"  Срабатываний:             {results['summary']['total_alerts']}")
    print(f"  Коррелированных инцидентов: {results['summary']['total_correlated']}")
    print(f"  Отчёт: {os.path.abspath(html_path)}")


def parse_arguments() -> argparse.Namespace:
    """Разбор аргументов командной строки."""
    parser = argparse.ArgumentParser(
        description='CatWatch — анализ журналов событий Windows',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py -i Security.evtx
  python main.py -i ./logs/ -o report.html --csv alerts.csv
  python main.py -i Security.evtx System.evtx -o full_report.html
        """
    )

    parser.add_argument(
        '-i', '--input',
        nargs='+',
        required=True,
        help='Путь к .evtx файлу(ам) или папке с ними'
    )

    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Путь для HTML-отчёта (по умолчанию: report_YYYYMMDD_HHMMSS.html)'
    )

    parser.add_argument(
        '--csv',
        default=None,
        help='Дополнительно сохранить CSV-отчёт по указанному пути'
    )

    return parser.parse_args()


def collect_files(inputs: list[str]) -> list[str]:
    """
    Собирает список .evtx файлов из переданных путей.
    Принимает как отдельные файлы, так и директории.
    """
    files = []
    for path in inputs:
        if os.path.isfile(path) and path.lower().endswith('.evtx'):
            files.append(os.path.abspath(path))
        elif os.path.isdir(path):
            pattern = os.path.join(path, '**', '*.evtx')
            found = glob.glob(pattern, recursive=True)
            files.extend([os.path.abspath(f) for f in found])
        else:
            # Попробуем как glob-паттерн
            found = glob.glob(path)
            files.extend([os.path.abspath(f) for f in found
                         if f.lower().endswith('.evtx')])
    return sorted(set(files))


def generate_output_name(ext: str) -> str:
    """Генерирует имя файла отчёта с текущей датой."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"report_{timestamp}.{ext}"


def print_summary(results: dict):
    """Выводит сводку анализа в консоль."""
    summary = results['summary']

    print(f"\n{Fore.WHITE}{'─'*50}")
    print(f"  СВОДКА АНАЛИЗА")
    print(f"{'─'*50}{Style.RESET_ALL}")

    print(f"  Всего событий:    {results['total_events']}")
    print(f"  Срабатываний:     {summary['total_alerts']}")
    print(f"  Инцидентов:       {summary['total_correlated']}")

    if summary['critical_count'] > 0:
        print(f"\n  {Fore.RED}🔴 CRITICAL: {summary['critical_count']}{Style.RESET_ALL}")
    if summary['high_count'] > 0:
        print(f"  {Fore.YELLOW}🟠 HIGH:     {summary['high_count']}{Style.RESET_ALL}")
    if summary.get('by_severity', {}).get('medium', 0) > 0:
        print(f"  {Fore.YELLOW}🟡 MEDIUM:   {summary['by_severity']['medium']}{Style.RESET_ALL}")
    if summary.get('by_severity', {}).get('low', 0) > 0:
        print(f"  {Fore.BLUE}🔵 LOW:      {summary['by_severity']['low']}{Style.RESET_ALL}")

    if summary.get('by_category'):
        print(f"\n  {Fore.WHITE}По категориям:{Style.RESET_ALL}")
        for cat, count in summary['by_category'].items():
            print(f"    • {cat}: {count}")


if __name__ == '__main__':
    main()