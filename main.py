"""CyberWatch entry point: desktop workspace and headless demo/report checks."""

import argparse
import json
from pathlib import Path
import sqlite3
import sys
import tkinter as tk

from db.database import DB_PATH, connect_database, get_setting
from services.demo import add_demo_events
from services.detection import run_detection
from services.reporting import export_report_html
from ui.app import CyberWatchApp

VERSION = "2.0"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="CyberWatch — локальное рабочее место SOC-аналитика")
    parser.add_argument("--database", type=Path, default=DB_PATH, help="Путь к отдельной SQLite-базе")
    parser.add_argument("--check", action="store_true", help="Проверить базу и вывести показатели без открытия окна")
    parser.add_argument("--demo", action="store_true", help="Добавить демо-сценарии и запустить детекцию без открытия окна")
    parser.add_argument("--report", type=Path, help="Сохранить HTML-отчёт без открытия окна")
    parser.add_argument("--version", action="version", version=f"CyberWatch {VERSION}")
    args = parser.parse_args(argv)
    try:
        if args.check or args.demo or args.report:
            db = connect_database(args.database)
            try:
                result = {"database": str(args.database), "version": VERSION}
                if args.demo:
                    result["demo_events_added"] = add_demo_events(db)
                    settings = []
                    for name, default, low, high in (("threshold", 5, 2, 100), ("window_minutes", 10, 1, 1440),
                                                      ("port_threshold", 10, 2, 1000)):
                        try:
                            value = int(get_setting(db, name, str(default)))
                            if not low <= value <= high:
                                raise ValueError
                        except ValueError:
                            value = default
                        settings.append(value)
                    scan = run_detection(db, settings[0], settings[1], port_threshold=settings[2])
                    result["new_alerts"] = scan.new_alerts
                integrity = db.execute("PRAGMA quick_check").fetchone()[0]
                if integrity != "ok":
                    raise ValueError(f"Проверка SQLite: {integrity}")
                if db.execute("PRAGMA foreign_key_check").fetchall():
                    raise ValueError("Обнаружены нарушенные связи в базе данных.")
                if args.report:
                    export_report_html(db, args.report)
                    result["report"] = str(args.report.resolve())
                result.update(integrity=integrity,
                              events=db.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                              alerts=db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
                              open_alerts=db.execute("SELECT COUNT(*) FROM alerts WHERE status='OPEN'").fetchone()[0])
                print(json.dumps(result, ensure_ascii=False, indent=2))
            finally:
                db.close()
            return 0
        root = tk.Tk()
        try:
            CyberWatchApp(root, db_path=args.database)
        except Exception:
            root.destroy()
            raise
        root.mainloop()
        return 0
    except (OSError, sqlite3.Error, ValueError, tk.TclError) as error:
        print(f"CyberWatch: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
