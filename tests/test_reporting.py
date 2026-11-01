import csv
from html.parser import HTMLParser
from pathlib import Path
import sqlite3
import os
import tempfile
import unittest

from db.database import add_event_record, initialize_database
from services.reporting import describe_ip_scope, event_filter, export_events_csv, export_report_html


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        initialize_database(self.connection)
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def add(self, message="Accepted password", **values):
        parameters = dict(source_ip="203.0.113.45", event_type="LOGIN_SUCCESS", severity="LOW",
                          message=message, timestamp="2026-11-02 08:00:00", destination_port=443,
                          source_file="example.log")
        parameters.update(values)
        add_event_record(self.connection, **parameters)
        self.connection.commit()

    def test_csv_filtered_export_includes_metadata_and_all_matching_rows(self):
        self.add("first", event_type="LOGIN_FAILED", severity="MEDIUM")
        self.add("ordinary")
        self.add("last", source_file="other.log", event_type="LOGIN_FAILED", severity="MEDIUM")
        target = self.directory / "events.csv"
        self.assertEqual(1, export_events_csv(self.connection, target, search="example.log", severity="MEDIUM"))
        self.assertTrue(target.read_bytes().startswith(b"\xef\xbb\xbf"))
        with target.open(encoding="utf-8-sig", newline="") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual("first", rows[0]["message"])
        self.assertEqual("443", rows[0]["destination_port"])
        self.assertEqual("example.log", rows[0]["source_file"])

    def test_csv_neutralizes_formulas_after_whitespace_and_control_characters(self):
        dangerous = ("=1+1", "+cmd", "-2+3", "@SUM(A1)", "\t=HYPERLINK(\"https://example.invalid\")",
                     " \r\n+1", "\x01=1", "\ufeff@SUM(A1)")
        for message in dangerous:
            self.add(message)
        ordinary = ("Accepted password", "192.0.2.5", "ошибка входа", "text = ordinary")
        for message in ordinary:
            self.add(message)
        target = self.directory / "events.csv"
        export_events_csv(self.connection, target)
        with target.open(encoding="utf-8-sig", newline="") as source:
            messages = {row["message"] for row in csv.DictReader(source)}
        for message in dangerous:
            self.assertIn("'" + message, messages)
        for message in ordinary:
            self.assertIn(message, messages)

    def test_search_is_literal_and_cannot_change_sql(self):
        self.add("100% failure")
        self.add("1000 failures")
        target = self.directory / "events.csv"
        self.assertEqual(1, export_events_csv(self.connection, target, search="100%"))
        self.assertEqual(0, export_events_csv(self.connection, target, search="' OR 1=1 --"))
        self.assertEqual(2, self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        with self.assertRaises(ValueError):
            event_filter(severity="UNKNOWN")

    def test_html_escapes_evidence_notes_history_and_labels(self):
        attack = '</td><script>alert("x")</script><img src=x onerror=alert(1)>'
        self.add(attack)
        event_id = self.connection.execute("SELECT id FROM events").fetchone()[0]
        self.connection.execute("""
            INSERT INTO alerts(fingerprint,created_at,source_ip,rule_name,severity,description,status)
            VALUES('report-test','2026-11-02 08:01:00','203.0.113.45',?,'HIGH',?,'OPEN')
        """, (attack, attack))
        alert_id = self.connection.execute("SELECT id FROM alerts").fetchone()[0]
        self.connection.execute("INSERT INTO alert_events(alert_id,event_id) VALUES (?,?)", (alert_id,event_id))
        self.connection.execute("INSERT INTO alert_notes(alert_id,created_at,note) VALUES (?, '2026-11-02 08:02:00', ?)", (alert_id,attack))
        self.connection.execute("INSERT INTO alert_history(alert_id,changed_at,from_status,to_status) VALUES (?, '2026-11-02 08:02:00', ?, 'OPEN')", (alert_id,attack))
        target = self.directory / "report.html"
        self.assertEqual(1, export_report_html(self.connection, target))
        report = target.read_text()
        self.assertNotIn(attack, report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("&quot;x&quot;", report)
        parser = _Tags()
        parser.feed(report)
        self.assertNotIn("script", parser.tags)
        self.assertNotIn("img", parser.tags)
        self.assertIn("Заметки аналитика", report)
        self.assertIn("История статусов", report)
        self.assertIn("Документационный адрес (демо)", report)

    def test_empty_database_report_is_standalone_and_does_not_change_database(self):
        before = self.connection.total_changes
        target = self.directory / "report.html"
        self.assertEqual(0, export_report_html(self.connection, target))
        report = target.read_text()
        self.assertIn('lang="ru"', report)
        self.assertIn("Сигналов нет", report)
        self.assertNotIn('src="http', report)
        self.assertNotIn('href="http', report)
        self.assertEqual(before, self.connection.total_changes)

    def test_ip_scope_does_not_mislabel_documentation_addresses_as_private(self):
        for value in ("203.0.113.45", "198.51.100.23", "192.0.2.1", "2001:db8::1"):
            self.assertEqual("Документационный адрес (демо)", describe_ip_scope(value))
        self.assertEqual("Частная сеть", describe_ip_scope("10.0.0.1"))
        self.assertEqual("Частная сеть", describe_ip_scope("fd00::1"))
        self.assertEqual("Локальный (loopback)", describe_ip_scope("127.0.0.1"))
        self.assertEqual("Некорректный адрес", describe_ip_scope("not-ip"))
        self.assertEqual("Не указан", describe_ip_scope(None))

    def test_exports_cannot_replace_active_database_links_or_sidecars(self):
        path = self.directory / "active.db"
        connection = sqlite3.connect(path)
        self.addCleanup(connection.close)
        initialize_database(connection)
        with connection:
            add_event_record(connection, "192.0.2.1", "LOG_EVENT", "LOW", "must survive")
        before = path.read_bytes()
        hardlink = self.directory / "hardlink.html"
        os.link(path, hardlink)
        symlink = self.directory / "symlink.csv"
        symlink.symlink_to(path)
        for destination in (path, hardlink, symlink, Path(str(path) + "-wal"),
                            Path(str(path) + "-shm"), Path(str(path) + "-journal")):
            for exporter in (export_events_csv, export_report_html):
                with self.subTest(destination=destination, exporter=exporter.__name__):
                    with self.assertRaises(ValueError):
                        exporter(connection, destination)
                    self.assertEqual(before, path.read_bytes())
                    self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
                    self.assertEqual("must survive", connection.execute("SELECT message FROM events").fetchone()[0])


if __name__ == "__main__":
    unittest.main()
