import sqlite3
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from db.database import (
    add_alert_note, add_event_record, change_alert_status, connect_database,
    get_alert_notes, get_setting, initialize_database, set_setting,
)


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.db = connect_database(":memory:")
        self.addCleanup(self.db.close)

    def test_connect_closes_connection_when_migration_fails(self):
        raw=sqlite3.connect(":memory:")
        with patch("db.database.sqlite3.connect",return_value=raw), \
             patch("db.database.initialize_database",side_effect=sqlite3.DatabaseError("broken")):
            with self.assertRaises(sqlite3.DatabaseError):
                connect_database(":memory:")
        with self.assertRaises(sqlite3.ProgrammingError):
            raw.execute("SELECT 1")

    def make_alert(self):
        cursor = self.db.execute(
            "INSERT INTO alerts(fingerprint,created_at,source_ip,rule_name,severity,description) "
            "VALUES ('fixture','2025-01-01 00:00:00','203.0.113.5','Test','HIGH','Test alert')"
        )
        self.db.commit()
        return cursor.lastrowid

    def test_legacy_migration_preserves_rows_and_is_repeatable(self):
        legacy = sqlite3.connect(":memory:")
        self.addCleanup(legacy.close)
        legacy.executescript("""
            CREATE TABLE events(id INTEGER PRIMARY KEY AUTOINCREMENT,timestamp TEXT NOT NULL,
                source_ip TEXT,event_type TEXT NOT NULL,severity TEXT NOT NULL,message TEXT NOT NULL);
            CREATE TABLE alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,fingerprint TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,source_ip TEXT,rule_name TEXT NOT NULL,severity TEXT NOT NULL,
                description TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'OPEN');
            INSERT INTO events VALUES(17,'2025-01-01 00:00:00','203.0.113.1','LOGIN_FAILED','MEDIUM','keep me');
            INSERT INTO alerts VALUES(9,'old','2025-01-01 00:00:00','203.0.113.1','Old rule','HIGH','keep alert','RESOLVED');
        """)
        initialize_database(legacy)
        initialize_database(legacy)
        self.assertEqual((17, "keep me", None), legacy.execute("SELECT id,message,event_key FROM events").fetchone())
        self.assertEqual((9, "RESOLVED"), legacy.execute("SELECT id,status FROM alerts").fetchone())
        self.assertEqual(2, legacy.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual([], legacy.execute("PRAGMA foreign_key_check").fetchall())

    def test_duplicate_key_is_skipped_but_unkeyed_repeats_are_distinct(self):
        with self.db:
            self.assertTrue(add_event_record(self.db,"203.0.113.1","LOGIN_FAILED","MEDIUM","raw",event_key="line1"))
            self.assertFalse(add_event_record(self.db,"203.0.113.1","LOGIN_FAILED","MEDIUM","raw",event_key="line1"))
            for _ in range(2):
                self.assertTrue(add_event_record(self.db,"203.0.113.1","LOGIN_FAILED","MEDIUM","raw"))
        self.assertEqual(3,self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def test_event_and_setting_changes_roll_back_together(self):
        with self.assertRaises(RuntimeError):
            with self.db:
                add_event_record(self.db,"203.0.113.1","LOGIN_FAILED","MEDIUM","raw")
                set_setting(self.db,"threshold",7)
                raise RuntimeError("import failed")
        self.assertEqual(0,self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        self.assertEqual("5",get_setting(self.db,"threshold","5"))
        with self.db:
            set_setting(self.db,"threshold",7)
            set_setting(self.db,"threshold",8)
        self.assertEqual("8",get_setting(self.db,"threshold","5"))

    def test_ip_normalization_and_destination_validation(self):
        with self.db:
            add_event_record(self.db," 2001:0db8::1 ","NETWORK_CONNECTION","LOW","raw",
                             timestamp="2025-01-01T00:00:00+00:00",destination_ip="invalid",destination_port=443)
        row=self.db.execute("SELECT source_ip,destination_ip,destination_port,timestamp FROM events").fetchone()
        self.assertEqual(("2001:db8::1",None,443),tuple(row)[:3])
        for port in (0,65536,True,"443"):
            with self.subTest(port=port),self.assertRaises(ValueError):
                add_event_record(self.db,None,"NETWORK_CONNECTION","LOW","raw",destination_port=port)
        with self.assertRaises(ValueError):
            add_event_record(self.db,None,"NETWORK_CONNECTION","LOW","raw",timestamp="bad timestamp")

    def test_response_status_history_is_atomic_and_idempotent(self):
        identity=self.make_alert()
        self.assertTrue(change_alert_status(self.db,identity,"ACKNOWLEDGED"))
        self.assertFalse(change_alert_status(self.db,identity,"ACKNOWLEDGED"))
        self.assertTrue(change_alert_status(self.db,identity,"RESOLVED"))
        rows=self.db.execute("SELECT from_status,to_status FROM alert_history ORDER BY id").fetchall()
        self.assertEqual([("OPEN","ACKNOWLEDGED"),("ACKNOWLEDGED","RESOLVED")],[tuple(row) for row in rows])
        with self.assertRaises(ValueError):
            change_alert_status(self.db,identity,"INVALID")
        self.assertFalse(change_alert_status(self.db,999,"OPEN"))

    def test_settings_response_and_notes_survive_reopening_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"workspace.db"
            db=connect_database(path)
            with db:
                set_setting(db,"threshold",7)
                db.execute("INSERT INTO alerts(fingerprint,created_at,rule_name,severity,description) "
                           "VALUES ('saved','2025-01-01 00:00:00','Saved rule','HIGH','persisted')")
            identity=db.execute("SELECT id FROM alerts").fetchone()[0]
            change_alert_status(db,identity,"ACKNOWLEDGED")
            add_alert_note(db,identity,"Сохранённый вывод")
            db.close()
            reopened=connect_database(path)
            try:
                self.assertEqual("7",get_setting(reopened,"threshold","5"))
                self.assertEqual("ACKNOWLEDGED",reopened.execute("SELECT status FROM alerts").fetchone()[0])
                self.assertEqual("Сохранённый вывод",get_alert_notes(reopened,identity)[0]["note"])
                self.assertEqual(1,reopened.execute("SELECT COUNT(*) FROM alert_history").fetchone()[0])
            finally:
                reopened.close()

    def test_notes_are_saved_and_validated(self):
        identity=self.make_alert()
        note_id=add_alert_note(self.db,identity,"  Проверен исходный журнал.  ")
        note=get_alert_notes(self.db,identity)[0]
        self.assertEqual(note_id,note["id"])
        self.assertEqual("Проверен исходный журнал.",note["note"])
        for text in ("   ","x"*5001):
            with self.assertRaises(ValueError):
                add_alert_note(self.db,identity,text)
        with self.assertRaises(ValueError):
            add_alert_note(self.db,999,"missing alert")
        self.assertEqual(1,len(get_alert_notes(self.db,identity)))


if __name__ == "__main__":
    unittest.main()
