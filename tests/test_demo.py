from datetime import datetime
import sqlite3
import unittest

from db.database import add_event_record, initialize_database, set_setting
from services.demo import add_demo_events
from services.detection import run_detection


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.addCleanup(self.connection.close)
        initialize_database(self.connection)

    def test_repeat_demo_is_idempotent_and_preserves_existing_data_and_settings(self):
        with self.connection:
            add_event_record(self.connection, "192.168.1.2", "LOG_EVENT", "LOW", "real existing event")
            set_setting(self.connection, "threshold", "9")
        self.assertEqual(21, add_demo_events(self.connection))
        first = [tuple(row) for row in self.connection.execute("SELECT * FROM events ORDER BY id")]
        self.assertEqual(0, add_demo_events(self.connection))
        second = [tuple(row) for row in self.connection.execute("SELECT * FROM events ORDER BY id")]
        self.assertEqual(first, second)
        self.assertEqual(22, len(second))
        self.assertEqual("9", self.connection.execute("SELECT value FROM settings WHERE key='threshold'").fetchone()[0])

    def test_demo_exercises_three_rules_with_linked_evidence(self):
        add_demo_events(self.connection)
        result = run_detection(self.connection)
        self.assertEqual(3, result.new_alerts)
        self.assertEqual(2, result.suspicious_ips)
        self.assertEqual(3, self.connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])
        self.assertGreaterEqual(self.connection.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0], 15)
        self.assertEqual(0, run_detection(self.connection).new_alerts)
        for row in self.connection.execute("SELECT timestamp FROM events"):
            self.assertLessEqual(datetime.fromisoformat(row[0]), datetime.now())


if __name__ == "__main__":
    unittest.main()
