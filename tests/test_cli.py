"""Headless entry point checks through real subprocesses and isolated databases."""

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.database = self.folder / 'separate.db'

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, str(PROJECT / 'main.py'), '--database', str(self.database), *arguments],
                              cwd=self.folder, text=True, capture_output=True, timeout=15)

    def test_demo_report_and_repeat_are_idempotent(self):
        report = self.folder / 'report.html'
        first = self.invoke('--demo', '--check', '--report', str(report))
        self.assertEqual(first.returncode, 0, first.stderr)
        data = json.loads(first.stdout)
        self.assertEqual(data['integrity'], 'ok')
        self.assertEqual(data['new_alerts'], 3)
        self.assertEqual(data['open_alerts'], 3)
        self.assertTrue(report.is_file())
        second = self.invoke('--demo', '--check')
        self.assertEqual(second.returncode, 0, second.stderr)
        repeat = json.loads(second.stdout)
        self.assertEqual(repeat['demo_events_added'], 0)
        self.assertEqual(repeat['new_alerts'], 0)
        self.assertEqual(repeat['events'], data['events'])
        with sqlite3.connect(self.database) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertGreater(db.execute('SELECT COUNT(*) FROM alert_events').fetchone()[0], 0)

    def test_invalid_database_is_an_actionable_error(self):
        self.database.write_bytes(b'not a sqlite file')
        before = self.database.read_bytes()
        result = self.invoke('--check')
        self.assertEqual(result.returncode, 1)
        self.assertIn('CyberWatch:', result.stderr)
        self.assertEqual(self.database.read_bytes(), before)

    def test_report_error_returns_nonzero_without_losing_events(self):
        first = self.invoke('--demo')
        self.assertEqual(first.returncode, 0, first.stderr)
        result = self.invoke('--report', str(self.folder / 'missing' / 'report.html'))
        self.assertEqual(result.returncode, 1)
        check = self.invoke('--check')
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual(json.loads(check.stdout)['alerts'], 3)

    def test_report_cannot_replace_the_database(self):
        created = self.invoke('--demo')
        self.assertEqual(created.returncode, 0, created.stderr)
        before = self.database.read_bytes()
        rejected = self.invoke('--report', str(self.database))
        self.assertEqual(rejected.returncode, 1)
        self.assertEqual(self.database.read_bytes(), before)
        check = self.invoke('--check')
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertEqual(json.loads(check.stdout)['alerts'], 3)

    def test_version_does_not_create_a_database(self):
        result = self.invoke('--version')
        self.assertEqual(result.returncode, 0)
        self.assertIn('2.0', result.stdout)
        self.assertFalse(self.database.exists())


if __name__ == '__main__':
    unittest.main()
