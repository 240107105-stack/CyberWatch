"""SQLite storage and additive migrations for the local CyberWatch workspace.

Event insertion and setting changes participate in the caller's transaction.
Response actions are atomic and keep a persistent audit trail.
"""

import ipaddress
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from utils.timeutils import now_text

DB_PATH = Path(__file__).resolve().parent.parent / "cyberwatch.db"
SCHEMA_VERSION = 2
ALERT_STATUSES = ("OPEN", "ACKNOWLEDGED", "RESOLVED")


def connect_database(path: str | Path = DB_PATH) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        initialize_database(connection)
    except Exception:
        connection.close()
        raise
    return connection


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create new tables or extend the legacy schema without replacing data."""
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    statements = (
        """CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            source_ip TEXT,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN'
        )""",
        "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        """CREATE TABLE IF NOT EXISTS alert_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            note TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            changed_at TEXT NOT NULL,
            from_status TEXT,
            to_status TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS alert_events (
            alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            PRIMARY KEY(alert_id, event_id)
        )""",
    )
    with connection:
        for statement in statements:
            connection.execute(statement)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(events)")}
        for name, kind in (
            ("destination_ip", "TEXT"),
            ("destination_port", "INTEGER"),
            ("source_file", "TEXT"),
            ("event_key", "TEXT"),
        ):
            if name not in columns:
                connection.execute(f"ALTER TABLE events ADD COLUMN {name} {kind}")
        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_ip_type ON events(source_ip, event_type)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_event_key ON events(event_key)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
            "CREATE INDEX IF NOT EXISTS idx_alert_notes_alert ON alert_notes(alert_id)",
            "CREATE INDEX IF NOT EXISTS idx_alert_history_alert ON alert_history(alert_id)",
            "CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id)",
        ):
            connection.execute(statement)
        _backfill_legacy_brute_force_evidence(connection)
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version < SCHEMA_VERSION:
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")



def _backfill_legacy_brute_force_evidence(connection: sqlite3.Connection) -> None:
    """Link only exactly verifiable evidence from the original detector.

    The old fingerprint contained the source IP, first/last event timestamps
    and exact attempt count. A mismatch leaves the legacy alert untouched.
    """
    timestamp_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    alerts = connection.execute(
        "SELECT id, source_ip, fingerprint FROM alerts a "
        "WHERE rule_name = 'SSH Brute Force' "
        "AND fingerprint LIKE 'BRUTE_FORCE:%' "
        "AND NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.alert_id = a.id)"
    ).fetchall()
    for alert_id, source_ip, fingerprint in alerts:
        if not isinstance(source_ip, str):
            continue
        try:
            ipaddress.ip_address(source_ip.strip())
        except ValueError:
            continue
        matched = re.fullmatch(
            re.escape(f"BRUTE_FORCE:{source_ip}:")
            + timestamp_pattern + ":" + timestamp_pattern + r":([1-9]\d*)",
            fingerprint,
        )
        if matched is None:
            continue
        first, last, attempts_text = matched.groups()
        try:
            first_time, last_time = datetime.fromisoformat(first), datetime.fromisoformat(last)
            attempts = int(attempts_text)
        except ValueError:
            continue
        if first_time > last_time or attempts < 2:
            continue
        evidence = connection.execute(
            "SELECT id, timestamp FROM events WHERE event_type = 'LOGIN_FAILED' "
            "AND source_ip = ? AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp, id",
            (source_ip, first, last),
        ).fetchall()
        if (len(evidence) != attempts or not evidence
                or evidence[0][1] != first or evidence[-1][1] != last):
            continue
        connection.executemany(
            "INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)",
            ((alert_id, event[0]) for event in evidence),
        )


def _normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def add_event_record(
    connection: sqlite3.Connection,
    source_ip: str | None,
    event_type: str,
    severity: str,
    message: str,
    timestamp: str | None = None,
    *,
    destination_ip: str | None = None,
    destination_port: int | None = None,
    source_file: str | None = None,
    event_key: str | None = None,
) -> bool:
    """Insert a record; return False only for an already imported event_key."""
    if destination_port is not None:
        if isinstance(destination_port, bool) or not isinstance(destination_port, int) or not 1 <= destination_port <= 65535:
            raise ValueError("Destination port must be an integer from 1 to 65535")
    timestamp = timestamp or now_text()
    moment = datetime.fromisoformat(timestamp)
    if moment.tzinfo is not None:
        moment = moment.astimezone().replace(tzinfo=None)
    cursor = connection.execute(
        """INSERT INTO events
        (timestamp, source_ip, event_type, severity, message,
         destination_ip, destination_port, source_file, event_key)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_key) DO NOTHING""",
        (moment.strftime("%Y-%m-%d %H:%M:%S"), _normalize_ip(source_ip),
         event_type, severity, message[:1000], _normalize_ip(destination_ip),
         destination_port, source_file, event_key or None),
    )
    return cursor.rowcount == 1


def get_setting(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row is not None else default


def set_setting(connection: sqlite3.Connection, key: str, value: object) -> None:
    connection.execute(
        "INSERT INTO settings(key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


def change_alert_status(connection: sqlite3.Connection, alert_id: int, status: str) -> bool:
    if status not in ALERT_STATUSES:
        raise ValueError("Unknown alert status")
    with connection:
        row = connection.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row is None or row[0] == status:
            return False
        connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        connection.execute(
            "INSERT INTO alert_history(alert_id, changed_at, from_status, to_status) VALUES (?, ?, ?, ?)",
            (alert_id, now_text(), row[0], status),
        )
    return True


def add_alert_note(connection: sqlite3.Connection, alert_id: int, note: str) -> int:
    note = note.strip()
    if not note or len(note) > 5000:
        raise ValueError("A note must contain from 1 to 5000 characters")
    with connection:
        if connection.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone() is None:
            raise ValueError("Alert does not exist")
        cursor = connection.execute(
            "INSERT INTO alert_notes(alert_id, created_at, note) VALUES (?, ?, ?)",
            (alert_id, now_text(), note),
        )
    return int(cursor.lastrowid)


def get_alert_notes(connection: sqlite3.Connection, alert_id: int) -> list:
    return connection.execute(
        "SELECT id, alert_id, created_at, note FROM alert_notes WHERE alert_id = ? ORDER BY id",
        (alert_id,),
    ).fetchall()
