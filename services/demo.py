"""Repeatable, explicitly educational authentication and firewall events."""

from __future__ import annotations

from datetime import datetime, timedelta
import sqlite3

from db.database import add_event_record


def add_demo_events(connection: sqlite3.Connection) -> int:
    """Add 21 sample events once per database without modifying real data."""
    now = datetime.now().replace(microsecond=0)
    samples: list[tuple[datetime, str, str, str, str, int | None]] = []
    for index in range(5):
        samples.append((now - timedelta(minutes=4, seconds=50 - index * 10),
                        "203.0.113.45", "LOGIN_FAILED", "MEDIUM",
                        "[DEMO] Failed password for analyst from 203.0.113.45 port 51820 ssh2", None))
    samples.append((now - timedelta(minutes=3), "203.0.113.45", "LOGIN_SUCCESS", "LOW",
                    "[DEMO] Accepted password for analyst from 203.0.113.45 port 51820 ssh2", None))
    ports = (22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389)
    for index, port in enumerate(ports):
        samples.append((now - timedelta(minutes=6, seconds=40 - index * 2),
                        "198.51.100.23", "NETWORK_CONNECTION", "LOW",
                        f"[DEMO] [UFW BLOCK] SRC=198.51.100.23 DST=10.10.0.5 PROTO=TCP DPT={port}", port))
    samples.append((now - timedelta(minutes=1), "2001:db8::10", "LOGIN_SUCCESS", "LOW",
                    "[DEMO] Accepted publickey for student from 2001:db8::10 port 52200 ssh2", None))
    for index in range(2):
        samples.append((now - timedelta(minutes=2, seconds=index * 10),
                        "192.0.2.44", "LOGIN_FAILED", "MEDIUM",
                        "[DEMO] Failed publickey for guest from 192.0.2.44 port 53300 ssh2", None))
    inserted = 0
    with connection:
        for index, (timestamp, ip, kind, severity, message, port) in enumerate(samples):
            inserted += bool(add_event_record(
                connection, ip, kind, severity, message,
                timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                destination_ip="10.10.0.5" if port is not None else None,
                destination_port=port, source_file="DEMO · встроенный сценарий",
                event_key=f"demo-v2:{index:02d}",
            ))
    return inserted
