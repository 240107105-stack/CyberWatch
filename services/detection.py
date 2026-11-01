"""Explainable historical correlation using event time and linked evidence.

A brute-force or port-scan alert consumes its own supporting events. Later
scans require a fresh threshold of evidence for a new alert of the same rule.
A successful login after failures is a separate rule and can share evidence.
Invalid records and events dated in the future are excluded from correlation.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import ipaddress
import sqlite3

from utils.timeutils import now_text

BRUTE_FORCE = "SSH Brute Force"
SUCCESS_AFTER_FAILURE = "Login After Failures"
PORT_SCAN = "Port Scan"


@dataclass(frozen=True)
class DetectionResult:
    suspicious_ips: int
    new_alerts: int


@dataclass(frozen=True)
class _Event:
    id: int
    moment: datetime
    ip: str
    kind: str
    port: int | None


def _events(connection: sqlite3.Connection) -> dict[str, list[_Event]]:
    grouped = defaultdict(list)
    now = datetime.now()
    rows = connection.execute(
        "SELECT id, timestamp, source_ip, event_type, destination_port FROM events "
        "WHERE source_ip IS NOT NULL AND event_type IN ('LOGIN_FAILED', 'LOGIN_SUCCESS', 'NETWORK_CONNECTION')"
    )
    for identity, timestamp, address, kind, port in rows:
        try:
            ip = str(ipaddress.ip_address(address.strip()))
            moment = datetime.fromisoformat(timestamp)
            if moment.tzinfo is not None:
                moment = moment.astimezone().replace(tzinfo=None)
        except (ValueError, TypeError, AttributeError):
            continue
        if moment > now:
            continue
        valid_port = port if isinstance(port, int) and 1 <= port <= 65535 else None
        grouped[ip].append(_Event(identity, moment, ip, kind, valid_port))
    for events in grouped.values():
        events.sort(key=lambda event: (event.moment, event.id))
    return grouped


def _brute_windows(events: list[_Event], threshold: int, window: timedelta, excluded: set[int]):
    pending = deque()
    for event in events:
        if event.kind != "LOGIN_FAILED" or event.id in excluded:
            continue
        cutoff = event.moment - window
        while pending and pending[0].moment < cutoff:
            pending.popleft()
        pending.append(event)
        if len(pending) >= threshold:
            yield list(pending)
            pending.clear()


def _port_windows(events: list[_Event], threshold: int, window: timedelta, excluded: set[int]):
    pending = deque()
    for event in events:
        if event.kind != "NETWORK_CONNECTION" or event.port is None or event.id in excluded:
            continue
        cutoff = event.moment - window
        while pending and pending[0].moment < cutoff:
            pending.popleft()
        pending.append(event)
        if len({record.port for record in pending}) >= threshold:
            yield list(pending)
            pending.clear()


def _success_windows(events: list[_Event], threshold: int, window: timedelta):
    pending = deque()
    for event in events:
        if event.kind not in ("LOGIN_FAILED", "LOGIN_SUCCESS"):
            continue
        cutoff = event.moment - window
        while pending and pending[0].moment < cutoff:
            pending.popleft()
        if event.kind == "LOGIN_FAILED":
            pending.append(event)
        else:
            if len(pending) >= threshold:
                yield [*pending, event]
            pending.clear()


def _covered(connection: sqlite3.Connection, rule: str) -> set[int]:
    return {
        row[0] for row in connection.execute(
            "SELECT ae.event_id FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id WHERE a.rule_name = ?",
            (rule,),
        )
    }


def _create_alert(connection: sqlite3.Connection, rule: str, evidence: list[_Event],
                  threshold: int, window_minutes: int) -> bool:
    first, last = evidence[0], evidence[-1]
    identity = f"v2|{rule}|{first.ip}|{last.id}|{threshold}|{window_minutes}"
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    interval = f"{first.moment:%Y-%m-%d %H:%M:%S} — {last.moment:%Y-%m-%d %H:%M:%S}"
    if rule == BRUTE_FORCE:
        description = (f"{len(evidence)} неудачных попыток входа с {first.ip} за интервал "
                       f"до {window_minutes} мин. Время событий: {interval}.")
    elif rule == SUCCESS_AFTER_FAILURE:
        description = (f"Успешный вход с {first.ip} после {len(evidence) - 1} неудачных попыток "
                       f"за интервал до {window_minutes} мин. Время событий: {interval}. "
                       "Требуется проверка учётной записи; это сигнал, а не доказательство компрометации.")
    else:
        ports = sorted({event.port for event in evidence})
        description = (f"Соединения с {first.ip} к {len(ports)} различным портам за интервал "
                       f"до {window_minutes} мин. Порты: {', '.join(map(str, ports))}. "
                       f"Время событий: {interval}.")
    cursor = connection.execute(
        """INSERT INTO alerts
        (fingerprint, created_at, source_ip, rule_name, severity, description, status)
        VALUES (?, ?, ?, ?, 'HIGH', ?, 'OPEN')
        ON CONFLICT(fingerprint) DO NOTHING""",
        (fingerprint, now_text(), first.ip, rule, description),
    )
    if not cursor.rowcount:
        return False
    alert_id = cursor.lastrowid
    connection.executemany(
        "INSERT INTO alert_events(alert_id, event_id) VALUES (?, ?)",
        ((alert_id, event.id) for event in evidence),
    )
    connection.execute(
        "INSERT INTO alert_history(alert_id, changed_at, from_status, to_status) VALUES (?, ?, NULL, 'OPEN')",
        (alert_id, now_text()),
    )
    return True


def run_detection(connection: sqlite3.Connection, threshold: int = 5, window_minutes: int = 10,
                  *, port_threshold: int = 10) -> DetectionResult:
    """Correlate all stored history using a rolling, inclusive event-time window."""
    if (isinstance(threshold, bool) or not isinstance(threshold, int) or not 2 <= threshold <= 100
            or isinstance(window_minutes, bool) or not isinstance(window_minutes, int) or not 1 <= window_minutes <= 1440
            or isinstance(port_threshold, bool) or not isinstance(port_threshold, int) or not 2 <= port_threshold <= 1000):
        raise ValueError("Invalid detection thresholds or time window")
    grouped = _events(connection)
    window = timedelta(minutes=window_minutes)
    suspicious = set()
    created = 0
    with connection:
        brute_covered = _covered(connection, BRUTE_FORCE)
        port_covered = _covered(connection, PORT_SCAN)
        success_covered = _covered(connection, SUCCESS_AFTER_FAILURE)
        for ip, events in grouped.items():
            for rule, scanner, limit, covered in (
                (BRUTE_FORCE, _brute_windows, threshold, brute_covered),
                (PORT_SCAN, _port_windows, port_threshold, port_covered),
            ):
                if next(scanner(events, limit, window, set()), None) is not None:
                    suspicious.add(ip)
                for evidence in scanner(events, limit, window, covered):
                    if _create_alert(connection, rule, evidence, limit, window_minutes):
                        created += 1
                        covered.update(event.id for event in evidence)
            for evidence in _success_windows(events, threshold, window):
                suspicious.add(ip)
                if evidence[-1].id not in success_covered:
                    if _create_alert(connection, SUCCESS_AFTER_FAILURE, evidence, threshold, window_minutes):
                        created += 1
                        success_covered.update(event.id for event in evidence)
    return DetectionResult(suspicious_ips=len(suspicious), new_alerts=created)
