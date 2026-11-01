"""Streaming log ingestion without Tk dependencies or third-party packages."""

from dataclasses import dataclass
from datetime import datetime
import csv
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Iterable

from config import FAILED_PATTERNS, SUCCESS_PATTERNS
from db.database import add_event_record
from utils.network import normalize_ip
from utils.timeutils import log_timestamp, normalize_timestamp


@dataclass(frozen=True)
class ParsedEvent:
    timestamp: str
    source_ip: str | None
    event_type: str
    severity: str
    message: str
    destination_ip: str | None = None
    destination_port: int | None = None


@dataclass(frozen=True)
class ImportResult:
    imported: int = 0
    skipped: int = 0
    duplicates: int = 0


_FROM = re.compile(r"\bfrom\s+([^\s]+)", re.IGNORECASE)
_FIELDS = re.compile(r"\b(SRC|DST|DPT)=([^\s]+)", re.IGNORECASE)
_SEVERITIES = {"LOW", "MEDIUM", "HIGH"}


def _address(token: object) -> str | None:
    if not isinstance(token, str):
        return None
    token = token.strip(" \t\r\n,;(){}\"'")
    if token.startswith("["):
        bracket = re.fullmatch(r"\[([^\]]+)\](?::\d+)?[.,;]?", token)
        return normalize_ip(bracket.group(1)) if bracket else None
    address = normalize_ip(token)
    if address:
        return address
    if token.endswith("."):
        address = normalize_ip(token[:-1])
        if address:
            return address
    # IPv4 host:port only; a colon inside IPv6 belongs to the address itself.
    if token.count(":") == 1:
        host, port = token.rsplit(":", 1)
        if port.isdigit():
            return normalize_ip(host)
    return None


def _source_address(line: str) -> str | None:
    explicit = _FROM.search(line)
    if explicit:
        return _address(explicit.group(1))
    for token in re.split(r"[\s=,;/()]+", line):
        if "." in token or ":" in token:
            address = _address(token)
            if address:
                return address
    return None


def _classification(message: str) -> tuple[str, str]:
    lowered = message.lower()
    if any(pattern in lowered for pattern in FAILED_PATTERNS):
        return "LOGIN_FAILED", "MEDIUM"
    if any(pattern in lowered for pattern in SUCCESS_PATTERNS):
        return "LOGIN_SUCCESS", "LOW"
    return "LOG_EVENT", "LOW"


def _port(value: object) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("Некорректный порт")
    text = str(value)
    if not text.isdecimal():
        raise ValueError("Некорректный порт")
    number = int(text)
    if not 1 <= number <= 65535:
        raise ValueError("Порт вне диапазона")
    return number


def _structured(record: dict, now: datetime | None) -> ParsedEvent | None:
    message = record.get("message")
    if not isinstance(message, str) or not message.strip():
        return None
    timestamp = record.get("timestamp")
    if timestamp in (None, ""):
        timestamp = log_timestamp("", now=now)
    else:
        timestamp = normalize_timestamp(timestamp)
    source = record.get("source_ip")
    if source in (None, ""):
        source = _source_address(message)
    else:
        source = _address(source)
        if source is None:
            return None
    destination = record.get("destination_ip")
    if destination not in (None, ""):
        destination = _address(destination)
        if destination is None:
            return None
    else:
        destination = None
    kind, severity = _classification(message)
    requested_kind = record.get("event_type")
    if requested_kind not in (None, ""):
        if not isinstance(requested_kind, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", requested_kind):
            return None
        kind = requested_kind.upper()
    requested_severity = record.get("severity")
    if requested_severity not in (None, ""):
        if not isinstance(requested_severity, str) or requested_severity.upper() not in _SEVERITIES:
            return None
        severity = requested_severity.upper()
    return ParsedEvent(timestamp, source, kind, severity, message.strip()[:1000],
                       destination, _port(record.get("destination_port")))


def parse_line(line: str, *, now: datetime | None = None) -> ParsedEvent | None:
    """Parse SSH/syslog, UFW, generic IP log lines or one JSON event object.

    A line without a timestamp gets import time; a malformed explicit timestamp
    is skipped. Unstructured lines must contain a valid source address.
    """
    if not isinstance(line, str) or not line.strip():
        return None
    text = line.strip().lstrip("\ufeff")
    if not text:
        return None
    try:
        if text.startswith(("{", "[")):
            # '[' also starts a bracketed ISO timestamp, not necessarily JSON.
            if text.startswith("{") or not (re.match(r"\[\d{4}-", text) or re.match(r"\[UFW\b", text, re.IGNORECASE)):
                record = json.loads(text)
                return _structured(record, now) if isinstance(record, dict) else None
        timestamp = log_timestamp(text, now=now)
        fields = {name.upper(): value for name, value in _FIELDS.findall(text)}
        if "SRC" in fields:
            source = _address(fields["SRC"])
            if source is None:
                return None
            destination = _address(fields["DST"]) if "DST" in fields else None
            if "DST" in fields and destination is None:
                return None
            port = _port(fields.get("DPT"))
            return ParsedEvent(timestamp, source, "NETWORK_CONNECTION", "LOW", text[:1000],
                               destination, port)
        source = _source_address(text)
        if source is None:
            return None
        kind, severity = _classification(text)
        return ParsedEvent(timestamp, source, kind, severity, text[:1000])
    except (ValueError, TypeError, OverflowError):
        return None


def event_key(source_id: str, line_number: int, line: str) -> str:
    """Physical line identity preserves identical attempts on separate lines."""
    payload = f"{source_id}\0{line_number}\0{line.rstrip(chr(10) + chr(13))}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def ingest_lines(
    connection: sqlite3.Connection,
    lines: Iterable[tuple[int, str]],
    source_id: str,
    source_file: str | None = None,
    *,
    now: datetime | None = None,
) -> ImportResult:
    """Commit a batch atomically; read/parse exceptions roll the batch back."""
    imported = skipped = duplicates = 0
    reference = now or datetime.now()
    with connection:
        for line_number, line in lines:
            event = parse_line(line, now=reference)
            if event is None:
                skipped += 1
                continue
            inserted = add_event_record(
                connection, event.source_ip, event.event_type, event.severity,
                event.message, event.timestamp,
                destination_ip=event.destination_ip,
                destination_port=event.destination_port,
                source_file=source_file or source_id,
                event_key=event_key(source_id, line_number, line),
            )
            if inserted:
                imported += 1
            else:
                duplicates += 1
    return ImportResult(imported, skipped, duplicates)


def _csv_lines(source) -> Iterable[tuple[int, str]]:
    reader = csv.DictReader(source, strict=True)
    required = {"timestamp", "source_ip", "event_type", "severity", "message"}
    if reader.fieldnames is None or not required.issubset(set(reader.fieldnames)):
        raise ValueError("CSV должен содержать поля timestamp, source_ip, event_type, severity, message")
    for record in reader:
        if None in record or any(value is None for value in record.values()):
            yield reader.line_num, ""
        else:
            yield reader.line_num, json.dumps(record, sort_keys=True, ensure_ascii=False)


def import_log_file(connection: sqlite3.Connection, path: str | Path) -> ImportResult:
    """Import a UTF-8 text/JSONL log or an exported CSV in one transaction."""
    filename = Path(path).expanduser().resolve()
    with filename.open("r", encoding="utf-8-sig", errors="replace", newline="") as source:
        lines = _csv_lines(source) if filename.suffix.lower() == ".csv" else enumerate(source, 1)
        return ingest_lines(connection, lines, str(filename), str(filename))
