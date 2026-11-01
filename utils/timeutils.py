"""Local database timestamps and timestamp parsing for imported logs."""

from datetime import datetime, timedelta
import re


TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
_ISO_PREFIX = re.compile(
    r"^\[?(\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:[zZ]|[+-]\d{2}:?\d{2})?)"
)
_DATE_LIKE = re.compile(r"^\[?\d{4}[-/]\d{1,2}[-/]")
_SYSLOG_PREFIX = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?=\s|$)")
_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}


def now_text() -> str:
    return datetime.now().strftime(TIMESTAMP_FORMAT)


def normalize_timestamp(value: str | datetime) -> str:
    """Convert ISO timestamps to local wall-clock time used by legacy SQLite rows.

    A timezone-less value is already local time. Explicit UTC/offset timestamps
    are converted to the computer's local timezone before dropping the offset.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip().replace(",", ".")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError("Отсутствует корректная временная метка")
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed.strftime(TIMESTAMP_FORMAT)


def log_timestamp(line: str, *, now: datetime | None = None) -> str:
    """Read an ISO or BSD syslog prefix; use import time only if no prefix exists.

    Syslog lacks a year. Choose the most recent valid date no more than one day
    ahead of import time. This keeps December logs imported in January in the
    previous year. Malformed explicit date prefixes raise ValueError.
    """
    reference = now or datetime.now()
    if reference.tzinfo is not None:
        reference = reference.astimezone().replace(tzinfo=None)
    text = line.lstrip()
    # RFC 5424 priority and version, or RFC 3164 priority, before the timestamp.
    text = re.sub(r"^<\d{1,3}>(?:\d{1,2}\s+)?", "", text)
    iso = _ISO_PREFIX.match(text)
    if iso:
        token = iso.group(1)
        following = text[iso.end():iso.end() + 1]
        # Reject prefixes such as 12:00:00junk rather than accepting a substring.
        if following and following not in (" ", "\t", "]"):
            raise ValueError("Некорректная временная метка ISO")
        return normalize_timestamp(token)
    if _DATE_LIKE.match(text):
        raise ValueError("Некорректная временная метка ISO")
    syslog = _SYSLOG_PREFIX.match(text)
    if syslog:
        month_name, day, clock = syslog.groups()
        month = _MONTHS.get(month_name.title())
        if month is None:
            raise ValueError("Некорректный месяц syslog")
        hour, minute, second = map(int, clock.split(":"))
        for year in range(reference.year, reference.year - 5, -1):
            try:
                candidate = datetime(year, month, int(day), hour, minute, second)
            except ValueError:
                continue
            if candidate <= reference + timedelta(days=1):
                return candidate.strftime(TIMESTAMP_FORMAT)
        raise ValueError("Некорректная временная метка syslog")
    # A recognizable month with a malformed clock must not become a fresh event.
    if any(text.startswith(month + " ") for month in _MONTHS):
        raise ValueError("Некорректная временная метка syslog")
    return reference.strftime(TIMESTAMP_FORMAT)
