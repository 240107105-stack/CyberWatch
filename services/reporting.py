"""Local CSV and standalone HTML reports, with no network dependencies."""

from __future__ import annotations

import csv
from contextlib import contextmanager
from datetime import datetime
from html import escape
import ipaddress
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Iterator, TextIO


EVENT_COLUMNS = (
    "id", "timestamp", "source_ip", "event_type", "severity", "message",
    "destination_ip", "destination_port", "source_file",
)
SEVERITIES = {"ALL", "LOW", "MEDIUM", "HIGH"}
DOCUMENTATION_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
))
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
))


def event_filter(search: str = "", severity: str = "ALL") -> tuple[str, list[object]]:
    """Return a parameterized WHERE clause for a literal substring search."""
    if severity not in SEVERITIES:
        raise ValueError("Неизвестный приоритет события.")
    clauses: list[str] = []
    parameters: list[object] = []
    search = search.strip()
    if search:
        term = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        fields = (
            "timestamp", "COALESCE(source_ip, '')", "event_type", "message",
            "COALESCE(destination_ip, '')", "CAST(COALESCE(destination_port, '') AS TEXT)",
            "COALESCE(source_file, '')",
        )
        clauses.append("(" + " OR ".join(f"{field} LIKE ? ESCAPE '\\'" for field in fields) + ")")
        parameters.extend([term] * len(fields))
    if severity != "ALL":
        clauses.append("severity = ?")
        parameters.append(severity)
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), parameters


def _csv_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    meaningful = value
    while meaningful and (ord(meaningful[0]) <= 32 or ord(meaningful[0]) == 127 or meaningful[0] == "\ufeff"):
        meaningful = meaningful[1:]
    if meaningful.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _check_destination(connection: sqlite3.Connection, path: str | Path) -> Path:
    """Never replace a connected database or one of its SQLite sidecar files."""
    target = Path(path).expanduser()
    resolved = target.resolve()
    for _sequence, _name, filename in connection.execute("PRAGMA database_list"):
        if not filename:
            continue
        database = Path(filename)
        for protected in (database, *(Path(str(database) + suffix) for suffix in ("-wal", "-shm", "-journal"))):
            if resolved == protected.resolve():
                raise ValueError("Нельзя сохранять отчёт поверх открытой базы данных или её служебных файлов.")
            try:
                same_file = target.exists() and protected.exists() and target.samefile(protected)
            except OSError:
                same_file = False
            if same_file:
                raise ValueError("Файл отчёта связан с открытой базой данных. Выберите другое имя.")
    return target


@contextmanager
def _atomic_text(path: str | Path, *, encoding: str = "utf-8", newline: str | None = None) -> Iterator[TextIO]:
    target = Path(path).expanduser()
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding=encoding, newline=newline,
                                         dir=target.parent, prefix=f".{target.name}.",
                                         suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            yield output
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def export_events_csv(connection: sqlite3.Connection, path: str | Path, *,
                      search: str = "", severity: str = "ALL") -> int:
    """Export every matching event, protecting spreadsheet users from formulas."""
    target = _check_destination(connection, path)
    where, parameters = event_filter(search, severity)
    cursor = connection.execute(
        "SELECT " + ", ".join(EVENT_COLUMNS) + " FROM events" + where + " ORDER BY id DESC",
        parameters,
    )
    count = 0
    with _atomic_text(target, encoding="utf-8-sig", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(EVENT_COLUMNS)
        for row in cursor:
            writer.writerow(_csv_cell(value) for value in row)
            count += 1
    return count


def describe_ip_scope(value: str | None) -> str:
    """Classify address scope; this is not a GeoIP or reputation lookup."""
    if not value:
        return "Не указан"
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "Некорректный адрес"
    if address.is_loopback:
        return "Локальный (loopback)"
    if address.is_link_local:
        return "Link-local"
    if address.is_multicast:
        return "Multicast"
    if any(address.version == network.version and address in network for network in DOCUMENTATION_NETWORKS):
        return "Документационный адрес (демо)"
    if any(address.version == network.version and address in network for network in PRIVATE_NETWORKS):
        return "Частная сеть"
    if address.is_global:
        return "Глобальный адрес"
    if address.is_reserved:
        return "Зарезервированный адрес"
    return "Специальный / неглобальный адрес"


def _rows(connection: sqlite3.Connection, query: str, parameters: tuple = ()) -> list[dict]:
    cursor = connection.execute(query, parameters)
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor]


def _text(value: object) -> str:
    return escape("—" if value is None else str(value), quote=True)


def _table(headers: tuple[str, ...], rows: list[tuple]) -> str:
    heading = "".join(f"<th>{_text(value)}</th>" for value in headers)
    if rows:
        body = "".join("<tr>" + "".join(f"<td>{_text(value)}</td>" for value in row) + "</tr>" for row in rows)
    else:
        body = f'<tr><td colspan="{len(headers)}" class="muted">Записей нет</td></tr>'
    return f'<div class="table-wrap"><table><thead><tr>{heading}</tr></thead><tbody>{body}</tbody></table></div>'


def export_report_html(connection: sqlite3.Connection, path: str | Path) -> int:
    """Write a self-contained analyst report and return its alert count."""
    target = _check_destination(connection, path)
    total_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    alerts = _rows(connection, "SELECT * FROM alerts ORDER BY id DESC")
    open_alerts = sum(alert["status"] == "OPEN" for alert in alerts)
    sources = _rows(connection, """
        SELECT source_ip, COUNT(*) AS events, MIN(timestamp) AS first_seen,
               MAX(timestamp) AS last_seen FROM events WHERE source_ip IS NOT NULL
        GROUP BY source_ip ORDER BY events DESC, source_ip
    """)
    summaries = _rows(connection, """
        SELECT rule_name, severity, status, COUNT(*) AS count FROM alerts
        GROUP BY rule_name, severity, status ORDER BY rule_name, severity, status
    """)
    settings = _rows(connection, "SELECT key, value FROM settings ORDER BY key")
    fragments = ["""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>CyberWatch — отчёт аналитика</title>
<style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#edf2f6;color:#152336;font:15px/1.55 system-ui,sans-serif}
main{max-width:1200px;margin:36px auto;padding:32px;background:white;border:1px solid #d4dde5;border-radius:16px}
header{border-bottom:3px solid #1b8b71;padding-bottom:20px}h1{margin:0;font-size:32px}h2{margin:32px 0 12px;font-size:22px}
h3{margin:0 0 12px;font-size:18px}.eyebrow{color:#18755f;font-weight:700;letter-spacing:2px;font-size:12px}.muted{color:#526477}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:24px}.stat{padding:16px;background:#f1f6f8;border-radius:10px}
.stat strong{display:block;font-size:30px}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:10px 12px;border-bottom:1px solid #dce4eb;text-align:left;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}
th{background:#edf3f7;color:#344a61}tr:nth-child(even){background:#f9fbfc}.alert{border:1px solid #d4dde5;border-radius:12px;padding:20px;margin:16px 0;break-inside:avoid}
.description{white-space:pre-wrap;overflow-wrap:anywhere}.label{display:inline-block;padding:3px 9px;background:#edf3f7;border-radius:20px;font-size:12px;margin-right:6px}
footer{border-top:1px solid #dce4eb;margin-top:32px;padding-top:16px;font-size:12px;color:#526477}
@media(max-width:700px){main{margin:0;padding:18px;border:0;border-radius:0}.stats{grid-template-columns:repeat(2,1fr)}}
@media print{body{background:white}main{border:0;margin:0;padding:0;max-width:none}.table-wrap{overflow:visible}h2{break-after:avoid}}
</style></head><body><main><header><div class="eyebrow">CYBERWATCH · LOCAL SIEM</div>
<h1>Отчёт аналитика</h1>"""]
    generated = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    fragments.append(f'<p class="muted">Сформирован: {_text(generated)} · Локальное время компьютера</p></header>')
    fragments.append('<section class="stats">' + "".join(
        f'<div class="stat"><span>{_text(label)}</span><strong>{count}</strong></div>'
        for label, count in (("Событий", total_events), ("Сигналов", len(alerts)),
                             ("Открытых сигналов", open_alerts), ("IP-источников", len(sources)))
    ) + "</section>")
    fragments.append('<h2>Сводка по правилам</h2>')
    fragments.append(_table(("Правило", "Приоритет", "Статус", "Количество"), [
        (row["rule_name"], row["severity"], row["status"], row["count"]) for row in summaries
    ]))
    fragments.append('<h2>Настройки анализа</h2><p class="muted">Сохранённые настройки на момент экспорта. '
                     'Описание каждого сигнала содержит параметры его обнаружения.</p>')
    fragments.append(_table(("Параметр", "Значение"), [(row["key"], row["value"]) for row in settings]))
    fragments.append('<h2>Источники событий</h2><p class="muted">Классификация IP отражает область адресации. '
                     'Геолокация и репутация адресов в этом отчёте не определяются.</p>')
    fragments.append(_table(("IP", "Область адресации", "Событий", "Первое событие", "Последнее событие"), [
        (row["source_ip"], describe_ip_scope(row["source_ip"]), row["events"], row["first_seen"], row["last_seen"])
        for row in sources
    ]))
    fragments.append('<h2>Сигналы и ход расследования</h2>')
    if not alerts:
        fragments.append('<p class="muted">Сигналов нет. Импортируйте события и запустите детекцию.</p>')
    for alert in alerts:
        alert_id = alert["id"]
        fragments.append(f'<article class="alert"><h3>#{alert_id} · {_text(alert["rule_name"])}</h3>')
        fragments.append("<p>" + "".join(f'<span class="label">{_text(value)}</span>' for value in (
            alert["severity"], alert["status"], alert["source_ip"], alert["created_at"],
        )) + "</p>")
        fragments.append(f'<p class="description">{_text(alert["description"])}</p>')
        evidence = _rows(connection, """
            SELECT e.id, e.timestamp, e.source_ip, e.event_type, e.destination_port, e.message
            FROM alert_events ae JOIN events e ON e.id = ae.event_id
            WHERE ae.alert_id = ? ORDER BY e.timestamp, e.id
        """, (alert_id,))
        fragments.append('<h4>Связанные события</h4>')
        fragments.append(_table(("ID", "Время", "IP", "Тип", "Порт назначения", "Сообщение"), [
            (row["id"], row["timestamp"], row["source_ip"], row["event_type"], row["destination_port"], row["message"])
            for row in evidence
        ]))
        notes = _rows(connection, "SELECT created_at, note FROM alert_notes WHERE alert_id = ? ORDER BY id", (alert_id,))
        fragments.append('<h4>Заметки аналитика</h4>')
        fragments.append(_table(("Время", "Заметка"), [(row["created_at"], row["note"]) for row in notes]))
        history = _rows(connection, "SELECT changed_at, from_status, to_status FROM alert_history WHERE alert_id = ? ORDER BY id", (alert_id,))
        fragments.append('<h4>История статусов</h4>')
        fragments.append(_table(("Время", "Было", "Стало"), [
            (row["changed_at"], row["from_status"], row["to_status"]) for row in history
        ]))
        fragments.append('</article>')
    fragments.append('<footer>CyberWatch 2.0 · Учебный проект для портфолио SOC-аналитика. '
                     'Отчёт отражает содержимое локальной базы на момент экспорта. Сигнал требует проверки аналитиком; '
                     'приложение не блокирует сетевой трафик. HTML автономен и не отправляет данные в сеть.</footer></main></body></html>')
    with _atomic_text(target) as output:
        output.write("\n".join(fragments))
    return len(alerts)
