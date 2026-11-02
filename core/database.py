"""SQLite persistence layer.

All SQL lives here (repository functions). Pages and analytics modules call these
functions instead of building SQL themselves. Every query is parameterized; the only
dynamic SQL fragments are column names taken from fixed allow-lists.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from core.config import DB_PATH
from core.logging_config import get_logger

log = get_logger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
    is_active      INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until   TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_hash       TEXT NOT NULL UNIQUE,
    timestamp        TEXT,
    hostname         TEXT,
    username         TEXT,
    source_ip        TEXT,
    source_port      INTEGER,
    destination_ip   TEXT,
    destination_port INTEGER,
    process_name     TEXT,
    process_path     TEXT,
    parent_process   TEXT,
    command_line     TEXT,
    event_category   TEXT,
    event_action     TEXT,
    outcome          TEXT,
    event_code       TEXT,
    domain           TEXT,
    url              TEXT,
    file_hash        TEXT,
    protocol         TEXT,
    severity         TEXT,
    source_type      TEXT NOT NULL,
    source_file      TEXT,
    record_ref       TEXT,
    ingested_at      TEXT NOT NULL,
    raw_event        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_hostname  ON events(hostname);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst_ip    ON events(destination_ip);
CREATE INDEX IF NOT EXISTS idx_events_username  ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_category  ON events(event_category);

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id            TEXT PRIMARY KEY,
    rule_name          TEXT NOT NULL,
    description        TEXT,
    rule_logic         TEXT NOT NULL,
    severity           TEXT NOT NULL,
    mitre_technique_id TEXT,
    enabled            INTEGER NOT NULL DEFAULT 1,
    source_file        TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER REFERENCES events(event_id) ON DELETE SET NULL,
    rule_id     TEXT NOT NULL REFERENCES detection_rules(rule_id),
    severity    TEXT NOT NULL,
    description TEXT,
    evidence    TEXT,
    status      TEXT NOT NULL DEFAULT 'New',
    dedupe_key  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (rule_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);

-- every event that contributed to an alert (threshold alerts have many)
CREATE TABLE IF NOT EXISTS alert_events (
    alert_id INTEGER NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, event_id)
);

-- local threat-intelligence list (loaded from CSV)
CREATE TABLE IF NOT EXISTS ioc_watchlist (
    indicator_type  TEXT NOT NULL,
    indicator_value TEXT NOT NULL,
    source          TEXT,
    confidence      TEXT,
    description     TEXT,
    PRIMARY KEY (indicator_type, indicator_value)
);

-- indicators observed in ingested events
CREATE TABLE IF NOT EXISTS iocs (
    ioc_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator_type    TEXT NOT NULL,
    indicator_value   TEXT NOT NULL,
    source            TEXT,
    confidence        TEXT,
    first_seen        TEXT,
    last_seen         TEXT,
    observations      INTEGER NOT NULL DEFAULT 0,
    watchlist_match   INTEGER NOT NULL DEFAULT 0,
    enrichment_status TEXT NOT NULL DEFAULT 'not_enriched',
    enrichment_data   TEXT,
    UNIQUE (indicator_type, indicator_value)
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(indicator_value);

CREATE TABLE IF NOT EXISTS ioc_events (
    ioc_id   INTEGER NOT NULL REFERENCES iocs(ioc_id) ON DELETE CASCADE,
    event_id INTEGER NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    PRIMARY KEY (ioc_id, event_id)
);

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    description TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    status      TEXT NOT NULL DEFAULT 'New',
    verdict     TEXT NOT NULL DEFAULT 'Undetermined',
    conclusion  TEXT,
    created_by  INTEGER REFERENCES users(user_id),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS investigation_events (
    investigation_id INTEGER NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    event_id         INTEGER NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    PRIMARY KEY (investigation_id, event_id)
);
CREATE TABLE IF NOT EXISTS investigation_alerts (
    investigation_id INTEGER NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    alert_id         INTEGER NOT NULL REFERENCES alerts(alert_id) ON DELETE CASCADE,
    PRIMARY KEY (investigation_id, alert_id)
);
CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    investigation_id INTEGER NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    user_id          INTEGER REFERENCES users(user_id),
    note             TEXT NOT NULL,
    is_system        INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER,
    username    TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    detail      TEXT,
    timestamp   TEXT NOT NULL
);
"""

EVENT_COLUMNS = [
    "timestamp", "hostname", "username", "source_ip", "source_port", "destination_ip",
    "destination_port", "process_name", "process_path", "parent_process", "command_line",
    "event_category", "event_action", "outcome", "event_code", "domain", "url", "file_hash",
    "protocol", "severity", "source_type", "source_file", "record_ref",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@contextmanager
def get_conn(db_path=None) -> Iterator[sqlite3.Connection]:
    path = str(db_path or DB_PATH)
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path=None) -> None:
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)


def rows(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> dict | None:
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def scalar(conn: sqlite3.Connection, sql: str, params: Sequence[Any] = ()) -> Any:
    r = conn.execute(sql, params).fetchone()
    return r[0] if r else None


# --------------------------------------------------------------------------- audit
def audit(conn, actor: dict | None, action: str, target_type: str | None = None,
          target_id: Any = None, detail: str | None = None) -> None:
    conn.execute(
        "INSERT INTO audit_logs (user_id, username, action, target_type, target_id, detail, timestamp)"
        " VALUES (?,?,?,?,?,?,?)",
        (actor.get("user_id") if actor else None, actor.get("username") if actor else None,
         action, target_type, None if target_id is None else str(target_id), detail, now_iso()),
    )


# --------------------------------------------------------------------------- events
def insert_events(conn, events: Iterable[dict]) -> tuple[int, int]:
    """Insert normalized events. Returns (inserted, duplicates). Duplicates = same event_hash."""
    cols = ["event_hash", *EVENT_COLUMNS, "ingested_at", "raw_event"]
    sql = f"INSERT OR IGNORE INTO events ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
    inserted = dup = 0
    ts = now_iso()
    for ev in events:
        values = [ev["event_hash"], *[ev.get(c) for c in EVENT_COLUMNS], ts, ev["raw_event"]]
        cur = conn.execute(sql, values)
        if cur.rowcount:
            inserted += 1
        else:
            dup += 1
    return inserted, dup


# Fixed allow-list of filters -> column. Values are always bound parameters.
_SEARCH_FILTERS = {
    "hostname": "hostname", "username": "username", "source_ip": "source_ip",
    "destination_ip": "destination_ip", "process_name": "process_name",
    "event_category": "event_category", "source_type": "source_type", "outcome": "outcome",
    "event_code": "event_code", "domain": "domain",
}


def search_events(conn, filters: dict | None = None, limit: int = 1000, offset: int = 0) -> list[dict]:
    where, params = _build_event_where(filters or {})
    sql = f"SELECT e.* FROM events e {where} ORDER BY e.timestamp DESC, e.event_id DESC LIMIT ? OFFSET ?"
    return rows(conn, sql, [*params, int(limit), int(offset)])


def count_events(conn, filters: dict | None = None) -> int:
    where, params = _build_event_where(filters or {})
    return scalar(conn, f"SELECT COUNT(*) FROM events e {where}", params) or 0


def _like(value: str) -> str:
    value = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{value}%"


def _build_event_where(f: dict) -> tuple[str, list]:
    clauses, params = [], []
    for key, col in _SEARCH_FILTERS.items():
        v = f.get(key)
        if v not in (None, ""):
            clauses.append(f"e.{col} LIKE ? ESCAPE '\\' COLLATE NOCASE")
            params.append(_like(str(v)))
    if f.get("text"):
        clauses.append("(e.command_line LIKE ? ESCAPE '\\' OR e.raw_event LIKE ? ESCAPE '\\')")
        params += [_like(str(f["text"]))] * 2
    if f.get("start"):
        clauses.append("e.timestamp >= ?")
        params.append(f["start"])
    if f.get("end"):
        clauses.append("e.timestamp <= ?")
        params.append(f["end"])
    if f.get("severity"):
        clauses.append("EXISTS (SELECT 1 FROM alert_events ae JOIN alerts a ON a.alert_id=ae.alert_id "
                       "WHERE ae.event_id=e.event_id AND a.severity=?)")
        params.append(f["severity"])
    if f.get("rule_id"):
        clauses.append("EXISTS (SELECT 1 FROM alert_events ae JOIN alerts a ON a.alert_id=ae.alert_id "
                       "WHERE ae.event_id=e.event_id AND a.rule_id=?)")
        params.append(f["rule_id"])
    if f.get("alerted_only"):
        clauses.append("EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id=e.event_id)")
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", params


def get_event(conn, event_id: int) -> dict | None:
    return one(conn, "SELECT * FROM events WHERE event_id=?", (event_id,))


def get_events_by_ids(conn, ids: Sequence[int]) -> list[dict]:
    out: list[dict] = []
    ids = list(ids)
    for i in range(0, len(ids), 500):  # stay under SQLite variable limit
        chunk = ids[i:i + 500]
        out += rows(conn, f"SELECT * FROM events WHERE event_id IN ({','.join('?' * len(chunk))})", chunk)
    return sorted(out, key=lambda r: (r["timestamp"] or "", r["event_id"]))


def distinct_values(conn, column: str) -> list[str]:
    if column not in set(_SEARCH_FILTERS.values()):
        raise ValueError("column not allowed")
    return [r[0] for r in conn.execute(
        f"SELECT DISTINCT {column} FROM events WHERE {column} IS NOT NULL ORDER BY 1 LIMIT 500")]


# --------------------------------------------------------------------------- alerts
def insert_alert(conn, *, rule_id: str, severity: str, description: str, evidence: dict,
                 event_ids: Sequence[int], dedupe_key: str) -> int | None:
    """Create an alert unless (rule_id, dedupe_key) already exists. Returns alert_id or None."""
    primary = event_ids[0] if event_ids else None
    cur = conn.execute(
        "INSERT OR IGNORE INTO alerts (event_id, rule_id, severity, description, evidence, dedupe_key, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (primary, rule_id, severity, description, json.dumps(evidence, default=str), dedupe_key, now_iso()))
    if not cur.rowcount:
        return None
    alert_id = cur.lastrowid
    conn.executemany("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?,?)",
                     [(alert_id, e) for e in event_ids])
    return alert_id


def list_alerts(conn, severity=None, status=None, rule_id=None, limit=2000) -> list[dict]:
    clauses, params = [], []
    for col, val in (("a.severity", severity), ("a.status", status), ("a.rule_id", rule_id)):
        if val:
            clauses.append(f"{col}=?")
            params.append(val)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = (f"SELECT a.*, r.rule_name, r.mitre_technique_id, "
           f"(SELECT COUNT(*) FROM alert_events ae WHERE ae.alert_id=a.alert_id) AS event_count "
           f"FROM alerts a JOIN detection_rules r ON r.rule_id=a.rule_id {where} "
           f"ORDER BY a.created_at DESC, a.alert_id DESC LIMIT ?")
    return rows(conn, sql, [*params, limit])


def get_alert(conn, alert_id: int) -> dict | None:
    a = one(conn, "SELECT a.*, r.rule_name, r.mitre_technique_id, r.rule_logic FROM alerts a "
                  "JOIN detection_rules r ON r.rule_id=a.rule_id WHERE a.alert_id=?", (alert_id,))
    if a:
        a["event_ids"] = [r[0] for r in conn.execute(
            "SELECT event_id FROM alert_events WHERE alert_id=? ORDER BY event_id", (alert_id,))]
    return a


def alert_event_map(conn) -> dict[int, list[int]]:
    """event_id -> [alert_id, ...] for every event that has at least one alert."""
    m: dict[int, list[int]] = {}
    for r in conn.execute("SELECT event_id, alert_id FROM alert_events"):
        m.setdefault(r[0], []).append(r[1])
    return m


# --------------------------------------------------------------------------- reset
def purge_all_data(conn) -> None:
    """Delete imported/analytic data. Users, rules and the audit log are kept."""
    for t in ("investigation_notes", "investigation_alerts", "investigation_events", "investigations",
              "ioc_events", "iocs", "alert_events", "alerts", "events"):
        conn.execute(f"DELETE FROM {t}")
