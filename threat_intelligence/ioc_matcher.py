"""Local watchlist loading and exact-match IOC analysis."""
from __future__ import annotations

import csv
import io
from collections import defaultdict
from pathlib import Path

from core import database as db
from core.authentication import authorize
from core.config import WATCHLIST_PATH
from core.logging_config import get_logger
from threat_intelligence.ioc_extractor import extract_from_event, is_internal_ip, normalize_indicator

log = get_logger(__name__)
VALID_TYPES = {"ip", "domain", "url", "hash"}
CONF_TO_SEVERITY = {"high": "high", "medium": "medium", "low": "low"}


def load_watchlist(conn, path: Path | None = None, actor: dict | None = None,
                   content: str | None = None) -> tuple[int, list[str]]:
    """Load indicators from a CSV file (or text) into ioc_watchlist. Returns (loaded, errors)."""
    if actor is not None:
        authorize(actor, "ioc_write")
    errors: list[str] = []
    if content is None:
        p = Path(path or WATCHLIST_PATH)
        if not p.exists():
            return 0, [f"Watchlist file not found: {p}"]
        content = p.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames or not {"indicator_type", "indicator_value"} <= set(reader.fieldnames):
        return 0, ["CSV needs columns: indicator_type, indicator_value (optional: source, confidence, description)"]
    loaded = 0
    for i, row in enumerate(reader, start=2):
        kind = (row.get("indicator_type") or "").strip().lower()
        value = (row.get("indicator_value") or "").strip()
        if kind not in VALID_TYPES or not value:
            errors.append(f"line {i}: invalid type/value")
            continue
        conf = (row.get("confidence") or "").strip().lower() or None
        conn.execute(
            "INSERT INTO ioc_watchlist (indicator_type, indicator_value, source, confidence, description)"
            " VALUES (?,?,?,?,?) ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET"
            " source=excluded.source, confidence=excluded.confidence, description=excluded.description",
            (kind, normalize_indicator(kind, value), (row.get("source") or "").strip() or None, conf,
             (row.get("description") or "").strip() or None))
        loaded += 1
    db.audit(conn, actor, "watchlist_load", "ioc_watchlist", None, f"loaded={loaded} errors={len(errors)}")
    return loaded, errors


def run_ioc_analysis(conn, actor: dict | None = None) -> dict:
    """Extract indicators from all events, store them, and alert on watchlist matches."""
    if actor is not None:
        authorize(actor, "detect")
    watch = {(r["indicator_type"], r["indicator_value"]): r
             for r in db.rows(conn, "SELECT * FROM ioc_watchlist")}
    agg: dict[tuple[str, str], dict] = defaultdict(
        lambda: {"events": {}, "ts": [], "entities": defaultdict(list)})
    scanned = 0
    cur = conn.execute("SELECT event_id, timestamp, hostname, source_ip, destination_ip, domain, url, "
                       "command_line, file_hash FROM events")
    while True:
        batch = cur.fetchmany(5000)
        if not batch:
            break
        for row in batch:
            ev = dict(row)
            scanned += 1
            for kind, value, field in extract_from_event(ev):
                key = (kind, normalize_indicator(kind, value))
                if key not in watch and kind == "ip" and is_internal_ip(value):
                    continue  # internal addresses are not IOC candidates
                a = agg[key]
                a["events"].setdefault(ev["event_id"], field)
                if ev["timestamp"]:
                    a["ts"].append(ev["timestamp"])
                a["entities"][ev["hostname"] or ev["source_ip"] or "unknown"].append(ev["event_id"])

    new_alerts = matches = 0
    for (kind, value), a in agg.items():
        w = watch.get((kind, value))
        conn.execute(
            "INSERT INTO iocs (indicator_type, indicator_value, source, confidence, first_seen, last_seen, observations, watchlist_match)"
            " VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(indicator_type, indicator_value) DO UPDATE SET"
            " source=excluded.source, confidence=excluded.confidence, first_seen=excluded.first_seen,"
            " last_seen=excluded.last_seen, observations=excluded.observations, watchlist_match=excluded.watchlist_match",
            (kind, value, (w or {}).get("source") or "extracted", (w or {}).get("confidence"),
             min(a["ts"]) if a["ts"] else None, max(a["ts"]) if a["ts"] else None,
             len(a["events"]), 1 if w else 0))
        ioc_id = db.scalar(conn, "SELECT ioc_id FROM iocs WHERE indicator_type=? AND indicator_value=?", (kind, value))
        conn.executemany("INSERT OR IGNORE INTO ioc_events (ioc_id, event_id) VALUES (?,?)",
                         [(ioc_id, e) for e in a["events"]])
        if not w:
            continue
        matches += 1
        severity = CONF_TO_SEVERITY.get((w["confidence"] or "").lower(), "medium")
        for entity, event_ids in a["entities"].items():
            event_ids = sorted(set(event_ids))
            dedupe = f"{kind}:{value}:{entity}"
            alert_id = db.insert_alert(
                conn, rule_id="IOC-001", severity=severity,
                description=f"Observed {kind} '{value}' matches the local IOC watchlist "
                            f"({w['source'] or 'unknown source'}, confidence {w['confidence'] or 'n/a'}) on {entity}.",
                evidence={"method": "ioc_match", "indicator_type": kind, "indicator_value": value,
                          "found_in_field": a["events"][event_ids[0]], "watchlist_source": w["source"],
                          "watchlist_confidence": w["confidence"], "watchlist_description": w["description"],
                          "entity": entity, "event_ids": event_ids},
                event_ids=event_ids, dedupe_key=dedupe)
            if alert_id:
                new_alerts += 1
            else:  # alert exists - attach any newly observed events
                existing = db.scalar(conn, "SELECT alert_id FROM alerts WHERE rule_id='IOC-001' AND dedupe_key=?", (dedupe,))
                conn.executemany("INSERT OR IGNORE INTO alert_events (alert_id, event_id) VALUES (?,?)",
                                 [(existing, e) for e in event_ids])
    db.audit(conn, actor, "run_ioc_analysis", "iocs", None,
             f"scanned={scanned} indicators={len(agg)} matches={matches} new_alerts={new_alerts}")
    return {"events_scanned": scanned, "indicators": len(agg), "watchlist_matches": matches, "new_alerts": new_alerts}
