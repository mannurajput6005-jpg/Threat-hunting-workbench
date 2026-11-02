"""Associate alerts / events with a case and collect the evidence for reporting."""
from __future__ import annotations

from core import database as db
from core.authentication import authorize
from investigations.case_manager import _touch, get_case, get_notes
from mitre.attack_mapper import techniques_for_rule_ids


def link_alerts(conn, actor: dict, case_id: int, alert_ids: list[int], include_events: bool = True) -> int:
    """Link alerts (and, by default, their contributing events) to a case. Returns #alerts newly linked."""
    authorize(actor, "case_write")
    if not get_case(conn, case_id):
        raise ValueError("Case not found.")
    added = 0
    for aid in alert_ids:
        if not db.one(conn, "SELECT 1 FROM alerts WHERE alert_id=?", (aid,)):
            continue
        added += conn.execute("INSERT OR IGNORE INTO investigation_alerts VALUES (?,?)", (case_id, aid)).rowcount
        if include_events:
            conn.execute("INSERT OR IGNORE INTO investigation_events SELECT ?, event_id FROM alert_events WHERE alert_id=?",
                         (case_id, aid))
    _touch(conn, case_id)
    db.audit(conn, actor, "case_link_alerts", "investigation", case_id, f"alerts={alert_ids[:20]}")
    return added


def link_events(conn, actor: dict, case_id: int, event_ids: list[int]) -> int:
    authorize(actor, "case_write")
    if not get_case(conn, case_id):
        raise ValueError("Case not found.")
    added = 0
    for eid in event_ids:
        if db.one(conn, "SELECT 1 FROM events WHERE event_id=?", (eid,)):
            added += conn.execute("INSERT OR IGNORE INTO investigation_events VALUES (?,?)", (case_id, eid)).rowcount
    _touch(conn, case_id)
    db.audit(conn, actor, "case_link_events", "investigation", case_id, f"count={len(event_ids)}")
    return added


def unlink_alert(conn, actor: dict, case_id: int, alert_id: int) -> None:
    authorize(actor, "case_write")
    conn.execute("DELETE FROM investigation_alerts WHERE investigation_id=? AND alert_id=?", (case_id, alert_id))
    db.audit(conn, actor, "case_unlink_alert", "investigation", case_id, str(alert_id))


def collect_evidence(conn, case_id: int) -> dict:
    """Everything a report needs, as plain data."""
    case = get_case(conn, case_id)
    if not case:
        raise ValueError("Case not found.")
    alerts = db.rows(conn, "SELECT a.*, r.rule_name, r.mitre_technique_id FROM alerts a "
                           "JOIN investigation_alerts ia ON ia.alert_id=a.alert_id "
                           "JOIN detection_rules r ON r.rule_id=a.rule_id WHERE ia.investigation_id=? "
                           "ORDER BY a.created_at", (case_id,))
    event_ids = [r[0] for r in conn.execute("SELECT event_id FROM investigation_events WHERE investigation_id=?", (case_id,))]
    events = db.get_events_by_ids(conn, event_ids)
    iocs = db.rows(conn, "SELECT DISTINCT i.* FROM iocs i JOIN ioc_events ie ON ie.ioc_id=i.ioc_id "
                         "JOIN investigation_events ev ON ev.event_id=ie.event_id WHERE ev.investigation_id=? "
                         "ORDER BY i.watchlist_match DESC, i.indicator_type", (case_id,))
    techniques: dict[str, dict] = {}
    for a in alerts:
        for t in techniques_for_rule_ids(a["mitre_technique_id"]):
            techniques[t["id"]] = t
    stamps = [e["timestamp"] for e in events if e.get("timestamp")]
    return {
        "case": case, "alerts": alerts, "events": events, "iocs": iocs,
        "techniques": list(techniques.values()), "notes": get_notes(conn, case_id),
        "time_range": {"start": min(stamps) if stamps else None, "end": max(stamps) if stamps else None},
        "data_sources": sorted({e["source_type"] for e in events}),
        "source_files": sorted({e["source_file"] for e in events if e.get("source_file")}),
    }
