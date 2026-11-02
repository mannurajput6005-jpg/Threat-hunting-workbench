"""Detection engine: evaluates enabled rules over stored events and creates evidence-backed alerts."""
from __future__ import annotations

from dataclasses import dataclass, field

from core import database as db
from core.authentication import authorize
from core.logging_config import get_logger
from detection.rule_evaluator import CompiledRule, evaluate_threshold
from detection.rule_loader import load_enabled_rules

log = get_logger(__name__)

ALERT_STATUSES = ["New", "Reviewed", "Escalated", "False Positive"]
SUMMARY_FIELDS = ("timestamp", "hostname", "username", "source_ip", "destination_ip", "destination_port",
                  "process_name", "command_line", "event_code", "event_category", "outcome", "source_type")


@dataclass
class DetectionSummary:
    rules_run: int = 0
    events_scanned: int = 0
    alerts_created: int = 0
    alerts_existing: int = 0
    per_rule: dict = field(default_factory=dict)


def _summary(ev: dict) -> dict:
    return {k: ev.get(k) for k in SUMMARY_FIELDS if ev.get(k) is not None}


def run_detection(conn, actor: dict | None = None, rule_ids: list[str] | None = None) -> DetectionSummary:
    """Evaluate enabled rules over ALL stored events. Re-running is safe: alerts are de-duplicated."""
    if actor is not None:
        authorize(actor, "detect")
    rules = [r for r in load_enabled_rules(conn) if not rule_ids or r.rule_id in rule_ids]
    summary = DetectionSummary(rules_run=len(rules))
    matched: dict[str, list[dict]] = {r.rule_id: [] for r in rules}
    evidence_by_event: dict[tuple[str, int], list] = {}

    cur = conn.execute("SELECT * FROM events")
    while True:
        batch = cur.fetchmany(5000)
        if not batch:
            break
        for row in batch:
            ev = dict(row)
            summary.events_scanned += 1
            for rule in rules:
                ev_evidence = rule.evaluate(ev)
                if ev_evidence is not None:
                    matched[rule.rule_id].append(ev)
                    evidence_by_event[(rule.rule_id, ev["event_id"])] = ev_evidence

    for rule in rules:
        created = existing = 0
        events = matched[rule.rule_id]
        if rule.type == "match":
            for ev in events:
                aid = db.insert_alert(
                    conn, rule_id=rule.rule_id, severity=rule.severity,
                    description=_describe(rule, ev),
                    evidence={"method": "field_match", "rule": rule.rule_id,
                              "matched_conditions": evidence_by_event[(rule.rule_id, ev["event_id"])],
                              "event": _summary(ev), "mitre": rule.mitre},
                    event_ids=[ev["event_id"]], dedupe_key=f"event:{ev['event_id']}")
                created, existing = (created + 1, existing) if aid else (created, existing + 1)
        else:
            th = rule.threshold
            unit = f"distinct {th['distinct_field']} values" if th.get("distinct_field") else "events"
            for f in evaluate_threshold(events, th):
                win = f["events"]
                aid = db.insert_alert(
                    conn, rule_id=rule.rule_id, severity=rule.severity,
                    description=f"{rule.description} Group {f['group']}: {f['measure']} {unit}"
                                f" within {th['window_seconds']}s (threshold {th['count']}).",
                    evidence={"method": "threshold", "rule": rule.rule_id, "threshold": th,
                              "group": f["group"], "measure": f["measure"],
                              "window_start": win[0]["timestamp"], "window_end": win[-1]["timestamp"],
                              "matched_conditions": [c.describe() for c in rule.all_of + rule.any_of],
                              "event_ids": [e["event_id"] for e in win],
                              "sample_event": _summary(win[0]), "mitre": rule.mitre},
                    event_ids=[e["event_id"] for e in win],
                    dedupe_key=f"{sorted(f['group'].items())}|{win[0]['event_id']}")
                created, existing = (created + 1, existing) if aid else (created, existing + 1)
        summary.alerts_created += created
        summary.alerts_existing += existing
        summary.per_rule[rule.rule_id] = {"created": created, "existing": existing, "matching_events": len(events)}

    db.audit(conn, actor, "run_detection", "alerts", None,
             f"rules={summary.rules_run} scanned={summary.events_scanned} new_alerts={summary.alerts_created}")
    log.info("Detection finished: %s", summary)
    return summary


def _describe(rule: CompiledRule, ev: dict) -> str:
    who = ", ".join(f"{k}={ev[k]}" for k in ("hostname", "username", "source_ip", "process_name") if ev.get(k))
    return f"{rule.description} ({who})" if who else rule.description


def update_alert_status(conn, actor: dict, alert_id: int, status: str) -> None:
    authorize(actor, "detect")
    if status not in ALERT_STATUSES:
        raise ValueError("invalid status")
    conn.execute("UPDATE alerts SET status=? WHERE alert_id=?", (status, alert_id))
    db.audit(conn, actor, "alert_status", "alert", alert_id, status)


def set_rule_enabled(conn, actor: dict, rule_id: str, enabled: bool) -> None:
    authorize(actor, "rules_manage")
    conn.execute("UPDATE detection_rules SET enabled=? WHERE rule_id=?", (1 if enabled else 0, rule_id))
    db.audit(conn, actor, "rule_enable" if enabled else "rule_disable", "rule", rule_id)
