"""Detection evaluation against a LABELED dataset.

The labeled CSV has a ``label`` column (malicious/benign). That column is not mapped into the normalized
schema, so rules never see it. Event-level scoring:
  TP = malicious event covered by >= 1 alert   FN = malicious event with no alert
  FP = benign event covered by >= 1 alert      TN = benign event with no alert
precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2PR/(P+R). A zero denominator is reported as None
(undefined) - never forced to 0 or 1.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core import database as db
from detection.engine import run_detection
from detection.rule_loader import sync_rules
from ingestion.parser import parse_file
from threat_intelligence.ioc_matcher import load_watchlist, run_ioc_analysis


def _ratio(n: int, d: int):
    return None if d == 0 else n / d


def metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = None if p is None or r is None or (p + r) == 0 else 2 * p * r / (p + r)
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn, "precision": p, "recall": r, "f1": f1,
            "accuracy": _ratio(tp + tn, tp + fp + tn + fn)}


def evaluate_file(labeled_csv: Path, use_ioc: bool = True) -> dict:
    """Ingest the labeled file into a throw-away database, run detection and score it."""
    labeled_csv = Path(labeled_csv)
    with tempfile.TemporaryDirectory() as tmp:
        dbp = Path(tmp) / "eval.db"
        db.init_db(dbp)
        with db.get_conn(dbp) as conn:
            sync_rules(conn)
            res = parse_file(labeled_csv.read_bytes(), labeled_csv.name, "auto")
            db.insert_events(conn, res.events)
            run_detection(conn)
            if use_ioc:
                load_watchlist(conn)
                run_ioc_analysis(conn)
            alerted = set(db.alert_event_map(conn))
            tp = fp = tn = fn = 0
            per_rule: dict[str, dict] = {}
            misses, false_alarms = [], []
            for e in db.rows(conn, "SELECT event_id, raw_event, command_line, event_category FROM events"):
                label = (json.loads(e["raw_event"]).get("label") or "").strip().lower()
                if label not in ("malicious", "benign"):
                    continue
                hit = e["event_id"] in alerted
                if label == "malicious":
                    tp, fn = (tp + 1, fn) if hit else (tp, fn + 1)
                    if not hit:
                        misses.append(e["event_id"])
                else:
                    fp, tn = (fp + 1, tn) if hit else (fp, tn + 1)
                    if hit:
                        false_alarms.append(e["event_id"])
            for r in db.rows(conn, "SELECT a.rule_id, COUNT(DISTINCT ae.event_id) n FROM alerts a "
                                   "JOIN alert_events ae ON ae.alert_id=a.alert_id GROUP BY a.rule_id"):
                per_rule[r["rule_id"]] = {"events_covered": r["n"]}
    out = metrics(tp, fp, tn, fn)
    out.update({"dataset": labeled_csv.name, "records": res.total_records, "parse_errors": res.error_count,
                "missed_event_ids": misses[:50], "false_alarm_event_ids": false_alarms[:50], "per_rule": per_rule})
    return out
