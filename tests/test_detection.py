import pytest

from core import database as db
from detection.engine import run_detection
from detection.rule_evaluator import RuleError, compile_condition, compile_rule, evaluate_threshold
from detection.rule_loader import load_rule_files
from tests.helpers import ADMIN, ANALYST, VIEWER, ingest, temp_db


def test_bundled_rules_all_valid():
    rules, errors = load_rule_files()
    assert errors == [] and len(rules) >= 19
    assert len({r["id"] for r in rules}) == len(rules)


def test_operators():
    ev = {"process_name": "PowerShell.exe", "destination_port": 4444, "command_line": None}
    assert compile_condition({"field": "process_name", "op": "equals", "value": "powershell.exe"}).test(ev["process_name"])
    assert compile_condition({"field": "destination_port", "op": "in", "value": [4444]}).test(ev["destination_port"])
    assert compile_condition({"field": "destination_port", "op": "gt", "value": 1000}).test(4444)
    assert not compile_condition({"field": "command_line", "op": "contains", "value": "x"}).test(None)
    assert compile_condition({"field": "command_line", "op": "not_exists"}).test(None)


def test_invalid_rules_rejected():
    for bad in ({"field": "nope", "op": "equals", "value": 1}, {"field": "hostname", "op": "zzz", "value": 1},
                {"field": "hostname", "op": "regex", "value": "("}, {"field": "hostname", "op": "in", "value": "a"}):
        with pytest.raises(RuleError):
            compile_condition(bad)
    with pytest.raises(RuleError):
        compile_rule({"id": "X", "name": "n", "severity": "low", "type": "threshold", "match": [
            {"field": "hostname", "op": "exists"}]})


def _ev(i, sec, ip="1.1.1.1", user="u"):
    return {"event_id": i, "timestamp": f"2024-01-01T00:{sec // 60:02d}:{sec % 60:02d}.000Z", "source_ip": ip, "username": user}


def test_threshold_window_and_distinct():
    th = {"count": 3, "window_seconds": 60, "group_by": ["source_ip"]}
    assert len(evaluate_threshold([_ev(1, 0), _ev(2, 10), _ev(3, 20)], th)) == 1
    assert evaluate_threshold([_ev(1, 0), _ev(2, 100), _ev(3, 200)], th) == []  # spread out
    d = {**th, "distinct_field": "username"}
    assert evaluate_threshold([_ev(1, 0, user="a"), _ev(2, 5, user="a"), _ev(3, 9, user="a")], d) == []
    assert len(evaluate_threshold([_ev(1, 0, user="a"), _ev(2, 5, user="b"), _ev(3, 9, user="c")], d)) == 1
    assert evaluate_threshold([{"event_id": 1, "timestamp": None, "source_ip": "x"}] * 5, th) == []  # no timestamp: skipped


def test_engine_on_samples_creates_evidence_backed_alerts():
    with temp_db() as conn:
        for f in ("sysmon_sample.json", "windows_security_sample.csv", "zeek_conn_sample.log", "suricata_eve_sample.json"):
            ingest(conn, f)
        s = run_detection(conn, ADMIN)
        fired = {r for r, v in s.per_rule.items() if v["created"]}
        assert {"PS-001", "PS-002", "PROC-002", "PROC-004", "AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004",
                "NET-001", "NET-002", "NET-003", "NET-004"} <= fired
        a = db.list_alerts(conn, rule_id="PS-001")[0]
        full = db.get_alert(conn, a["alert_id"])
        assert full["event_ids"] and "matched_conditions" in full["evidence"]
        th = db.get_alert(conn, db.list_alerts(conn, rule_id="AUTH-001")[0]["alert_id"])
        assert len(th["event_ids"]) >= 5
        # re-run is idempotent
        s2 = run_detection(conn, ADMIN)
        assert s2.alerts_created == 0 and s2.alerts_existing == s.alerts_created


def test_benign_activity_does_not_trip_credential_rules():
    with temp_db() as conn:
        ingest(conn, "windows_security_sample.csv")
        run_detection(conn, ADMIN)
        # the two typo failures by 'bob' from 10.0.0.33 must not alert
        n = conn.execute("SELECT COUNT(*) FROM alerts a JOIN alert_events ae ON ae.alert_id=a.alert_id "
                         "JOIN events e ON e.event_id=ae.event_id WHERE e.source_ip='10.0.0.33'").fetchone()[0]
        assert n == 0


def test_permissions_enforced_in_service_layer():
    with temp_db() as conn:
        with pytest.raises(PermissionError):
            run_detection(conn, VIEWER)
        from detection.engine import set_rule_enabled
        with pytest.raises(PermissionError):
            set_rule_enabled(conn, ANALYST, "PS-001", False)
        set_rule_enabled(conn, ADMIN, "PS-001", False)
        assert run_detection(conn, ANALYST).rules_run == 18
