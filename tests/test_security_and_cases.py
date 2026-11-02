import pytest

from core import authentication as auth
from core import database as db
from detection.engine import run_detection
from investigations import case_manager as cm
from investigations import evidence_manager as em
from reporting import report_generator as rg
from evaluation.evaluate import evaluate_file, metrics
from tests.helpers import ADMIN, ANALYST, SAMPLES, VIEWER, ingest, temp_db


def test_password_rules_and_hash():
    for bad in ("short1A", "alllowercase123", "ALLUPPERCASE123", "NoDigitsHereAtAll"):
        with pytest.raises(auth.AuthError):
            auth.validate_password(bad)
    h = auth.hash_password("Correct-Horse-9")
    assert "Correct-Horse-9" not in h and auth.verify_password("Correct-Horse-9", h) and not auth.verify_password("nope", h)


def test_bootstrap_only_once_and_lockout():
    with temp_db() as conn:
        conn.execute("DELETE FROM users")
        auth.create_user(conn, "root", "Correct-Horse-9", "admin", bootstrap=True)
        with pytest.raises(PermissionError):
            auth.create_user(conn, "evil", "Correct-Horse-9", "admin", bootstrap=True)
        for _ in range(5):
            with pytest.raises(auth.AuthError):
                auth.authenticate(conn, "root", "wrong")
        with pytest.raises(auth.AuthError):  # now locked even with the right password
            auth.authenticate(conn, "root", "Correct-Horse-9")


def test_login_success_and_unknown_user_same_error():
    with temp_db() as conn:
        conn.execute("DELETE FROM users")
        auth.create_user(conn, "root", "Correct-Horse-9", "admin", bootstrap=True)
        assert auth.authenticate(conn, "root", "Correct-Horse-9")["role"] == "admin"
        with pytest.raises(auth.AuthError) as e1:
            auth.authenticate(conn, "ghost", "x")
        with pytest.raises(auth.AuthError) as e2:
            auth.authenticate(conn, "root", "x")
        assert str(e1.value) == str(e2.value)  # no user enumeration


def test_viewer_cannot_write_and_admin_functions_gated():
    with temp_db() as conn:
        with pytest.raises(PermissionError):
            cm.create_case(conn, VIEWER, "t")
        with pytest.raises(PermissionError):
            auth.create_user(conn, "x" * 5, "Correct-Horse-9", "viewer", ANALYST)
        with pytest.raises(PermissionError):
            auth.list_users(conn, ANALYST)


def test_sql_injection_strings_are_inert():
    with temp_db() as conn:
        ingest(conn, "windows_security_sample.csv")
        n = db.count_events(conn)
        for evil in ("'; DROP TABLE events; --", "' OR '1'='1", "%", "_"):
            db.search_events(conn, {"hostname": evil, "username": evil, "text": evil})
        assert db.count_events(conn) == n
        assert db.count_events(conn, {"hostname": "%"}) == 0  # wildcard characters are escaped, not interpreted


def test_case_lifecycle_and_report_exports():
    with temp_db() as conn:
        ingest(conn, "sysmon_sample.json")
        run_detection(conn, ADMIN)
        cid = cm.create_case(conn, ANALYST, "Suspicious PowerShell on ws-fin-01", "desc", "high")
        alerts = [a["alert_id"] for a in db.list_alerts(conn) if a["rule_id"].startswith(("PS-", "PROC-"))]
        assert em.link_alerts(conn, ANALYST, cid, alerts) == len(alerts)
        cm.add_note(conn, ANALYST, cid, "Reviewed =cmd|calc")
        cm.update_case(conn, ANALYST, cid, status="In Progress", verdict="True Positive (Confirmed Incident)",
                       conclusion="Confirmed in lab")
        with pytest.raises(ValueError):
            cm.update_case(conn, ANALYST, cid, status="Bogus")
        rep = rg.build_report(conn, cid)
        assert rep["events"] and rep["techniques"] and rep["data_sources"] == ["sysmon"]
        assert rep["time_range"]["start"] and rg.DISCLAIMER in rg.to_markdown(rep).decode()
        assert rg.to_pdf(rep)[:4] == b"%PDF"
        assert b"alert_id" in rg.alerts_csv(rep) and b"event_id" in rg.events_csv(rep)
        assert rg._csv_safe("=1+1") == "'=1+1"
        assert conn.execute("SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'case_%'").fetchone()[0] >= 4


def test_metrics_undefined_not_forced():
    m = metrics(0, 0, 10, 0)
    assert m["precision"] is None and m["recall"] is None and m["f1"] is None
    m = metrics(7, 1, 43, 1)
    assert abs(m["precision"] - 0.875) < 1e-9 and abs(m["recall"] - 0.875) < 1e-9


def test_labeled_evaluation_runs_and_reports_known_limits():
    r = evaluate_file(SAMPLES / "labeled_eval.csv")
    assert r["TP"] + r["FN"] == 7 and r["FN"] >= 1 and r["FP"] >= 1  # deliberate hard cases are visible
