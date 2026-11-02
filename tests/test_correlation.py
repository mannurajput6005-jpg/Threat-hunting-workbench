from correlation.engine import correlate, correlate_from_db
from detection.engine import run_detection
from tests.helpers import ADMIN, ingest, temp_db


def _e(i, sec, host="h1", ip=None):
    return {"event_id": i, "timestamp": f"2024-01-01T00:{sec // 60:02d}:{sec % 60:02d}.000Z", "hostname": host,
            "username": None, "source_ip": ip, "destination_ip": None}


def test_links_by_shared_entity_within_window_only():
    cl = correlate([_e(1, 0), _e(2, 60), _e(3, 5000, host="h1"), _e(4, 10, host="h2")], window_seconds=300)
    assert len(cl) == 1 and cl[0].event_ids == [1, 2]
    assert cl[0].shared_entities["hostname"] == ["h1"]


def test_unrelated_events_not_grouped_and_ignored_values():
    assert correlate([_e(1, 0, "a"), _e(2, 5, "b")], window_seconds=300) == []
    ev = [{**_e(1, 0, None), "username": "SYSTEM"}, {**_e(2, 5, None), "username": "SYSTEM"}]
    assert correlate(ev) == []


def test_attack_chain_on_sample_is_one_cluster_with_techniques():
    with temp_db() as conn:
        ingest(conn, "sysmon_sample.json")
        run_detection(conn, ADMIN)
        clusters = correlate_from_db(conn, window_seconds=300)
        big = max(clusters, key=lambda c: len(c.alert_ids))
        assert big.max_severity == "critical" and "T1059.001" in big.techniques and "T1490" in big.techniques
