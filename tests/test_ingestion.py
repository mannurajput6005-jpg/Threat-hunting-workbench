import json

import pytest

from ingestion.parser import IngestionError, parse_file
from normalization.normalizer import parse_timestamp
from tests.helpers import ingest, temp_db


def test_csv_generic_mapping_and_nulls():
    csv = b"time,host,user,src_ip,dest_ip,dest_port\n2024-01-01T10:00:00Z,HOST1,CORP\\jdoe,10.0.0.1,198.51.100.5,443\n"
    res = parse_file(csv, "x.csv")
    e = res.events[0]
    assert e["hostname"] == "host1" and e["username"] == "jdoe" and e["destination_port"] == 443
    assert e["timestamp"] == "2024-01-01T10:00:00.000Z"
    assert e["process_name"] is None  # unavailable fields stay null, nothing invented


def test_json_array_object_and_jsonl():
    assert len(parse_file(b'[{"hostname":"a"},{"hostname":"b"}]', "x.json").events) == 2
    assert len(parse_file(b'{"events":[{"hostname":"a"}]}', "x.json").events) == 1
    assert len(parse_file(b'{"hostname":"a"}\n{"hostname":"b"}\n', "x.jsonl").events) == 2


def test_malformed_records_are_reported_not_fatal():
    res = parse_file(b'{"hostname":"a"}\nnot json\n[1,2]\n', "x.jsonl")
    assert len(res.events) == 1 and res.error_count == 2


def test_rejects_bad_extension_empty_and_undecodable():
    with pytest.raises(IngestionError):
        parse_file(b"x", "evil.exe")
    with pytest.raises(IngestionError):
        parse_file(b"", "x.csv")
    with pytest.raises(IngestionError):
        parse_file(b"\x80\x81\x82", "x.csv")


def test_timestamp_variants():
    assert parse_timestamp(1710406800) == "2024-03-14T09:00:00.000Z"
    assert parse_timestamp("1710406800.5").startswith("2024-03-14T09:00:00.5")
    assert parse_timestamp("2024-03-14 09:00:00") == "2024-03-14T09:00:00.000Z"  # assumed UTC
    assert parse_timestamp("garbage") is None


def test_sysmon_sample_detected_and_mapped():
    with temp_db() as conn:
        res = ingest(conn, "sysmon_sample.json")
        assert res.error_count == 0 and res.source_types["sysmon"] == res.total_records
        row = conn.execute("SELECT * FROM events WHERE command_line LIKE '%-enc%'").fetchone()
        assert row["process_name"] == "powershell.exe" and row["parent_process"] == "cmd.exe"
        assert row["username"] == "alice" and row["event_category"] == "process_creation"


def test_windows_csv_zeek_and_suricata_samples():
    with temp_db() as conn:
        w = ingest(conn, "windows_security_sample.csv")
        assert w.source_types["windows_event"] == w.total_records
        z = ingest(conn, "zeek_conn_sample.log")
        assert z.source_types["zeek"] == z.total_records and z.error_count == 0
        s = ingest(conn, "suricata_eve_sample.json")
        assert s.source_types["suricata"] == s.total_records
        r = conn.execute("SELECT * FROM events WHERE source_type='zeek' LIMIT 1").fetchone()
        assert r["timestamp"].startswith("2024-03-14") and r["destination_port"] is not None


def test_windows_xml_and_xxe_is_blocked():
    xml = (b'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID>'
           b'<TimeCreated SystemTime="2024-03-14T09:00:00.000Z"/><Computer>DC1</Computer></System>'
           b'<EventData><Data Name="TargetUserName">bob</Data><Data Name="IpAddress">203.0.113.50</Data></EventData></Event>')
    res = parse_file(xml, "sec.xml")
    e = res.events[0]
    assert e["outcome"] == "failure" and e["username"] == "bob" and e["source_ip"] == "203.0.113.50"
    evil = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><Event><System><EventID>1</EventID></System><EventData><Data Name="X">&a;</Data></EventData></Event>'
    res = parse_file(evil, "evil.xml")
    assert not res.events and res.error_count >= 1


def test_reimport_is_deduplicated():
    with temp_db() as conn:
        from core import database as db
        r = ingest(conn, "windows_security_sample.csv")
        before = db.count_events(conn)
        again = parse_file((__import__("pathlib").Path("data/samples/windows_security_sample.csv")).read_bytes(), "renamed.csv")
        ins, dup = db.insert_events(conn, again.events)
        assert ins == 0 and dup == len(again.events) and db.count_events(conn) == before
