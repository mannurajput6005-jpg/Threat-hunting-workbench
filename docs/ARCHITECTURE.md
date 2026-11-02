# Architecture

Modular monolith: one Streamlit process, responsibilities separated into packages. Pages never contain SQL.

```
Upload -> ingestion.parser (validate, decode, read, detect source, map)
       -> normalization.normalizer (clean, validate, hash, keep raw record)
       -> core.database.insert_events (SQLite, de-duplicated by event_hash)
       -> detection.engine (YAML rules -> alerts + alert_events)      \
       -> threat_intelligence.ioc_matcher (IOCs, watchlist alerts)     } alerts table (rule_id, evidence JSON)
       -> correlation.engine (entity/time-window clusters)            /
       -> investigations.* (cases, notes, linked alerts/events)
       -> reporting.report_generator (PDF / MD / JSON / CSV)
```

## Key decisions

- **Traceability:** every event stores `raw_event`, `source_file`, `record_ref`; every alert stores its matched
  conditions in `evidence` and links all contributing events through `alert_events`.
- **No invented data:** parsers leave unavailable fields `NULL`; threshold rules skip events lacking a timestamp or
  group-by value.
- **Idempotent analytics:** alerts are unique on `(rule_id, dedupe_key)`, so re-running detection never duplicates.
- **Authorization in services:** `core.authentication.authorize(actor, permission)` is called by service functions;
  pages additionally gate controls for usability only.
- **Offline first:** the IOC watchlist and ATT&CK reference ship with the repo; external enrichment is opt-in.
- **Rules as data:** YAML rules are validated and compiled once; regexes are length-limited and evaluated on
  bounded input.

## Database tables

`users, events, detection_rules, alerts, alert_events, ioc_watchlist, iocs, ioc_events, investigations,
investigation_events, investigation_alerts, investigation_notes, audit_logs` (see `core/database.py`).

## Adding a parser

1. Create `ingestion/<name>_parser.py` with a `map_<name>(raw) -> dict` returning normalized field names.
2. Register it in `MAPPERS` and `detect_record_type` in `ingestion/parser.py`.
3. Add a sample under `data/samples/` and a test in `tests/test_ingestion.py`.
