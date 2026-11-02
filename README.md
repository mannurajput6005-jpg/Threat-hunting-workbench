# 🛡️ Threat Hunting Workbench

A standalone cybersecurity investigation platform for proactive security-log analysis. Import endpoint and
network telemetry, normalize it into one schema, run transparent rule-based detections, extract and match IOCs,
correlate related activity, reference MITRE ATT&CK, and document findings in cases with exportable reports.

Built with **Python**, **Streamlit** and **SQLite** as a modular monolith. No SIEM or EDR is required, and the
app works fully offline. It is an educational / lab investigation aid, **not** a replacement for an enterprise
SIEM, EDR or incident-response team.

> An alert is an investigative lead, not proof of compromise. Every alert in the UI shows the rule, the matched
> evidence and the source events so an analyst can verify it.

## Features

| Area | What it does |
|---|---|
| Ingestion | CSV/TSV, JSON/JSONL, Sysmon, Windows Event (CSV/JSON/XML), Zeek (TSV/JSON), Suricata EVE JSON; auto-detection per record; size/extension/encoding checks; invalid records reported, not fatal |
| Normalization | One event schema; unavailable fields stay `NULL`; raw record kept with every event; UTC timestamps; duplicate re-imports skipped |
| Detection | YAML rules (field match, regex, thresholds, time windows, distinct counts); 19 rules shipped (auth, PowerShell, process, network) |
| IOC analysis | Extracts IPs, domains, URLs, hashes; exact match against a local watchlist CSV; optional VirusTotal enrichment (off by default) |
| Correlation | Entity + time-window grouping with timeline view; association only, never causation |
| MITRE ATT&CK | Local technique reference, rule-to-technique coverage view |
| Investigations | Cases, notes, status/verdict, linked alerts/events, automatic history notes |
| Reports | PDF, Markdown, JSON, CSV exports with time range and data sources |
| Security | bcrypt passwords, roles enforced in service functions, login lockout, session timeout, audit log, parameterized SQL, XXE-safe XML parsing, escaped rendering |
| Evaluation | Labeled-dataset scoring (TP/FP/TN/FN, precision, recall, F1; undefined ratios reported as undefined) |

## Quick start

Requires Python 3.10+.

```bash
git clone <your-repo-url> threat-hunting-workbench
cd threat-hunting-workbench
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

1. Open the URL Streamlit prints (usually http://localhost:8501).
2. **First run:** create the administrator account (the form only appears while no user exists).
3. Go to **Log Ingestion → Sample data → Load all sample logs**. This imports synthetic logs, runs detection and
   IOC analysis, and gives you a small attack scenario to explore.
4. Explore **Threat Detection → Alerts**, **Correlation**, **IOC Analysis**, then open an **Investigation**, link
   alerts to it, and generate a **Report**.

To regenerate the sample logs: `python scripts/generate_samples.py`.

## Roles

| Role | Can do |
|---|---|
| viewer | Read dashboards, events, alerts, cases, reports |
| analyst | + ingest logs, run detection/IOC analysis, manage cases, load watchlists |
| admin | + enable/disable rules, manage users, delete data, read audit log |

Permissions are checked in the service layer (`core/authentication.authorize`), not just by hiding buttons.

## Writing a detection rule

Rules live in `rules/*.yaml` and refer to the normalized fields (see `core/database.EVENT_COLUMNS`).

```yaml
rules:
  - id: AUTH-001
    name: Repeated failed logins from one source
    description: Several failed authentications from the same source IP within a short window.
    severity: medium            # low | medium | high | critical
    type: threshold             # match | threshold
    mitre: [T1110]
    match:                      # all must hold
      - {field: event_category, op: equals, value: authentication}
      - {field: outcome, op: equals, value: failure}
    threshold: {count: 5, window_seconds: 300, group_by: [source_ip]}   # optional: distinct_field
    caution: May be caused by mistyped passwords or service accounts.
```

Operators: `equals not_equals in not_in contains contains_any startswith endswith regex exists not_exists gt gte lt lte`.
`match_any` holds conditions where at least one must hold. Rules are validated on load; a bad rule is reported
and skipped without blocking the others. Use **Threat Detection → Rules → Reload rules** after editing.

## Optional external enrichment

Disabled by default. To enable VirusTotal lookups, set in `.env`:

```
THW_ENABLE_EXTERNAL_ENRICHMENT=true
VIRUSTOTAL_API_KEY=your-key
```

Only the indicator value is sent, never raw logs, hostnames or usernames.

## Configuration

All settings are environment variables (or `.env`); see `.env.example`.

## Tests and evaluation

```bash
pip install -r requirements-dev.txt
pytest -q                              # unit + integration + security tests
python scripts/evaluate_detection.py   # TP/FP/TN/FN, precision, recall, F1 on data/samples/labeled_eval.csv
```

The labeled evaluation set is small, synthetic and contains deliberate false-positive and false-negative
cases. Treat its numbers as a demonstration of the method, not as a claim about real-world detection quality.
Record your own results (dataset, labels, conditions) if you cite them.

## Project structure

```
app.py                  entry point, login, navigation
pages/                  Streamlit pages (dashboard, ingestion, explorer, detection, correlation, IOC, ATT&CK, cases, reports, admin)
core/                   config, database (all SQL), authentication/authorization, logging, UI helpers
ingestion/              file validation + source parsers (csv, json, sysmon/windows, zeek, suricata)
normalization/          common event schema and helpers
detection/              rule loader, evaluator, engine, severity
correlation/            entity/time-window engine, timeline
threat_intelligence/    IOC extractor, matcher, optional enrichment
mitre/                  ATT&CK mapper + local techniques.json
investigations/         case and evidence management
reporting/              PDF / Markdown / JSON / CSV report generation
evaluation/             labeled-dataset scoring
rules/                  YAML detection rules
data/samples/           synthetic sample logs; data/threat_intelligence/ioc_watchlist.csv
tests/                  pytest suite
docs/                   architecture notes
```

## Security notes

- Uploaded logs are untrusted: extension/size/encoding validated, record cap, XML parsed with `defusedxml`.
- Log-derived text is rendered with `st.text/st.json/st.dataframe`, never as markdown/HTML. CSV exports neutralise formula injection.
- All SQL is parameterized; dynamic fragments come only from fixed allow-lists.
- Passwords are hashed with bcrypt (12 rounds); accounts lock after repeated failures; sessions time out.
- Streamlit has no built-in TLS. For anything beyond a local lab, put it behind a reverse proxy that terminates HTTPS.
- Data retention: imported data stays in the local SQLite file (`data/workbench.db`) until an administrator deletes it from **Log Ingestion → Data management**.

## Limitations

- Detection depends on the telemetry in the imported logs; rule-based logic misses behaviour no rule describes.
- Timestamps without a time zone are assumed UTC.
- IOC lists can be stale or wrong; correlation shows association, not causation.
- SQLite suits a single-user lab, not high-volume or heavily concurrent use (PostgreSQL would be the next step).
- File-based ingestion only; there is no real-time collection.

## Roadmap ideas

ML anomaly detection against labeled baselines · live log streaming · attack-path graphs · Sigma rule import ·
more threat-intel feeds · PostgreSQL backend.

## License

MIT (see `LICENSE`). Replace the copyright holder with your own name if you prefer.
