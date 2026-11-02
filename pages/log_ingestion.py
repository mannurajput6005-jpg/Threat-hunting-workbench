import streamlit as st

from core import database as db
from core.authentication import has_permission, require_login
from core.config import ALLOWED_EXTENSIONS, MAX_UPLOAD_MB, SAMPLES_DIR
from core.ui import table
from detection.engine import run_detection
from ingestion.parser import SOURCE_TYPES, IngestionError, parse_file
from threat_intelligence.ioc_matcher import run_ioc_analysis

user = require_login("ingest")
st.title("📥 Log Ingestion")
st.caption(f"Supported: Sysmon, Windows Event (CSV/JSON/XML), Zeek (TSV/JSON), Suricata EVE JSON, generic CSV/JSON. "
           f"Max {MAX_UPLOAD_MB} MB per file. Uploaded files are treated as untrusted data.")


def import_results(results: list, run_analytics: bool) -> None:
    total_in = total_dup = 0
    with db.get_conn() as conn:
        for r in results:
            ins, dup = db.insert_events(conn, r.events)
            total_in += ins
            total_dup += dup
            db.audit(conn, user, "ingest", "file", r.filename,
                     f"records={r.total_records} inserted={ins} duplicates={dup} errors={r.error_count}")
        if run_analytics and total_in:
            s = run_detection(conn, user)
            io = run_ioc_analysis(conn, user)
            st.success(f"Imported {total_in} new events ({total_dup} duplicates skipped). Detection created "
                       f"{s.alerts_created} alerts; IOC analysis created {io['new_alerts']} IOC alerts.")
            return
    st.success(f"Imported {total_in} new events ({total_dup} duplicates skipped).")


tab_up, tab_sample, tab_admin = st.tabs(["Upload files", "Sample data", "Data management"])

with tab_up:
    files = st.file_uploader("Log files", type=[e.lstrip(".") for e in sorted(ALLOWED_EXTENSIONS)],
                             accept_multiple_files=True)
    src = st.selectbox("Source type", SOURCE_TYPES, help="'auto' detects the format of each record.")
    if st.button("Parse files", disabled=not files):
        parsed = []
        for f in files:
            try:
                parsed.append(parse_file(f.getvalue(), f.name, src))
            except IngestionError as exc:
                st.error(f"{f.name}: {exc}")
        st.session_state["parsed"] = parsed
    parsed = st.session_state.get("parsed", [])
    if parsed:
        table([{"file": r.filename, "records": r.total_records, "valid events": len(r.events),
                "invalid records": r.error_count, "sources": ", ".join(f"{k}:{v}" for k, v in r.source_types.items()),
                "truncated": r.truncated} for r in parsed])
        for r in parsed:
            if r.errors:
                with st.expander(f"{r.filename}: {r.error_count} invalid record(s)"):
                    for ref, msg in r.errors[:100]:
                        st.text(f"{ref}: {msg}")
        run_after = st.checkbox("Run detection and IOC analysis after import", value=True)
        n_valid = sum(len(r.events) for r in parsed)
        if st.button(f"Import {n_valid} valid events", type="primary", disabled=n_valid == 0):
            import_results(parsed, run_after)
            st.session_state["parsed"] = []

with tab_sample:
    st.write("Synthetic lab logs (documentation IPs and `.test` domains only) containing a small attack "
             "scenario plus benign background activity.")
    samples = sorted(p for p in SAMPLES_DIR.glob("*") if p.is_file() and p.name != "labeled_eval.csv")
    st.caption(", ".join(p.name for p in samples) or "No sample files found - run scripts/generate_samples.py")
    run_after_s = st.checkbox("Run detection and IOC analysis after import", value=True, key="run_after_sample")
    if st.button("Load all sample logs", disabled=not samples):
        res = []
        for p in samples:
            try:
                res.append(parse_file(p.read_bytes(), p.name, "auto"))
            except IngestionError as exc:
                st.error(f"{p.name}: {exc}")
        import_results(res, run_after_s)

with tab_admin:
    if has_permission(user, "data_purge"):
        st.warning("Deleting imported data also removes alerts, IOCs and investigations. Users, rules and the "
                   "audit log are kept. Retention: data stays in the local SQLite file until deleted here.")
        confirm = st.text_input("Type DELETE to confirm")
        if st.button("Delete all imported data", disabled=confirm != "DELETE"):
            with db.get_conn() as conn:
                db.purge_all_data(conn)
                db.audit(conn, user, "data_purge", "all")
            st.success("All imported data deleted.")
    else:
        st.info("Only administrators can delete data.")
