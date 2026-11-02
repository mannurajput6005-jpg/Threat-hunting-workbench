import streamlit as st

from core import database as db
from core.authentication import has_permission, require_login
from core.ui import table
from detection.severity import SEVERITIES
from investigations import case_manager as cm
from investigations import evidence_manager as em

user = require_login("read")
st.title("📁 Investigations")
can_write = has_permission(user, "case_write")

if can_write:
    with st.expander("➕ New investigation"):
        with st.form("new_case", clear_on_submit=True):
            title = st.text_input("Title")
            desc = st.text_area("Description")
            sev = st.selectbox("Severity", SEVERITIES, index=1)
            if st.form_submit_button("Create"):
                try:
                    with db.get_conn() as conn:
                        cid = cm.create_case(conn, user, title, desc, sev)
                    st.session_state["open_case"] = cid
                    st.success(f"Created case #{cid}.")
                except ValueError as exc:
                    st.error(str(exc))

flt = st.selectbox("Filter by status", [""] + cm.STATUSES)
with db.get_conn() as conn:
    cases = cm.list_cases(conn, user, flt or None)
sel = table(cases, ["investigation_id", "title", "severity", "status", "verdict", "alerts", "events", "created_by_name",
                    "updated_at"], key="cases_tbl", select="single-row", height=260)
case_id = sel[0]["investigation_id"] if sel else st.session_state.get("open_case")
if not case_id:
    st.stop()

with db.get_conn() as conn:
    case = cm.get_case(conn, case_id)
    if not case:
        st.stop()
    ev = em.collect_evidence(conn, case_id)
    open_alerts = db.list_alerts(conn, limit=300)

st.divider()
st.subheader(f"Case #{case['investigation_id']}: {case['title']}")
st.text(case["description"] or "(no description)")
tr = ev["time_range"]
st.caption(f"Linked events {tr['start'] or 'n/a'} -> {tr['end'] or 'n/a'} | sources: {', '.join(ev['data_sources']) or 'n/a'}")

if can_write:
    c1, c2, c3 = st.columns(3)
    status = c1.selectbox("Status", cm.STATUSES, index=cm.STATUSES.index(case["status"]))
    severity = c2.selectbox("Severity", SEVERITIES, index=SEVERITIES.index(case["severity"]))
    verdict = c3.selectbox("Verdict", cm.VERDICTS, index=cm.VERDICTS.index(case["verdict"]))
    conclusion = st.text_area("Conclusion", value=case["conclusion"] or "")
    if st.button("Save changes", type="primary"):
        with db.get_conn() as conn:
            cm.update_case(conn, user, case_id, status=status, severity=severity, verdict=verdict, conclusion=conclusion)
        st.success("Saved.")
        st.rerun()
else:
    st.text(f"Status: {case['status']} | Severity: {case['severity']} | Verdict: {case['verdict']}")
    st.text(f"Conclusion: {case['conclusion'] or '(none)'}")

t_alerts, t_events, t_ioc, t_notes = st.tabs(
    [f"Alerts ({len(ev['alerts'])})", f"Events ({len(ev['events'])})", f"IOCs ({len(ev['iocs'])})", "Notes"])
with t_alerts:
    table(ev["alerts"], ["alert_id", "severity", "rule_id", "rule_name", "status", "description"])
    if can_write:
        linked = {a["alert_id"] for a in ev["alerts"]}
        labels = {a["alert_id"]: f"#{a['alert_id']} [{a['severity']}] {a['rule_id']} {a['description'][:70]}"
                  for a in open_alerts if a["alert_id"] not in linked}
        picks = st.multiselect("Link alerts (their events are linked too)", list(labels), format_func=labels.get)
        if st.button("Link selected alerts", disabled=not picks):
            with db.get_conn() as conn:
                em.link_alerts(conn, user, case_id, picks)
            st.rerun()
        if ev["alerts"]:
            rm = st.selectbox("Unlink alert", [a["alert_id"] for a in ev["alerts"]])
            if st.button("Unlink"):
                with db.get_conn() as conn:
                    em.unlink_alert(conn, user, case_id, rm)
                st.rerun()
with t_events:
    table(ev["events"], ["event_id", "timestamp", "hostname", "username", "source_ip", "destination_ip", "process_name",
                         "command_line", "event_category", "source_type"], height=380)
with t_ioc:
    table(ev["iocs"], ["indicator_type", "indicator_value", "watchlist_match", "confidence", "observations"])
with t_notes:
    for n in ev["notes"]:
        st.text(f"{n['created_at']}  {n['username'] or 'system'}{' (auto)' if n['is_system'] else ''}: {n['note']}")
    if can_write:
        note = st.text_area("Add note", key="note_text")
        if st.button("Add note"):
            try:
                with db.get_conn() as conn:
                    cm.add_note(conn, user, case_id, note)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
