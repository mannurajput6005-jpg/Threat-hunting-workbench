import json

import streamlit as st

from core import database as db
from core.authentication import has_permission, require_login
from core.ui import case_picker, table
from detection import engine
from detection.rule_loader import sync_rules
from mitre.attack_mapper import techniques_for_rule_ids
from investigations import evidence_manager as em

user = require_login("read")
st.title("🚨 Threat Detection")
st.caption("An alert is an investigative lead, not proof of compromise. Open an alert to see exactly why the rule matched.")

tab_alerts, tab_run, tab_rules = st.tabs(["Alerts", "Run detection", "Rules"])

with tab_alerts:
    with db.get_conn() as conn:
        rule_ids = [r["rule_id"] for r in db.rows(conn, "SELECT DISTINCT rule_id FROM alerts ORDER BY rule_id")]
    a, b, c = st.columns(3)
    sev = a.selectbox("Severity", ["", "critical", "high", "medium", "low"])
    status = b.selectbox("Status", [""] + engine.ALERT_STATUSES)
    rid = c.selectbox("Rule", [""] + rule_ids)
    with db.get_conn() as conn:
        alerts = db.list_alerts(conn, sev or None, status or None, rid or None)
    st.caption(f"{len(alerts)} alert(s). Select a row for details.")
    sel = table(alerts, ["alert_id", "created_at", "severity", "rule_id", "rule_name", "status", "event_count",
                         "description"], key="alerts_tbl", select="single-row", height=360)
    if sel:
        with db.get_conn() as conn:
            al = db.get_alert(conn, sel[0]["alert_id"])
            events = db.get_events_by_ids(conn, al["event_ids"][:200])
            logic = json.loads(al["rule_logic"])
        st.subheader(f"Alert #{al['alert_id']} - {al['rule_name']} [{al['severity']}]")
        st.text(al["description"])
        if logic.get("caution"):
            st.warning(f"Analyst caution: {logic['caution']}")
        for t in techniques_for_rule_ids(al["mitre_technique_id"]):
            st.text(f"ATT&CK reference: {t['id']} {t['name']} ({', '.join(t['tactics'])}) - supports review, not proof")
        st.caption("Evidence (why this alert fired)")
        try:
            st.json(json.loads(al["evidence"]))
        except (TypeError, ValueError):
            st.code(al["evidence"] or "")
        st.caption(f"Contributing events ({len(al['event_ids'])})")
        table(events, ["event_id", "timestamp", "hostname", "username", "source_ip", "destination_ip",
                       "process_name", "command_line", "event_category", "outcome"], height=250)
        if has_permission(user, "detect"):
            s1, s2 = st.columns(2)
            new_status = s1.selectbox("Set status", engine.ALERT_STATUSES, index=engine.ALERT_STATUSES.index(al["status"]))
            if s1.button("Update status"):
                with db.get_conn() as conn:
                    engine.update_alert_status(conn, user, al["alert_id"], new_status)
                st.rerun()
        if has_permission(user, "case_write"):
            with db.get_conn() as conn:
                cid = case_picker(conn, user, "td_case")
                if cid and st.button("Add alert (and its events) to case"):
                    em.link_alerts(conn, user, cid, [al["alert_id"]])
                    st.success(f"Linked to case #{cid}.")

with tab_run:
    if not has_permission(user, "detect"):
        st.info("Your role cannot run detection.")
    else:
        st.write("Evaluates every enabled rule over all stored events. Re-running is safe: existing alerts are not duplicated.")
        if st.button("Run detection now", type="primary"):
            with db.get_conn() as conn:
                s = engine.run_detection(conn, user)
            st.success(f"Scanned {s.events_scanned:,} events with {s.rules_run} rules: "
                       f"{s.alerts_created} new alert(s), {s.alerts_existing} already existed.")
            table([{"rule_id": k, **v} for k, v in s.per_rule.items()])

with tab_rules:
    with db.get_conn() as conn:
        rules = db.rows(conn, "SELECT rule_id, rule_name, severity, mitre_technique_id, enabled, source_file, description "
                              "FROM detection_rules ORDER BY rule_id")
    sel = table(rules, key="rules_tbl", select="single-row", height=380)
    if sel:
        with db.get_conn() as conn:
            logic = db.scalar(conn, "SELECT rule_logic FROM detection_rules WHERE rule_id=?", (sel[0]["rule_id"],))
        st.json(json.loads(logic))
    if has_permission(user, "rules_manage"):
        c1, c2 = st.columns(2)
        if sel:
            enabled = bool(sel[0]["enabled"])
            if c1.button("Disable rule" if enabled else "Enable rule"):
                with db.get_conn() as conn:
                    engine.set_rule_enabled(conn, user, sel[0]["rule_id"], not enabled)
                st.rerun()
        if c2.button("Reload rules from YAML files"):
            with db.get_conn() as conn:
                n, errors = sync_rules(conn)
            st.success(f"Loaded {n} rules.")
            for e in errors:
                st.error(e)
    else:
        st.caption("Only administrators can enable/disable rules.")
