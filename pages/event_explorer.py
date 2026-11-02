import json

import streamlit as st

from core import database as db
from core.authentication import has_permission, require_login
from core.ui import case_picker, day_end, day_start, table
from investigations import evidence_manager as em

user = require_login("read")
st.title("🔎 Event Explorer")

with db.get_conn() as conn:
    cats = db.distinct_values(conn, "event_category")
    srcs = db.distinct_values(conn, "source_type")
    rule_ids = [r["rule_id"] for r in db.rows(conn, "SELECT rule_id FROM detection_rules ORDER BY rule_id")]

with st.expander("Filters", expanded=True):
    a, b, c = st.columns(3)
    f = {
        "hostname": a.text_input("Hostname"), "username": b.text_input("Username"),
        "process_name": c.text_input("Process"),
        "source_ip": a.text_input("Source IP"), "destination_ip": b.text_input("Destination IP"),
        "domain": c.text_input("Domain"),
        "text": a.text_input("Free text (command line / raw event)"),
        "event_category": b.selectbox("Category", [""] + cats), "source_type": c.selectbox("Source", [""] + srcs),
        "rule_id": a.selectbox("Rule that alerted", [""] + rule_ids),
        "severity": b.selectbox("Alert severity", ["", "critical", "high", "medium", "low"]),
        "alerted_only": c.checkbox("Only events with alerts"),
    }
    d1, d2, lim = st.columns(3)
    f["start"], f["end"] = day_start(d1.date_input("From", value=None)), day_end(d2.date_input("To", value=None))
    limit = lim.slider("Max rows", 100, 5000, 1000, step=100)

with db.get_conn() as conn:
    total = db.count_events(conn, f)
    events = db.search_events(conn, f, limit=limit)
    amap = db.alert_event_map(conn)
st.caption(f"{total:,} matching events (showing {len(events):,}). Times are UTC.")
for e in events:
    e["alerts"] = len(amap.get(e["event_id"], []))
selected = table(events, ["event_id", "timestamp", "hostname", "username", "source_ip", "destination_ip",
                          "destination_port", "process_name", "command_line", "event_category", "outcome",
                          "alerts", "source_type"], key="events_tbl", select="multi-row", height=420)

if selected:
    ev = selected[0]
    st.subheader(f"Event #{ev['event_id']}")
    l, r = st.columns(2)
    with l:
        st.caption("Normalized fields")
        st.json({k: v for k, v in ev.items() if v is not None and k not in ("raw_event", "event_hash")})
    with r:
        st.caption(f"Original raw record ({ev['source_file']}, {ev['record_ref']})")
        try:
            st.json(json.loads(ev["raw_event"]))
        except ValueError:
            st.code(ev["raw_event"])
    if has_permission(user, "case_write"):
        st.subheader(f"Add {len(selected)} selected event(s) to a case")
        with db.get_conn() as conn:
            cid = case_picker(conn, user, "ee_case")
            if cid and st.button("Add to case"):
                n = em.link_events(conn, user, cid, [e["event_id"] for e in selected])
                st.success(f"Linked {n} new event(s) to case #{cid}.")
