import streamlit as st

from core import database as db
from core.authentication import has_permission, require_login
from core.config import CORRELATION_WINDOW_SECONDS
from core.ui import table
from correlation.engine import DEFAULT_ENTITIES, correlate_from_db
from correlation.timeline import build_timeline, timeline_figure
from investigations import case_manager as cm
from investigations import evidence_manager as em

user = require_login("read")
st.title("🔗 Event Correlation")
st.caption("Events are grouped when they share an entity (host, user, IP) within the time window. This shows "
           "association for analyst review - it does not prove causation.")

a, b, c, d = st.columns(4)
window = a.number_input("Window (minutes)", 1, 1440, max(1, CORRELATION_WINDOW_SECONDS // 60))
entities = b.multiselect("Shared entities", list(DEFAULT_ENTITIES), default=list(DEFAULT_ENTITIES))
alerted_only = c.checkbox("Only events that raised alerts", value=True)
min_events = d.number_input("Min events per group", 2, 50, 2)

if not entities:
    st.warning("Pick at least one entity field.")
    st.stop()

with db.get_conn() as conn:
    clusters = correlate_from_db(conn, int(window) * 60, tuple(entities), alerted_only, int(min_events))
    amap = db.alert_event_map(conn)
    asev = {r["alert_id"]: r["severity"] for r in db.rows(conn, "SELECT alert_id, severity FROM alerts")}

st.write(f"**{len(clusters)}** candidate activity sequence(s)")
for cl in clusters[:50]:
    label = f"[{cl.max_severity or 'no alert'}] {cl.start} -> {cl.end} | {len(cl.event_ids)} events | {len(cl.alert_ids)} alerts"
    with st.expander(label):
        st.text(cl.summary)
        if cl.rule_ids:
            st.text("Rules: " + ", ".join(cl.rule_ids))
        if cl.techniques:
            st.text("ATT&CK references: " + ", ".join(cl.techniques))
        df = build_timeline(cl.events, amap, asev)
        fig = timeline_figure(df)
        if fig is not None:
            st.plotly_chart(fig, width="stretch", key=f"fig_{cl.cluster_id}")
        table(df.to_dict("records"), height=240)
        if has_permission(user, "case_write") and st.button("Create case from this sequence", key=f"mk_{cl.cluster_id}"):
            with db.get_conn() as conn:
                cid = cm.create_case(conn, user, f"Correlated activity {cl.start}", cl.summary, cl.max_severity or "medium")
                em.link_alerts(conn, user, cid, cl.alert_ids)
                em.link_events(conn, user, cid, cl.event_ids)
            st.success(f"Created case #{cid}. Open the Investigations page.")
