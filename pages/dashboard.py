import pandas as pd
import plotly.express as px
import streamlit as st

from core import database as db
from core.authentication import require_login
from core.ui import SEV_COLORS, SEV_ORDER, table

user = require_login("read")
st.title("📊 Security Dashboard")
st.caption("Events, alerts and confirmed incidents are different things: an alert is a lead to investigate, "
           "not proof of compromise.")

with db.get_conn() as conn:
    n_events = db.scalar(conn, "SELECT COUNT(*) FROM events") or 0
    n_alerts = db.scalar(conn, "SELECT COUNT(*) FROM alerts") or 0
    open_alerts = db.scalar(conn, "SELECT COUNT(*) FROM alerts WHERE status IN ('New','Escalated')") or 0
    n_cases = db.scalar(conn, "SELECT COUNT(*) FROM investigations") or 0
    confirmed = db.scalar(conn, "SELECT COUNT(*) FROM investigations WHERE verdict LIKE 'True Positive%'") or 0
    sev = db.rows(conn, "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")
    src = db.rows(conn, "SELECT source_type, COUNT(*) AS n FROM events GROUP BY source_type ORDER BY n DESC")
    per_hour = db.rows(conn, "SELECT substr(timestamp,1,13) AS hour, COUNT(*) AS n FROM events "
                             "WHERE timestamp IS NOT NULL GROUP BY hour ORDER BY hour")
    recent = db.list_alerts(conn, limit=10)
    cases = db.rows(conn, "SELECT investigation_id, title, severity, status, verdict, updated_at FROM investigations "
                          "ORDER BY updated_at DESC LIMIT 8")

c = st.columns(5)
c[0].metric("Events ingested", f"{n_events:,}")
c[1].metric("Alerts (total)", f"{n_alerts:,}")
c[2].metric("Alerts needing review", f"{open_alerts:,}")
c[3].metric("Investigations", f"{n_cases:,}")
c[4].metric("Confirmed incidents", f"{confirmed:,}", help="Cases whose analyst verdict is True Positive.")

if n_events == 0:
    st.info("No data yet. Open **Log Ingestion** and import your own logs or the bundled sample logs.")
    st.stop()

left, right = st.columns(2)
with left:
    st.subheader("Alerts by severity")
    if sev:
        df = pd.DataFrame(sev)
        fig = px.bar(df, x="severity", y="n", color="severity", color_discrete_map=SEV_COLORS,
                     category_orders={"severity": SEV_ORDER}, labels={"n": "alerts"})
        fig.update_layout(showlegend=False, margin={"t": 10, "b": 10})
        st.plotly_chart(fig, width="stretch")
    else:
        st.caption("No alerts yet - run detection on the Threat Detection page.")
with right:
    st.subheader("Events by source")
    fig = px.pie(pd.DataFrame(src), names="source_type", values="n", hole=0.45)
    fig.update_layout(margin={"t": 10, "b": 10})
    st.plotly_chart(fig, width="stretch")

st.subheader("Event activity over time (UTC, per hour)")
if per_hour:
    fig = px.bar(pd.DataFrame(per_hour), x="hour", y="n", labels={"n": "events"})
    fig.update_layout(margin={"t": 10, "b": 10})
    st.plotly_chart(fig, width="stretch")

l2, r2 = st.columns(2)
with l2:
    st.subheader("Recent alerts")
    table(recent, ["alert_id", "created_at", "severity", "rule_id", "rule_name", "status"])
with r2:
    st.subheader("Recent investigations")
    table(cases, ["investigation_id", "title", "severity", "status", "verdict"])
