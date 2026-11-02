import pandas as pd
import plotly.express as px
import streamlit as st

from core import database as db
from core.authentication import require_login
from core.ui import table
from mitre import attack_mapper

user = require_login("read")
st.title("🗺️ MITRE ATT&CK Mapping")
st.warning("Mappings show which ATT&CK techniques each detection rule relates to. They are supported only by the "
           "evidence in the matching events and are NOT proof of attacker activity.")

with db.get_conn() as conn:
    cov = attack_mapper.coverage(conn)
if not cov:
    st.info("No rules with ATT&CK references.")
    st.stop()

df = pd.DataFrame(cov)
fired = df[df["alerts"] > 0]
st.subheader("Techniques with alerts in your data")
if fired.empty:
    st.caption("No alerts reference an ATT&CK technique yet.")
else:
    tac = fired.assign(tactic=fired["tactics"].str.split(", ")).explode("tactic").groupby("tactic")["alerts"].sum().reset_index()
    st.plotly_chart(px.bar(tac, x="tactic", y="alerts"), width="stretch")
    table(fired.to_dict("records"))

st.subheader("Rule coverage")
table(df.sort_values("technique_id").to_dict("records"), height=380)

st.subheader("Technique reference (bundled, offline)")
techs = attack_mapper.load_techniques()
tid = st.selectbox("Technique", sorted(techs), format_func=lambda k: f"{k} - {techs[k]['name']}")
t = attack_mapper.describe(tid)
st.text(f"{t['id']}  {t['name']}\nTactics: {', '.join(t['tactics'])}\n{t['description']}")
st.link_button("Open on attack.mitre.org", t["url"])
