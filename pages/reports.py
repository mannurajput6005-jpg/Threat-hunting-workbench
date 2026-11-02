import streamlit as st

from core import database as db
from core.authentication import require_login
from core.config import SAMPLES_DIR
from core.ui import table
from evaluation.evaluate import evaluate_file
from investigations import case_manager as cm
from reporting import report_generator as rg

user = require_login("read")
st.title("📄 Reports")
tab_rep, tab_eval = st.tabs(["Investigation report", "Detection evaluation"])

with tab_rep:
    with db.get_conn() as conn:
        cases = cm.list_cases(conn, user)
    if not cases:
        st.info("Create an investigation first.")
    else:
        labels = {c["investigation_id"]: f"#{c['investigation_id']} {c['title']} [{c['status']}]" for c in cases}
        cid = st.selectbox("Investigation", list(labels), format_func=labels.get)
        if st.button("Generate report", type="primary"):
            with db.get_conn() as conn:
                st.session_state["report"] = rg.build_report(conn, cid)
                db.audit(conn, user, "report_generate", "investigation", cid)
        rep = st.session_state.get("report")
        if rep and rep["case"]["investigation_id"] == cid:
            name = f"investigation_{cid}"
            c = st.columns(5)
            c[0].download_button("PDF", rg.to_pdf(rep), f"{name}.pdf", "application/pdf")
            c[1].download_button("Markdown", rg.to_markdown(rep), f"{name}.md", "text/markdown")
            c[2].download_button("JSON", rg.to_json(rep), f"{name}.json", "application/json")
            c[3].download_button("Alerts CSV", rg.alerts_csv(rep), f"{name}_alerts.csv", "text/csv")
            c[4].download_button("Events CSV", rg.events_csv(rep), f"{name}_events.csv", "text/csv")
            st.caption("Preview (plain text - log content is never rendered as markup)")
            st.code(rg.to_markdown(rep).decode("utf-8"), language="markdown")

with tab_eval:
    st.write("Scores the bundled rules and IOC matching against a **labeled** dataset in an isolated temporary "
             "database (your real data is untouched). Metrics are event-level; undefined ratios are shown as n/a.")
    path = SAMPLES_DIR / "labeled_eval.csv"
    st.caption(f"Dataset: {path.name} (synthetic, includes deliberate false-positive and false-negative cases)")
    if path.exists() and st.button("Run evaluation"):
        r = evaluate_file(path)
        fmt = lambda x: "n/a" if x is None else f"{x:.3f}"
        c = st.columns(4)
        c[0].metric("Precision", fmt(r["precision"]))
        c[1].metric("Recall", fmt(r["recall"]))
        c[2].metric("F1", fmt(r["f1"]))
        c[3].metric("Accuracy", fmt(r["accuracy"]))
        table([{"TP": r["TP"], "FP": r["FP"], "TN": r["TN"], "FN": r["FN"], "records": r["records"]}])
        st.caption("Per-rule events covered")
        table([{"rule": k, **v} for k, v in r["per_rule"].items()])
