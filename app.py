"""Threat Hunting Workbench - Streamlit entry point.   Run:  streamlit run app.py"""
import streamlit as st

from core import authentication as auth
from core import database as db
from core.ui import bootstrap

st.set_page_config(page_title="Threat Hunting Workbench", page_icon="🛡️", layout="wide")
rule_errors = bootstrap()


def login_view() -> None:
    st.title("🛡️ Threat Hunting Workbench")
    st.caption("Standalone investigation workbench for imported security logs.")
    with db.get_conn() as conn:
        first_run = auth.user_count(conn) == 0
    if first_run:
        st.subheader("First-run setup: create the administrator account")
        st.info("No users exist yet. This form is available only until the first account is created.")
        with st.form("setup"):
            u = st.text_input("Administrator username")
            p1 = st.text_input("Password (10+ chars, upper/lower case and a digit)", type="password")
            p2 = st.text_input("Repeat password", type="password")
            go = st.form_submit_button("Create administrator")
        if go:
            if p1 != p2:
                st.error("Passwords do not match.")
                return
            try:
                with db.get_conn() as conn:
                    auth.create_user(conn, u, p1, "admin", bootstrap=True)
                st.success("Administrator created. You can log in now.")
                st.rerun()
            except (auth.AuthError, PermissionError) as exc:
                st.error(str(exc))
        return
    with st.form("login"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        go = st.form_submit_button("Log in")
    if go:
        try:
            with db.get_conn() as conn:
                user = auth.authenticate(conn, u, p)
            auth.login_session(user)
            st.rerun()
        except auth.AuthError as exc:
            st.error(str(exc))


user = auth.current_user()
if not user:
    login_view()
    st.stop()

pages = [
    st.Page("pages/dashboard.py", title="Dashboard", icon="📊", default=True),
    st.Page("pages/log_ingestion.py", title="Log Ingestion", icon="📥"),
    st.Page("pages/event_explorer.py", title="Event Explorer", icon="🔎"),
    st.Page("pages/threat_detection.py", title="Threat Detection", icon="🚨"),
    st.Page("pages/correlation.py", title="Correlation", icon="🔗"),
    st.Page("pages/ioc_analysis.py", title="IOC Analysis", icon="🧬"),
    st.Page("pages/mitre_attack.py", title="MITRE ATT&CK", icon="🗺️"),
    st.Page("pages/investigations.py", title="Investigations", icon="📁"),
    st.Page("pages/reports.py", title="Reports", icon="📄"),
]
if auth.has_permission(user, "users_manage"):
    pages.append(st.Page("pages/administration.py", title="Administration", icon="⚙️"))

with st.sidebar:
    st.markdown("### 🛡️ Threat Hunting Workbench")
    st.caption(f"Signed in as **{user['username']}** ({user['role']})")
    if st.button("Log out", width="stretch"):
        auth.logout()
        st.rerun()
    if rule_errors:
        with st.expander(f"⚠️ {len(rule_errors)} rule file problem(s)"):
            for e in rule_errors:
                st.text(e)

st.navigation(pages).run()
