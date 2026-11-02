import streamlit as st

from core import authentication as auth
from core import config
from core import database as db
from core.ui import table

user = auth.require_login("users_manage")
st.title("⚙️ Administration")
tab_u, tab_a, tab_s = st.tabs(["Users", "Audit log", "System"])

with tab_u:
    with db.get_conn() as conn:
        users = auth.list_users(conn, user)
    table(users)
    with st.form("new_user", clear_on_submit=True):
        st.subheader("Create user")
        u = st.text_input("Username")
        p = st.text_input("Initial password", type="password")
        role = st.selectbox("Role", auth.ROLES, index=1)
        if st.form_submit_button("Create"):
            try:
                with db.get_conn() as conn:
                    auth.create_user(conn, u, p, role, user)
                st.success("User created.")
                st.rerun()
            except (auth.AuthError, PermissionError) as exc:
                st.error(str(exc))
    st.subheader("Manage user")
    labels = {x["user_id"]: f"{x['username']} ({x['role']}{'' if x['is_active'] else ', disabled'})" for x in users}
    uid = st.selectbox("User", list(labels), format_func=labels.get)
    c1, c2, c3 = st.columns(3)
    new_role = c1.selectbox("New role", auth.ROLES)
    try:
        if c1.button("Change role"):
            with db.get_conn() as conn:
                auth.set_user_role(conn, user, uid, new_role)
            st.rerun()
        target = next(x for x in users if x["user_id"] == uid)
        if c2.button("Disable account" if target["is_active"] else "Enable account"):
            with db.get_conn() as conn:
                auth.set_user_active(conn, user, uid, not target["is_active"])
            st.rerun()
        pw = c3.text_input("New password", type="password", key="rp")
        if c3.button("Reset password"):
            with db.get_conn() as conn:
                auth.reset_password(conn, user, uid, pw)
            st.success("Password reset.")
    except (auth.AuthError, PermissionError) as exc:
        st.error(str(exc))

with tab_a:
    flt = st.text_input("Filter by action or username")
    with db.get_conn() as conn:
        if flt:
            like = f"%{flt}%"
            logs = db.rows(conn, "SELECT * FROM audit_logs WHERE action LIKE ? OR username LIKE ? "
                                 "ORDER BY audit_id DESC LIMIT 500", (like, like))
        else:
            logs = db.rows(conn, "SELECT * FROM audit_logs ORDER BY audit_id DESC LIMIT 500")
    table(logs, height=480)

with tab_s:
    with db.get_conn() as conn:
        counts = {t: db.scalar(conn, f"SELECT COUNT(*) FROM {t}") for t in
                  ("events", "alerts", "iocs", "investigations", "users", "detection_rules", "audit_logs")}
    st.json({"database": str(config.DB_PATH), "rules_dir": str(config.RULES_DIR), "row_counts": counts,
             "max_upload_mb": config.MAX_UPLOAD_MB, "session_timeout_minutes": config.SESSION_TIMEOUT_MINUTES,
             "external_enrichment_enabled": config.ENABLE_EXTERNAL_ENRICHMENT})
