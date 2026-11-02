"""Small Streamlit helpers shared by the pages. Log-derived text is only ever shown via st.text/st.code/
st.json/st.dataframe (never st.markdown or unsafe HTML), so hostile log content cannot inject markup."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from core import database as db
from core.logging_config import get_logger

log = get_logger(__name__)
SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_COLORS = {"critical": "#b71c1c", "high": "#e64a19", "medium": "#f9a825", "low": "#1e88e5"}


@st.cache_resource(show_spinner="Preparing database...")
def bootstrap() -> list[str]:
    """Create tables, sync YAML rules, load the bundled IOC watchlist on first run. Returns rule errors."""
    from detection.rule_loader import sync_rules
    from threat_intelligence.ioc_matcher import load_watchlist
    db.init_db()
    with db.get_conn() as conn:
        _, errors = sync_rules(conn)
        if not db.scalar(conn, "SELECT COUNT(*) FROM ioc_watchlist"):
            load_watchlist(conn)
    return errors


def table(rows: list[dict], columns: list[str] | None = None, *, key: str | None = None,
          select: str | None = None, height: int | None = None):
    """Render rows as a dataframe. With ``select`` ('single-row'/'multi-row') returns the selected row dicts."""
    df = pd.DataFrame(rows)
    if columns and not df.empty:
        df = df[[c for c in columns if c in df.columns]]
    if df.empty:
        st.info("No data to show.")
        return []
    if select:
        ev = st.dataframe(df, hide_index=True, width="stretch", on_select="rerun", selection_mode=select,
                          key=key, height=height)
        return [rows[i] for i in ev.selection.rows if i < len(rows)]
    st.dataframe(df, hide_index=True, width="stretch", height=height)
    return []


def case_picker(conn, user, key: str):
    """Selectbox of open cases; returns case_id or None."""
    from investigations.case_manager import list_cases
    cases = [c for c in list_cases(conn, user) if c["status"] != "Closed"]
    if not cases:
        st.caption("No open cases yet - create one on the Investigations page.")
        return None
    labels = {c["investigation_id"]: f"#{c['investigation_id']} {c['title']} [{c['status']}]" for c in cases}
    return st.selectbox("Case", list(labels), format_func=labels.get, key=key)


def day_start(d) -> str | None:
    return f"{d.isoformat()}T00:00:00.000Z" if d else None


def day_end(d) -> str | None:
    return f"{d.isoformat()}T23:59:59.999Z" if d else None
