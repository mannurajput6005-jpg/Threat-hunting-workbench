import json

import streamlit as st

from core import database as db
from core.authentication import has_permission, require_login
from core.ui import table
from threat_intelligence import enrichment
from threat_intelligence.ioc_matcher import load_watchlist, run_ioc_analysis

user = require_login("read")
st.title("🧬 IOC Analysis")
st.caption("Indicators (IPs, domains, URLs, hashes) are extracted from events and matched exactly against the local "
           "watchlist. Check indicator confidence and freshness before acting on a match.")

can_write = has_permission(user, "ioc_write")
tab_obs, tab_watch = st.tabs(["Observed indicators", "Watchlist"])

with tab_obs:
    if has_permission(user, "detect") and st.button("Run IOC extraction and matching", type="primary"):
        with db.get_conn() as conn:
            r = run_ioc_analysis(conn, user)
        st.success(f"Scanned {r['events_scanned']:,} events; {r['indicators']} indicators; "
                   f"{r['watchlist_matches']} watchlist match(es); {r['new_alerts']} new alert(s).")
    only = st.checkbox("Only watchlist matches")
    with db.get_conn() as conn:
        iocs = db.rows(conn, "SELECT * FROM iocs " + ("WHERE watchlist_match=1 " if only else "") +
                             "ORDER BY watchlist_match DESC, observations DESC LIMIT 2000")
    sel = table(iocs, ["ioc_id", "indicator_type", "indicator_value", "watchlist_match", "confidence", "source",
                       "observations", "first_seen", "last_seen", "enrichment_status"], key="ioc_tbl",
                select="single-row", height=380)
    if sel:
        ioc = sel[0]
        with db.get_conn() as conn:
            ev = db.rows(conn, "SELECT e.event_id, e.timestamp, e.hostname, e.event_category, e.command_line, e.domain "
                               "FROM events e JOIN ioc_events ie ON ie.event_id=e.event_id WHERE ie.ioc_id=? "
                               "ORDER BY e.timestamp LIMIT 200", (ioc["ioc_id"],))
        st.caption(f"Events containing {ioc['indicator_type']} {ioc['indicator_value']}")
        table(ev)
        if ioc["enrichment_data"]:
            st.json(json.loads(ioc["enrichment_data"]))
        if enrichment.enrichment_enabled() and can_write:
            st.warning("External enrichment sends ONLY this indicator value to VirusTotal.")
            if st.button("Enrich with VirusTotal"):
                with db.get_conn() as conn:
                    res = enrichment.enrich_ioc(conn, user, ioc["ioc_id"])
                st.write(f"Result: {res['status']}")
        else:
            st.caption("External enrichment is disabled (offline mode). See README to enable it.")

with tab_watch:
    with db.get_conn() as conn:
        wl = db.rows(conn, "SELECT * FROM ioc_watchlist ORDER BY indicator_type, indicator_value")
    table(wl, height=300)
    if can_write:
        up = st.file_uploader("Upload watchlist CSV (indicator_type, indicator_value, source, confidence, description)",
                              type=["csv"], key="wl_up")
        if up and st.button("Load uploaded watchlist"):
            try:
                text = up.getvalue().decode("utf-8-sig")
            except UnicodeDecodeError:
                st.error("File is not valid UTF-8.")
            else:
                with db.get_conn() as conn:
                    n, errors = load_watchlist(conn, actor=user, content=text)
                st.success(f"Loaded {n} indicators.")
                for e in errors[:20]:
                    st.error(e)
        if st.button("Reload bundled watchlist"):
            with db.get_conn() as conn:
                n, errors = load_watchlist(conn, actor=user)
            st.success(f"Loaded {n} indicators.")
