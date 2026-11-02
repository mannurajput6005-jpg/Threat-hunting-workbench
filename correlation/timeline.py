"""Timeline helpers: turn events (+ their alerts) into ordered rows and a Plotly figure."""
from __future__ import annotations

import pandas as pd

ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
COLORS = {"critical": "#b71c1c", "high": "#e64a19", "medium": "#f9a825", "low": "#1e88e5", "no alert": "#9e9e9e"}


def build_timeline(events: list[dict], alert_map: dict[int, list[int]] | None = None,
                   alert_severity: dict[int, str] | None = None) -> pd.DataFrame:
    alert_map, alert_severity = alert_map or {}, alert_severity or {}
    rows = []
    for e in sorted(events, key=lambda x: (x.get("timestamp") or "", x["event_id"])):
        sevs = [alert_severity[a] for a in alert_map.get(e["event_id"], []) if a in alert_severity]
        top = max(sevs, key=lambda s: ORDER.get(s, -1)) if sevs else "no alert"
        summary = e.get("command_line") or e.get("domain") or (
            f"{e.get('source_ip') or ''} -> {e.get('destination_ip') or ''}:{e.get('destination_port') or ''}"
            if e.get("destination_ip") else e.get("event_action") or "")
        rows.append({"event_id": e["event_id"], "timestamp": e.get("timestamp"), "host": e.get("hostname") or "(unknown)",
                     "user": e.get("username"), "category": e.get("event_category") or "(none)",
                     "alert_severity": top, "summary": (summary or "")[:160]})
    return pd.DataFrame(rows, columns=["event_id", "timestamp", "host", "user", "category", "alert_severity", "summary"])


def timeline_figure(df: pd.DataFrame):
    """Plotly scatter timeline, or None when there is nothing with a timestamp to draw."""
    import plotly.express as px
    if df.empty or df["timestamp"].isna().all():
        return None
    d = df.dropna(subset=["timestamp"]).copy()
    d["time"] = pd.to_datetime(d["timestamp"], utc=True, format="ISO8601")
    fig = px.scatter(d, x="time", y="category", color="alert_severity", color_discrete_map=COLORS,
                     hover_data=["event_id", "host", "user", "summary"], height=380)
    fig.update_traces(marker={"size": 11})
    fig.update_layout(margin={"l": 10, "r": 10, "t": 10, "b": 10}, legend_title_text="Alert severity")
    return fig
