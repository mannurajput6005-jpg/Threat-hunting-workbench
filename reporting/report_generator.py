"""Investigation report export: PDF, Markdown, JSON and CSV.

Reports state the time range and data sources examined, and repeat that alerts/correlations are
investigative leads - not proof of compromise. All untrusted text is escaped before it goes into a PDF.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from core import database as db
from investigations.evidence_manager import collect_evidence

DISCLAIMER = ("Alerts, IOC matches, ATT&CK references and correlations in this report are investigative "
              "leads derived from imported logs. They are not proof of compromise or of attacker intent.")
MAX_EVENT_ROWS = 200


def _generated() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def build_report(conn, case_id: int) -> dict:
    """Plain-data report (also used for the JSON export)."""
    ev = collect_evidence(conn, case_id)
    for a in ev["alerts"]:
        try:
            a["evidence"] = json.loads(a["evidence"]) if a.get("evidence") else None
        except (TypeError, ValueError):
            pass
    return {"generated_at": _generated(), "disclaimer": DISCLAIMER, **ev}


def to_json(report: dict) -> bytes:
    return json.dumps(report, indent=2, default=str, ensure_ascii=False).encode("utf-8")


def alerts_csv(report: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["alert_id", "rule_id", "rule_name", "severity", "status", "created_at", "mitre", "description"])
    for a in report["alerts"]:
        w.writerow([_csv_safe(x) for x in (a["alert_id"], a["rule_id"], a["rule_name"], a["severity"], a["status"],
                                           a["created_at"], a.get("mitre_technique_id") or "", a["description"])])
    return buf.getvalue().encode("utf-8")


def events_csv(report: dict) -> bytes:
    cols = ["event_id", "timestamp", "hostname", "username", "source_ip", "destination_ip", "destination_port",
            "process_name", "command_line", "event_category", "outcome", "source_type", "source_file", "record_ref"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for e in report["events"]:
        w.writerow([_csv_safe(e.get(c)) for c in cols])
    return buf.getvalue().encode("utf-8")


def _csv_safe(v):
    """Neutralise spreadsheet formula injection from log-derived text."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def to_markdown(report: dict) -> bytes:
    c, tr = report["case"], report["time_range"]
    L = [f"# Investigation Report: {c['title']}", "",
         f"- Case ID: {c['investigation_id']}", f"- Status: {c['status']}  |  Severity: {c['severity']}  |  Verdict: {c['verdict']}",
         f"- Generated: {report['generated_at']}",
         f"- Time range of linked events: {tr['start'] or 'n/a'} to {tr['end'] or 'n/a'}",
         f"- Data sources examined: {', '.join(report['data_sources']) or 'n/a'}",
         f"- Source files: {', '.join(report['source_files']) or 'n/a'}", "",
         f"> {report['disclaimer']}", "", "## Description", c["description"] or "(none)", "", "## Alerts"]
    for a in report["alerts"]:
        L.append(f"- [{a['severity']}] #{a['alert_id']} {a['rule_id']} {a['rule_name']} ({a['status']}): {a['description']}")
    L += ["", "## ATT&CK references (rule-based, not proof)"]
    L += [f"- {t['id']} {t['name']} ({', '.join(t['tactics'])})" for t in report["techniques"]] or ["- none"]
    L += ["", "## IOC findings"]
    L += [f"- {i['indicator_type']}: {i['indicator_value']} (watchlist match: {'yes' if i['watchlist_match'] else 'no'}, "
          f"observations: {i['observations']})" for i in report["iocs"]] or ["- none"]
    L += ["", "## Timeline (linked events)"]
    for e in report["events"][:MAX_EVENT_ROWS]:
        L.append(f"- {e['timestamp'] or 'n/a'} | {e.get('hostname') or '-'} | {e.get('event_category') or '-'} | "
                 f"{(e.get('command_line') or e.get('domain') or e.get('destination_ip') or '')[:120]}")
    L += ["", "## Analyst notes"]
    L += [f"- {n['created_at']} {n.get('username') or 'system'}: {n['note']}" for n in report["notes"]] or ["- none"]
    L += ["", "## Conclusion", c["conclusion"] or "(not yet recorded)", ""]
    return "\n".join(L).encode("utf-8")


def to_pdf(report: dict) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    ss = getSampleStyleSheet()
    small = ss["BodyText"].clone("small", fontSize=8, leading=10)
    P = lambda t, st=ss["BodyText"]: Paragraph(escape(str(t if t is not None else "")), st)

    def table(header, data, widths):
        rows = [[P(h, small) for h in header]] + [[P(x, small) for x in r] for r in data]
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                               ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        return t

    c, tr = report["case"], report["time_range"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                            bottomMargin=15 * mm, title=f"Investigation {c['investigation_id']}")
    S = [P("Investigation Report", ss["Title"]), P(c["title"], ss["Heading2"]),
         P(f"Case #{c['investigation_id']}  |  Status: {c['status']}  |  Severity: {c['severity']}  |  Verdict: {c['verdict']}"),
         P(f"Generated: {report['generated_at']}"),
         P(f"Time range of linked events: {tr['start'] or 'n/a'} to {tr['end'] or 'n/a'}"),
         P(f"Data sources examined: {', '.join(report['data_sources']) or 'n/a'}"),
         P(f"Source files: {', '.join(report['source_files']) or 'n/a'}"), Spacer(1, 6),
         P(report["disclaimer"], ss["Italic"]), Spacer(1, 8),
         P("Description", ss["Heading3"]), P(c["description"] or "(none)")]
    S += [P("Alerts", ss["Heading3"])]
    S += [table(["ID", "Severity", "Rule", "Status", "Description"],
                [[a["alert_id"], a["severity"], f"{a['rule_id']} {a['rule_name']}", a["status"], a["description"]]
                 for a in report["alerts"]], [12 * mm, 18 * mm, 45 * mm, 20 * mm, 85 * mm])
          if report["alerts"] else P("No alerts linked.")]
    S += [P("ATT&CK references (rule-based, not proof of attacker activity)", ss["Heading3"])]
    S += [table(["Technique", "Name", "Tactics"], [[t["id"], t["name"], ", ".join(t["tactics"])] for t in report["techniques"]],
                [25 * mm, 90 * mm, 65 * mm]) if report["techniques"] else P("None.")]
    S += [P("IOC findings", ss["Heading3"])]
    S += [table(["Type", "Value", "Watchlist", "Obs."],
                [[i["indicator_type"], i["indicator_value"], "yes" if i["watchlist_match"] else "no", i["observations"]]
                 for i in report["iocs"]], [18 * mm, 110 * mm, 25 * mm, 15 * mm]) if report["iocs"] else P("None.")]
    S += [P(f"Timeline (first {MAX_EVENT_ROWS} of {len(report['events'])} linked events)", ss["Heading3"])]
    S += [table(["Time (UTC)", "Host", "Category", "Detail"],
                [[e["timestamp"], e.get("hostname"), e.get("event_category"),
                  (e.get("command_line") or e.get("domain") or f"{e.get('source_ip') or ''} -> {e.get('destination_ip') or ''}")[:140]]
                 for e in report["events"][:MAX_EVENT_ROWS]], [38 * mm, 28 * mm, 30 * mm, 84 * mm])
          if report["events"] else P("No events linked.")]
    S += [P("Analyst notes", ss["Heading3"])]
    S += [P(f"{n['created_at']} - {n.get('username') or 'system'}: {n['note']}", small) for n in report["notes"]] or [P("None.")]
    S += [P("Conclusion", ss["Heading3"]), P(c["conclusion"] or "(not yet recorded)")]
    doc.build(S)
    return buf.getvalue()
