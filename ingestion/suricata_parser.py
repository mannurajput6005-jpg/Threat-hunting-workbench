"""Suricata EVE JSON mapper."""
from __future__ import annotations

from normalization.normalizer import FieldView, clean

SEVERITY = {"1": "high", "2": "medium", "3": "low"}


def map_suricata(raw: dict) -> dict:
    v = FieldView(raw)
    etype = (clean(v.get("event_type")) or "other").lower()
    f = {
        "timestamp": v.get("timestamp"),
        "hostname": v.get("host"),
        "source_ip": v.get("src_ip"), "source_port": v.get("src_port"),
        "destination_ip": v.get("dest_ip"), "destination_port": v.get("dest_port"),
        "protocol": v.get("proto"),
        "event_category": {"alert": "ids_alert", "dns": "dns_query", "http": "http_request",
                           "tls": "tls_connection", "flow": "network_connection"}.get(etype, f"suricata_{etype}"),
        "event_action": etype,
    }
    if etype == "alert":
        f["event_action"] = clean(v.get("alert.signature")) or "alert"
        f["severity"] = SEVERITY.get(clean(v.get("alert.severity")) or "")
        f["event_code"] = clean(v.get("alert.signature_id"))
    elif etype == "dns":
        f["domain"] = v.get("dns.rrname", "rrname")
    elif etype == "http":
        host, url = clean(v.get("http.hostname")), clean(v.get("http.url")) or ""
        f["domain"] = host
        f["url"] = f"http://{host}{url}" if host else url or None
    elif etype == "tls":
        f["domain"] = v.get("tls.sni", "sni")
    return f
