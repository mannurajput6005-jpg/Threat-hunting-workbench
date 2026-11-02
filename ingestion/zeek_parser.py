"""Zeek logs: native TSV (with #fields header) and JSON (flat or nested)."""
from __future__ import annotations

from typing import Iterator

from normalization.normalizer import FieldView, clean

UNSET = {"-", "(empty)"}


def is_zeek_tsv(text: str) -> bool:
    head = text[:2000]
    return head.startswith("#separator") or "\n#fields" in head or head.startswith("#fields")


def read_zeek_tsv(text: str) -> Iterator[tuple[str, dict | None, str | None]]:
    sep, fields, path = "\t", None, None
    for i, line in enumerate(text.splitlines(), start=1):
        if not line:
            continue
        if line.startswith("#separator"):
            spec = line.split(" ", 1)[1].strip() if " " in line else "\\x09"
            sep = bytes(spec, "utf-8").decode("unicode_escape") or "\t"
            continue
        if line.startswith("#fields"):
            fields = line.split(sep)[1:]
            continue
        if line.startswith("#path"):
            path = line.split(sep)[1] if sep in line else None
            continue
        if line.startswith("#"):
            continue
        if not fields:
            yield (f"line {i}", None, "data row before #fields header")
            continue
        parts = line.split(sep)
        if len(parts) != len(fields):
            yield (f"line {i}", None, f"expected {len(fields)} columns, found {len(parts)}")
            continue
        rec = {k: (None if p in UNSET else p) for k, p in zip(fields, parts)}
        if path:
            rec["_path"] = path
        yield (f"line {i}", rec, None)


def _log_type(v: FieldView) -> str:
    path = clean(v.get("_path"))
    if path:
        return path
    if v.has("query") and v.has("qtype_name", "qtype", "trans_id"):
        return "dns"
    if v.has("host") and v.has("uri", "method"):
        return "http"
    if v.has("server_name") or v.has("cipher"):
        return "ssl"
    if v.has("proto") and v.has("id.resp_p"):
        return "conn"
    return "other"


def map_zeek(raw: dict) -> dict:
    v = FieldView(raw)
    log_type = _log_type(v)
    f = {
        "timestamp": v.get("ts"),
        "source_ip": v.get("id.orig_h"), "source_port": v.get("id.orig_p"),
        "destination_ip": v.get("id.resp_h"), "destination_port": v.get("id.resp_p"),
        "protocol": v.get("proto"),
        "event_category": {"conn": "network_connection", "dns": "dns_query", "http": "http_request",
                           "ssl": "tls_connection"}.get(log_type, f"zeek_{log_type}"),
        "event_action": log_type,
    }
    if log_type == "dns":
        f["domain"] = v.get("query")
        f["event_action"] = clean(v.get("qtype_name")) or "dns"
    elif log_type == "http":
        host, uri = clean(v.get("host")), clean(v.get("uri")) or ""
        f["domain"] = host
        f["url"] = f"http://{host}{uri}" if host else None
        f["event_action"] = clean(v.get("method")) or "http"
    elif log_type == "ssl":
        f["domain"] = v.get("server_name")
    elif log_type == "conn":
        f["event_action"] = clean(v.get("conn_state")) or "conn"
    return f
