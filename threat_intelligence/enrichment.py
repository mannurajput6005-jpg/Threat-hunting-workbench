"""OPTIONAL external enrichment (VirusTotal). Disabled by default; the app works fully offline.

Only the indicator value itself is sent - never raw logs, hostnames or usernames.
Enable with THW_ENABLE_EXTERNAL_ENRICHMENT=true and VIRUSTOTAL_API_KEY=<key>.
"""
from __future__ import annotations

import base64
import json

import requests

from core import database as db
from core.authentication import authorize
from core.config import ENABLE_EXTERNAL_ENRICHMENT, VIRUSTOTAL_API_KEY

VT_BASE = "https://www.virustotal.com/api/v3"


def enrichment_enabled() -> bool:
    return bool(ENABLE_EXTERNAL_ENRICHMENT and VIRUSTOTAL_API_KEY)


def _vt_path(kind: str, value: str) -> str | None:
    if kind == "ip":
        return f"/ip_addresses/{value}"
    if kind == "domain":
        return f"/domains/{value}"
    if kind == "hash":
        return f"/files/{value}"
    if kind == "url":
        return f"/urls/{base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')}"
    return None


def enrich_ioc(conn, actor: dict, ioc_id: int, http_get=requests.get) -> dict:
    """Look up one stored IOC. Returns the stored result. ``http_get`` is injectable for tests."""
    authorize(actor, "ioc_write")
    if not enrichment_enabled():
        raise RuntimeError("External enrichment is disabled (see README).")
    ioc = db.one(conn, "SELECT * FROM iocs WHERE ioc_id=?", (ioc_id,))
    if not ioc:
        raise ValueError("IOC not found")
    path = _vt_path(ioc["indicator_type"], ioc["indicator_value"])
    status, data = "error", {}
    try:
        resp = http_get(VT_BASE + path, headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10)
        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            data = {"provider": "virustotal", **{k: stats.get(k) for k in
                    ("malicious", "suspicious", "harmless", "undetected")}}
            status = "enriched"
        elif resp.status_code == 404:
            status, data = "not_found", {"provider": "virustotal"}
        elif resp.status_code == 429:
            status, data = "rate_limited", {"provider": "virustotal"}
        else:
            data = {"provider": "virustotal", "http_status": resp.status_code}
    except requests.RequestException as exc:
        data = {"provider": "virustotal", "error": type(exc).__name__}
    conn.execute("UPDATE iocs SET enrichment_status=?, enrichment_data=? WHERE ioc_id=?",
                 (status, json.dumps(data), ioc_id))
    db.audit(conn, actor, "ioc_enrich", "ioc", ioc_id, status)
    return {"status": status, **data}
