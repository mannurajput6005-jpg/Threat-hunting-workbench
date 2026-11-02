"""Extract IOCs (IPs, domains, URLs, file hashes) from normalized events.

Structured fields (source_ip, destination_ip, domain, url, file_hash) are used directly.
Free text (command_line) is scanned only for URLs, IPv4 addresses and hashes - bare
"domain-like" words are NOT extracted from free text because file names such as
``update.exe`` would create false positives.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
HASH_RE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]

Indicator = tuple[str, str, str]  # (type, value, source_field)


def is_internal_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
            or any(a in net for net in PRIVATE_NETS if a.version == 4))


def _ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip())) if value else None
    except ValueError:
        return None


def _domain(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().lower().rstrip(".")
    return v if DOMAIN_RE.match(v) else None


def extract_from_event(ev: dict) -> list[Indicator]:
    found: dict[tuple[str, str], str] = {}

    def add(kind: str, value: str | None, field: str) -> None:
        if value:
            found.setdefault((kind, value), field)

    add("ip", _ip(ev.get("source_ip")), "source_ip")
    add("ip", _ip(ev.get("destination_ip")), "destination_ip")

    dom = ev.get("domain")
    if _ip(dom):
        add("ip", _ip(dom), "domain")
    else:
        add("domain", _domain(dom), "domain")

    for field in ("url", "command_line"):
        text = ev.get(field) or ""
        for m in URL_RE.findall(text):
            url = m.rstrip(".,;:")
            add("url", url, field)
            host = urlparse(url).hostname
            if _ip(host):
                add("ip", _ip(host), field)
            else:
                add("domain", _domain(host), field)
    for m in IPV4_RE.findall(ev.get("command_line") or ""):
        add("ip", _ip(m), "command_line")

    h = (ev.get("file_hash") or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]+", h or "x") and len(h) in HASH_LEN:
        add("hash", h, "file_hash")
    for m in HASH_RE.findall(ev.get("command_line") or ""):
        add("hash", m.lower(), "command_line")
    return [(k, v, f) for (k, v), f in found.items()]


def normalize_indicator(kind: str, value: str) -> str:
    """Canonical form used for exact matching (case-insensitive types are lowercased)."""
    v = value.strip()
    if kind in ("domain", "hash"):
        return v.lower().rstrip(".")
    if kind == "ip":
        return _ip(v) or v
    return v.lower()  # url
