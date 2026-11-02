"""Sysmon and Windows Event Log mappers + XML reader (wevtutil / Event Viewer exports)."""
from __future__ import annotations

import re
from typing import Iterator

from defusedxml import ElementTree as SafeET  # blocks entity expansion / external entities

from normalization.normalizer import FieldView, clean, strip_domain

SYSMON_CATEGORIES = {
    "1": "process_creation", "2": "file_time_changed", "3": "network_connection",
    "5": "process_terminated", "6": "driver_loaded", "7": "image_load", "8": "remote_thread",
    "10": "process_access", "11": "file_creation", "12": "registry_event", "13": "registry_event",
    "14": "registry_event", "15": "file_stream", "22": "dns_query", "23": "file_delete",
}

# code -> (category, action, outcome)
WINDOWS_EVENTS = {
    "4624": ("authentication", "logon", "success"),
    "4625": ("authentication", "logon", "failure"),
    "4634": ("authentication", "logoff", None),
    "4647": ("authentication", "logoff", None),
    "4648": ("authentication", "explicit_credential_logon", None),
    "4672": ("authentication", "special_privileges_assigned", None),
    "4768": ("authentication", "kerberos_tgt_request", None),
    "4769": ("authentication", "kerberos_service_ticket", None),
    "4771": ("authentication", "kerberos_preauth", "failure"),
    "4776": ("authentication", "ntlm_validation", None),
    "4688": ("process_creation", "process_create", None),
    "4698": ("scheduled_task", "task_created", None),
    "4720": ("account_management", "account_created", None),
    "4732": ("account_management", "group_member_added", None),
    "7045": ("service_install", "service_installed", None),
    "1102": ("log_cleared", "security_log_cleared", None),
    "104": ("log_cleared", "system_log_cleared", None),
}
SUBJECT_USER_CODES = {"4688", "1102", "104", "4698", "7045", "4648", "4672", "4732"}


def _parse_hashes(value: str | None) -> str | None:
    """'SHA256=ab..,MD5=cd..' -> prefer SHA256, else SHA1, else MD5."""
    if not value:
        return None
    pairs = dict(p.split("=", 1) for p in re.split(r"[,;]", value) if "=" in p)
    pairs = {k.strip().upper(): v.strip() for k, v in pairs.items()}
    for algo in ("SHA256", "SHA1", "MD5"):
        if pairs.get(algo):
            return pairs[algo].lower()
    return None


def _code(v: FieldView) -> str | None:
    code = clean(v.get("EventID", "event_id", "event.code"))
    return code[:-2] if code and code.endswith(".0") else code


def map_sysmon(raw: dict) -> dict:
    v = FieldView(raw)
    code = _code(v)
    category = SYSMON_CATEGORIES.get(code or "", "sysmon_other")
    return {
        "timestamp": v.get("UtcTime", "TimeCreated", "SystemTime", "@timestamp", "timestamp"),
        "hostname": v.get("Computer", "ComputerName", "host.name", "hostname", "MachineName"),
        "username": strip_domain(clean(v.get("User", "user.name", "UserName"))),
        "process_path": v.get("Image", "process.executable"),
        "parent_process": v.get("ParentImage"),
        "command_line": v.get("CommandLine", "process.command_line"),
        "source_ip": v.get("SourceIp"), "source_port": v.get("SourcePort"),
        "destination_ip": v.get("DestinationIp"), "destination_port": v.get("DestinationPort"),
        "protocol": v.get("Protocol"),
        "domain": v.get("QueryName", "DestinationHostname"),
        "file_hash": _parse_hashes(clean(v.get("Hashes"))) or clean(v.get("Hash", "SHA256", "MD5")),
        "event_code": code, "event_category": category, "event_action": category,
    }


def map_windows(raw: dict) -> dict:
    v = FieldView(raw)
    code = _code(v)
    category, action, outcome = WINDOWS_EVENTS.get(code or "", ("windows_event", "windows_event", None))
    if code == "4776":  # Status 0x0 = success
        status = clean(v.get("Status"))
        outcome = "success" if status in ("0x0", "0") else ("failure" if status else None)
    if code in SUBJECT_USER_CODES:
        user = v.get("SubjectUserName", "TargetUserName", "UserName")
    else:
        user = v.get("TargetUserName", "SubjectUserName", "UserName")
    return {
        "timestamp": v.get("TimeCreated", "SystemTime", "UtcTime", "@timestamp", "timestamp"),
        "hostname": v.get("Computer", "ComputerName", "MachineName", "host.name", "hostname"),
        "username": strip_domain(clean(user)),
        "source_ip": v.get("IpAddress", "SourceNetworkAddress", "ClientAddress", "SourceAddress"),
        "source_port": v.get("IpPort", "SourcePort"),
        "process_path": v.get("NewProcessName", "ProcessName"),
        "parent_process": v.get("ParentProcessName"),
        "command_line": v.get("CommandLine", "ImagePath", "TaskName"),
        "event_code": code, "event_category": category, "event_action": action, "outcome": outcome,
    }


def read_windows_xml(text: str, max_records: int) -> Iterator[tuple[str, dict | None, str | None]]:
    """Parse concatenated <Event> elements (wevtutil export) or an <Events> wrapper."""
    body = re.sub(r"<\?xml[^>]*\?>", "", text).strip()
    try:
        root = SafeET.fromstring(f"<Events>{body}</Events>" if not body.startswith("<Events") else body)
    except Exception as exc:  # defusedxml raises its own exception types for forbidden constructs
        yield ("document", None, f"invalid or unsafe XML: {type(exc).__name__}")
        return
    events = [e for e in root.iter() if e.tag.split("}")[-1] == "Event"]
    for i, ev in enumerate(events[:max_records], start=1):
        rec: dict = {}
        try:
            for child in ev:
                tag = child.tag.split("}")[-1]
                if tag == "System":
                    for s in child:
                        stag = s.tag.split("}")[-1]
                        if stag == "TimeCreated":
                            rec["TimeCreated"] = s.attrib.get("SystemTime")
                        elif stag == "Provider":
                            rec["Provider"] = s.attrib.get("Name")
                        else:
                            rec[stag] = (s.text or "").strip()
                elif tag in ("EventData", "UserData"):
                    for d in child.iter():
                        name = d.attrib.get("Name") or (d.tag.split("}")[-1] if d is not child else None)
                        if name and (d.text or "").strip():
                            rec[name] = d.text.strip()
            yield (f"event {i}", rec, None)
        except Exception as exc:  # pragma: no cover - defensive
            yield (f"event {i}", None, f"cannot read event: {type(exc).__name__}")
