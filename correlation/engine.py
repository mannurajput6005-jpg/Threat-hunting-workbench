"""Entity / time-window correlation.

Two events are linked when they share an entity value (host, user, source IP, destination IP ...)
and occur within ``window_seconds`` of each other. Linked events form a *candidate activity
sequence* for analyst review. This shows association only - it does NOT prove causation.
By default only events that already triggered an alert are correlated (keeps clusters meaningful
and avoids chaining every event on a busy host).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime

from core import database as db
from core.config import CORRELATION_WINDOW_SECONDS
from detection.severity import max_severity

DEFAULT_ENTITIES = ("hostname", "username", "source_ip", "destination_ip")
IGNORED_VALUES = {"127.0.0.1", "::1", "0.0.0.0", "system", "local service", "network service",
                  "anonymous logon", "-", "localhost"}


@dataclass
class Cluster:
    cluster_id: str
    event_ids: list[int]
    alert_ids: list[int]
    start: str
    end: str
    shared_entities: dict[str, list[str]]
    rule_ids: list[str]
    techniques: list[str]
    max_severity: str | None
    summary: str = ""
    events: list[dict] = field(default_factory=list, repr=False)


def _t(e: dict) -> datetime | None:
    try:
        return datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")) if e.get("timestamp") else None
    except ValueError:
        return None


def correlate(events: list[dict], alert_map: dict[int, list[int]] | None = None,
              alert_info: dict[int, dict] | None = None,
              entity_fields: tuple[str, ...] = DEFAULT_ENTITIES,
              window_seconds: int = CORRELATION_WINDOW_SECONDS, min_events: int = 2) -> list[Cluster]:
    alert_map, alert_info = alert_map or {}, alert_info or {}
    timed = []
    for e in events:
        t = _t(e)
        if t is not None:
            timed.append((t, e))
    timed.sort(key=lambda x: (x[0], x[1]["event_id"]))
    parent = list(range(len(timed)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    last_seen: dict[tuple[str, str], tuple[datetime, int]] = {}
    for idx, (t, e) in enumerate(timed):
        for f in entity_fields:
            val = e.get(f)
            if not val or str(val).lower() in IGNORED_VALUES:
                continue
            key = (f, str(val).lower())
            prev = last_seen.get(key)
            if prev and (t - prev[0]).total_seconds() <= window_seconds:
                parent[find(idx)] = find(prev[1])
            last_seen[key] = (t, idx)

    groups: dict[int, list[int]] = {}
    for idx in range(len(timed)):
        groups.setdefault(find(idx), []).append(idx)

    clusters = []
    for members in groups.values():
        if len(members) < min_events:
            continue
        evs = [timed[i][1] for i in members]
        ids = sorted(e["event_id"] for e in evs)
        alert_ids = sorted({a for e in evs for a in alert_map.get(e["event_id"], [])})
        infos = [alert_info[a] for a in alert_ids if a in alert_info]
        shared: dict[str, list[str]] = {}
        for f in entity_fields:
            counts: dict[str, int] = {}
            for e in evs:
                v = e.get(f)
                if v and str(v).lower() not in IGNORED_VALUES:
                    counts[str(v)] = counts.get(str(v), 0) + 1
            repeated = sorted(v for v, c in counts.items() if c >= 2)
            if repeated:
                shared[f] = repeated
        techniques = sorted({t for i in infos for t in (i.get("mitre") or "").split(",") if t})
        rules = sorted({i["rule_id"] for i in infos})
        cid = hashlib.sha1(",".join(map(str, ids)).encode()).hexdigest()[:10]
        c = Cluster(cid, ids, alert_ids, evs[0]["timestamp"], evs[-1]["timestamp"], shared, rules, techniques,
                    max_severity([i["severity"] for i in infos]), events=evs)
        entities = "; ".join(f"{k}={', '.join(v[:3])}" for k, v in shared.items()) or "no repeated entity"
        c.summary = (f"{len(ids)} events / {len(alert_ids)} alerts between {c.start} and {c.end}; "
                     f"shared: {entities}.")
        clusters.append(c)
    clusters.sort(key=lambda c: (-(len(c.alert_ids)), c.start))
    return clusters


def correlate_from_db(conn, window_seconds: int = CORRELATION_WINDOW_SECONDS,
                      entity_fields: tuple[str, ...] = DEFAULT_ENTITIES, alerted_only: bool = True,
                      min_events: int = 2) -> list[Cluster]:
    amap = db.alert_event_map(conn)
    ainfo = {r["alert_id"]: {"rule_id": r["rule_id"], "severity": r["severity"], "mitre": r["mitre_technique_id"]}
             for r in db.rows(conn, "SELECT a.alert_id, a.rule_id, a.severity, r.mitre_technique_id "
                                    "FROM alerts a JOIN detection_rules r ON r.rule_id=a.rule_id")}
    if alerted_only:
        events = db.get_events_by_ids(conn, list(amap.keys()))
    else:
        events = db.rows(conn, "SELECT * FROM events WHERE timestamp IS NOT NULL ORDER BY timestamp LIMIT 20000")
    return correlate(events, amap, ainfo, entity_fields, window_seconds, min_events)
