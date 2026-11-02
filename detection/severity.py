"""Severity scale shared by rules, alerts, cases and reports."""
SEVERITIES = ["low", "medium", "high", "critical"]
_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(value: str | None, default: str = "medium") -> str:
    v = (value or "").strip().lower()
    return v if v in _RANK else default


def severity_rank(value: str | None) -> int:
    return _RANK.get((value or "").lower(), -1)


def max_severity(values) -> str | None:
    vals = [v for v in values if v in _RANK]
    return max(vals, key=severity_rank) if vals else None
