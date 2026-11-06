"""Severity rating and behavioral rule escalation.

Evaluates change paths against configured rules (first match wins)
and escalates severity when behavioral detection signals fire.
"""

from __future__ import annotations

import fnmatch
from typing import List, Optional

from sentinel.models import Change
from sentinel.settings import RuleSettings

# Base severity defaults
DEFAULT_KIND_SEVERITY = {
    "created": "info",
    "modified": "medium",
    "deleted": "high",
    "permissions": "high",
    "owner": "high",
    "renamed": "medium",
}

SEVERITY_ORDER = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _higher_severity(sev1: str, sev2: str) -> str:
    """Return the more severe of two levels."""
    o1 = SEVERITY_ORDER.get(sev1.lower(), 1)
    o2 = SEVERITY_ORDER.get(sev2.lower(), 1)
    return sev1 if o1 >= o2 else sev2


def evaluate_rules(
    relpath: str,
    abspath: str,
    root_id: str,
    change: Change,
    rules: List[RuleSettings],
    default_new_severity: str = "info",
) -> str:
    """Determine initial severity based on matched rules or kind defaults.

    First match wins among explicit rules.
    """
    norm_rel = relpath.replace("\\", "/").strip("/")
    norm_abs = abspath.replace("\\", "/")
    filename = norm_rel.split("/")[-1]

    for rule in rules:
        if rule.under and rule.under != root_id:
            continue
        pat = rule.match.replace("\\", "/").strip("/")
        # Check against relative path, absolute path, and filename
        if (
            fnmatch.fnmatch(norm_rel, pat)
            or fnmatch.fnmatch(norm_abs, pat)
            or fnmatch.fnmatch(filename, pat)
        ):
            return rule.severity

    # Fallback to default severity by change kind
    if "created" in change.kinds:
        base = default_new_severity
    else:
        # Highest severity among detected kinds
        base = "info"
        for k in change.kinds:
            k_sev = DEFAULT_KIND_SEVERITY.get(k, "info")
            base = _higher_severity(base, k_sev)

    return base


def escalate_with_signals(base_severity: str, signals: List[str]) -> str:
    """Escalate severity when behavioral anomaly signals are present.

    - DECOY -> critical
    - SPEED + ENTROPY -> critical
    - SLOW_SUSPICION -> critical
    - SPEED or SUSTAINED alone -> high
    """
    sev = base_severity.lower()
    sigs = set(signals)

    if "DECOY" in sigs:
        return "critical"
    if "SPEED" in sigs and "ENTROPY" in sigs:
        return "critical"
    if "SLOW_SUSPICION" in sigs:
        return "critical"
    if "SPEED" in sigs or "SUSTAINED" in sigs:
        return _higher_severity(sev, "high")

    return sev
