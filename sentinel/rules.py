"""Severity rating and behavioral rule escalation.

Evaluates change paths against configured rules (first match wins)
and escalates severity when behavioral detection signals fire.
Ensures severity is never lowered once assigned.
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


def higher_severity(sev1: str, sev2: str) -> str:
    """Return the higher of two severities; never lowers."""
    o1 = SEVERITY_ORDER.get((sev1 or "info").lower(), 1)
    o2 = SEVERITY_ORDER.get((sev2 or "info").lower(), 1)
    return (sev1 or "info").lower() if o1 >= o2 else (sev2 or "info").lower()


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
            or (pat.endswith("/**") and (norm_rel == pat[:-3] or norm_rel.startswith(pat[:-3] + "/")))
            or (pat.startswith("**/") and fnmatch.fnmatch(norm_rel, pat[3:]))
        ):
            return rule.severity.lower()

    # Fallback to default severity by change kind
    base = "info"
    for k in change.kinds:
        if k == "created":
            k_sev = default_new_severity.lower()
        else:
            k_sev = DEFAULT_KIND_SEVERITY.get(k, "info")
        base = higher_severity(base, k_sev)

    return base


def escalate_with_signals(base_severity: str, signals: List[str]) -> str:
    """Escalate severity when behavioral anomaly signals are present.

    Rules:
    - DECOY -> critical
    - SPEED + ENTROPY -> critical
    - SLOW_SUSPICION -> critical
    - SPEED or SUSTAINED alone -> high
    Never lowers base_severity.
    """
    sev = (base_severity or "info").lower()
    sigs = set(signals or [])

    escalated = sev
    if "DECOY" in sigs:
        escalated = "critical"
    elif "SPEED" in sigs and "ENTROPY" in sigs:
        escalated = "critical"
    elif "SLOW_SUSPICION" in sigs:
        escalated = "critical"
    elif "SPEED" in sigs or "SUSTAINED" in sigs:
        escalated = higher_severity(sev, "high")

    return higher_severity(sev, escalated)
