"""Unit tests for Sentinel rules engine and behavioral escalation."""

import pytest
from sentinel.models import Change
from sentinel.rules import evaluate_rules, escalate_with_signals, higher_severity
from sentinel.settings import RuleSettings


def test_first_match_wins():
    rules = [
        RuleSettings(match="**/special.txt", severity="critical", reason="first rule"),
        RuleSettings(match="**/special.txt", severity="low", reason="second rule"),
        RuleSettings(match="**/*.txt", severity="medium", reason="generic rule"),
    ]
    change = Change(kinds=["modified"])
    sev = evaluate_rules("sub/special.txt", "/abs/sub/special.txt", "root1", change, rules)
    assert sev == "critical"


def test_rule_scoping_with_under():
    rules = [
        RuleSettings(match="**/index.html", severity="high", under="web"),
        RuleSettings(match="**/index.html", severity="low", under="docs"),
    ]
    change = Change(kinds=["modified"])

    sev_web = evaluate_rules("index.html", "/var/www/html/index.html", "web", change, rules)
    assert sev_web == "high"

    sev_docs = evaluate_rules("index.html", "/home/user/docs/index.html", "docs", change, rules)
    assert sev_docs == "low"

    # Not matching 'under' root
    sev_other = evaluate_rules("index.html", "/tmp/index.html", "other", change, rules)
    assert sev_other == "medium"  # default for 'modified'


def test_default_kind_severities():
    rules = []
    assert evaluate_rules("f", "/f", "r", Change(kinds=["created"]), rules) == "info"
    assert evaluate_rules("f", "/f", "r", Change(kinds=["modified"]), rules) == "medium"
    assert evaluate_rules("f", "/f", "r", Change(kinds=["deleted"]), rules) == "high"
    assert evaluate_rules("f", "/f", "r", Change(kinds=["permissions"]), rules) == "high"
    assert evaluate_rules("f", "/f", "r", Change(kinds=["owner"]), rules) == "high"

    # Multi-kind takes higher severity
    assert evaluate_rules("f", "/f", "r", Change(kinds=["created", "permissions"]), rules) == "high"


def test_behavioral_escalation_rules():
    # DECOY -> critical
    assert escalate_with_signals("info", ["DECOY"]) == "critical"

    # SPEED + ENTROPY -> critical
    assert escalate_with_signals("low", ["SPEED", "ENTROPY"]) == "critical"

    # SLOW_SUSPICION -> critical
    assert escalate_with_signals("medium", ["SLOW_SUSPICION"]) == "critical"

    # SPEED alone -> high
    assert escalate_with_signals("low", ["SPEED"]) == "high"

    # SUSTAINED alone -> high
    assert escalate_with_signals("info", ["SUSTAINED"]) == "high"


def test_never_lowers_severity():
    # If base is already critical, SPEED alone does not lower to high
    assert escalate_with_signals("critical", ["SPEED"]) == "critical"
    assert escalate_with_signals("critical", []) == "critical"

    assert higher_severity("critical", "low") == "critical"
    assert higher_severity("medium", "high") == "high"
    assert higher_severity("info", "info") == "info"
