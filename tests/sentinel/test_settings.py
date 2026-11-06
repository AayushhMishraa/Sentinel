"""Tests for Sentinel configuration and settings loader."""

import os
import pytest
from sentinel.settings import load_settings, load_settings_dict, ConfigError, SentinelConfig


def test_load_example_yaml():
    cfg = load_settings("sentinel.example.yaml")
    assert isinstance(cfg, SentinelConfig)
    assert len(cfg.paths) == 3
    assert len(cfg.rules) == 6
    assert cfg.paths[0].id == "ssh"
    assert cfg.paths[0].mode == "monitor"
    assert cfg.paths[0].capture_content is True
    assert cfg.paths[2].id == "docs"
    assert cfg.paths[2].mode == "protect"
    assert len(cfg.notify.webhooks) == 1


def test_tilde_expansion_for_paths():
    data = {
        "paths": [{"id": "home", "path": "~/test_folder", "mode": "monitor"}]
    }
    cfg = load_settings_dict(data)
    assert cfg.paths[0].resolved_path.startswith("/")
    assert not cfg.paths[0].resolved_path.startswith("~")


def test_plain_english_error_missing_file():
    with pytest.raises(ConfigError) as exc:
        load_settings("/non/existent/path/sentinel.yaml")
    assert exc.value.key == "file"
    assert "Configuration file not found" in str(exc.value)


def test_plain_english_error_bad_mode():
    data = {
        "paths": [{"id": "bad", "path": "/tmp", "mode": "destroy"}]
    }
    with pytest.raises(ConfigError) as exc:
        load_settings_dict(data)
    assert exc.value.key == "paths[0].mode"
    assert "Invalid mode 'destroy'" in str(exc.value)


def test_plain_english_error_bad_severity():
    data = {
        "rules": [{"match": "*.py", "severity": "super_critical"}]
    }
    with pytest.raises(ConfigError) as exc:
        load_settings_dict(data)
    assert exc.value.key == "rules[0].severity"
    assert "Invalid severity 'super_critical'" in str(exc.value)


def test_token_retrieval_from_env(monkeypatch):
    monkeypatch.setenv("TEST_TOKEN_VAR", "secret-agent-token")
    data = {
        "server": {"url": "http://localhost:5000", "token_env": "TEST_TOKEN_VAR"}
    }
    cfg = load_settings_dict(data)
    assert cfg.server.get_token() == "secret-agent-token"


def test_duplicate_path_ids_rejected():
    data = {
        "paths": [
            {"id": "duplicate", "path": "/tmp/a"},
            {"id": "duplicate", "path": "/tmp/b"}
        ]
    }
    with pytest.raises(ConfigError) as exc:
        load_settings_dict(data)
    assert exc.value.key == "paths[1].id"
    assert "Duplicate path id" in str(exc.value)
