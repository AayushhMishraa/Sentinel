"""Sentinel settings loader and validator.

Loads configuration from YAML data or file with plain-English error messages
pinpointing the exact problematic key.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import yaml

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_MODES = {"monitor", "protect"}


class ConfigError(ValueError):
    """Raised when configuration is missing or invalid, with offending key."""

    def __init__(self, key: str, message: str) -> None:
        self.key = key
        self.message = message
        super().__init__(f"Configuration error at '{key}': {message}")


@dataclass
class ServerSettings:
    url: str = "http://127.0.0.1:5000"
    token_env: str = "SENTINEL_TOKEN"
    token_file: Optional[str] = None
    token_val: Optional[str] = None

    def get_token(self) -> Optional[str]:
        if self.token_val is not None:
            return self.token_val
        if self.token_env and os.environ.get(self.token_env):
            return os.environ[self.token_env]
        if self.token_file and os.path.isfile(self.token_file):
            try:
                with open(self.token_file, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except OSError:
                return None
        return None


@dataclass
class DefaultsSettings:
    exclude: List[str] = field(default_factory=lambda: [
        ".git/**", "node_modules/**", "__pycache__/**", "*.swp", "*.tmp"
    ])
    new_file_severity: str = "info"
    max_files: int = 50000
    max_hash_bytes: int = 104857600  # 100 MB


@dataclass
class PathSettings:
    id: str
    path: str
    mode: str = "monitor"
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    decoys: bool = False
    capture_content: bool = False
    max_files: Optional[int] = None

    @property
    def resolved_path(self) -> str:
        return os.path.abspath(os.path.expanduser(self.path))


@dataclass
class RuleSettings:
    match: str
    severity: str
    under: Optional[str] = None
    reason: Optional[str] = None


@dataclass
class WebhookSettings:
    url: str
    min_severity: str = "high"


@dataclass
class NotifySettings:
    webhooks: List[WebhookSettings] = field(default_factory=list)


@dataclass
class SentinelConfig:
    host_id: str
    server: ServerSettings
    defaults: DefaultsSettings
    paths: List[PathSettings]
    rules: List[RuleSettings]
    notify: NotifySettings


def _validate_severity(sev: Any, key_name: str) -> str:
    if not isinstance(sev, str) or sev.lower() not in VALID_SEVERITIES:
        raise ConfigError(
            key_name,
            f"Invalid severity '{sev}'. Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )
    return sev.lower()


def load_settings_dict(data: Any) -> SentinelConfig:
    """Validate and parse configuration dictionary."""
    if not isinstance(data, dict):
        raise ConfigError("root", "Configuration file must contain a YAML mapping/dictionary.")

    # 1. host_id
    raw_host_id = data.get("host_id", "auto")
    if not isinstance(raw_host_id, str) or not raw_host_id.strip():
        raise ConfigError("host_id", "Must be a non-empty string or 'auto'.")
    host_id = socket.gethostname() if raw_host_id.strip().lower() == "auto" else raw_host_id.strip()

    # 2. server
    raw_server = data.get("server", {})
    if not isinstance(raw_server, dict):
        raise ConfigError("server", "Must be a dictionary containing server settings.")
    server_settings = ServerSettings(
        url=str(raw_server.get("url", "http://127.0.0.1:5000")),
        token_env=str(raw_server.get("token_env", "SENTINEL_TOKEN")),
        token_file=str(raw_server.get("token_file")) if raw_server.get("token_file") else None,
        token_val=str(raw_server.get("token")) if raw_server.get("token") else None,
    )

    # 3. defaults
    raw_defaults = data.get("defaults", {})
    if not isinstance(raw_defaults, dict):
        raise ConfigError("defaults", "Must be a dictionary containing default options.")
    defaults = DefaultsSettings()
    if "exclude" in raw_defaults:
        if not isinstance(raw_defaults["exclude"], list):
            raise ConfigError("defaults.exclude", "Must be a list of glob patterns.")
        defaults.exclude = [str(x) for x in raw_defaults["exclude"]]
    if "new_file_severity" in raw_defaults:
        defaults.new_file_severity = _validate_severity(
            raw_defaults["new_file_severity"], "defaults.new_file_severity"
        )
    if "max_files" in raw_defaults:
        try:
            defaults.max_files = int(raw_defaults["max_files"])
            if defaults.max_files <= 0:
                raise ValueError
        except (ValueError, TypeError):
            raise ConfigError("defaults.max_files", "Must be a positive integer.")
    if "max_hash_bytes" in raw_defaults:
        try:
            defaults.max_hash_bytes = int(raw_defaults["max_hash_bytes"])
            if defaults.max_hash_bytes <= 0:
                raise ValueError
        except (ValueError, TypeError):
            raise ConfigError("defaults.max_hash_bytes", "Must be a positive integer.")

    # 4. paths
    raw_paths = data.get("paths", [])
    if not isinstance(raw_paths, list):
        raise ConfigError("paths", "Must be a list of monitored path entries.")

    parsed_paths: List[PathSettings] = []
    seen_ids = set()

    for idx, item in enumerate(raw_paths):
        key_pfx = f"paths[{idx}]"
        if not isinstance(item, dict):
            raise ConfigError(key_pfx, "Each path entry must be a dictionary.")

        path_id = item.get("id")
        if not path_id or not isinstance(path_id, str):
            raise ConfigError(f"{key_pfx}.id", "Path entry must have a unique non-empty string 'id'.")
        if path_id in seen_ids:
            raise ConfigError(f"{key_pfx}.id", f"Duplicate path id '{path_id}'. Each path id must be unique.")
        seen_ids.add(path_id)

        raw_path = item.get("path")
        if not raw_path or not isinstance(raw_path, str):
            raise ConfigError(f"{key_pfx}.path", "Path entry must specify a non-empty 'path'.")

        mode = str(item.get("mode", "monitor")).lower()
        if mode not in VALID_MODES:
            raise ConfigError(
                f"{key_pfx}.mode",
                f"Invalid mode '{mode}'. Must be one of: {', '.join(sorted(VALID_MODES))}"
            )

        includes = item.get("include", [])
        if not isinstance(includes, list):
            raise ConfigError(f"{key_pfx}.include", "Must be a list of glob patterns or file names.")

        excludes = item.get("exclude", defaults.exclude)
        if not isinstance(excludes, list):
            raise ConfigError(f"{key_pfx}.exclude", "Must be a list of glob patterns.")

        decoys = bool(item.get("decoys", False))
        capture_content = bool(item.get("capture_content", False))

        max_f = item.get("max_files")
        if max_f is not None:
            try:
                max_f = int(max_f)
                if max_f <= 0:
                    raise ValueError
            except (ValueError, TypeError):
                raise ConfigError(f"{key_pfx}.max_files", "Must be a positive integer.")

        parsed_paths.append(PathSettings(
            id=path_id,
            path=raw_path,
            mode=mode,
            include=[str(x) for x in includes],
            exclude=[str(x) for x in excludes],
            decoys=decoys,
            capture_content=capture_content,
            max_files=max_f,
        ))

    # 5. rules
    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ConfigError("rules", "Must be a list of rule definitions.")

    parsed_rules: List[RuleSettings] = []
    for idx, item in enumerate(raw_rules):
        key_pfx = f"rules[{idx}]"
        if not isinstance(item, dict):
            raise ConfigError(key_pfx, "Each rule entry must be a dictionary.")

        match_pat = item.get("match")
        if not match_pat or not isinstance(match_pat, str):
            raise ConfigError(f"{key_pfx}.match", "Rule entry must specify a 'match' pattern.")

        severity = _validate_severity(item.get("severity"), f"{key_pfx}.severity")
        under = str(item["under"]) if item.get("under") else None
        reason = str(item["reason"]) if item.get("reason") else None

        parsed_rules.append(RuleSettings(
            match=match_pat,
            severity=severity,
            under=under,
            reason=reason,
        ))

    # 6. notify
    raw_notify = data.get("notify", {})
    parsed_notify = NotifySettings()
    if isinstance(raw_notify, dict):
        raw_hooks = raw_notify.get("webhooks", [])
        if not isinstance(raw_hooks, list):
            raise ConfigError("notify.webhooks", "Must be a list of webhook definitions.")
        for idx, item in enumerate(raw_hooks):
            key_pfx = f"notify.webhooks[{idx}]"
            if not isinstance(item, dict) or not item.get("url"):
                raise ConfigError(f"{key_pfx}.url", "Webhook entry must have a valid 'url'.")
            url = str(item["url"])
            if not (url.startswith("http://") or url.startswith("https://")):
                raise ConfigError(f"{key_pfx}.url", "Webhook URL must start with http:// or https://")
            min_sev = item.get("min_severity", "high")
            min_sev = _validate_severity(min_sev, f"{key_pfx}.min_severity")
            parsed_notify.webhooks.append(WebhookSettings(url=url, min_severity=min_sev))

    return SentinelConfig(
        host_id=host_id,
        server=server_settings,
        defaults=defaults,
        paths=parsed_paths,
        rules=parsed_rules,
        notify=parsed_notify,
    )


def load_settings(path: str) -> SentinelConfig:
    """Load configuration from a YAML file path."""
    expanded = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(expanded):
        raise ConfigError("file", f"Configuration file not found at '{expanded}'")
    try:
        with open(expanded, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError("syntax", f"Failed to parse YAML: {e}")
    except OSError as e:
        raise ConfigError("file", f"Failed to read file: {e}")

    return load_settings_dict(data or {})
