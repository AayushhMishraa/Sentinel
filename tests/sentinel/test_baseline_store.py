"""Tests for BaselineStore and scan_and_save_baseline."""

import os
import stat
import pytest
from sentinel.baseline_store import (
    BaselineStore,
    BaselineEntry,
    scan_and_save_baseline,
    inspect_file,
    is_sensitive_content,
)


def test_baseline_store_round_trip(tmp_path):
    db_file = tmp_path / "baseline.db"
    store = BaselineStore(str(db_file))

    entry = BaselineEntry(
        root_id="test_root",
        relpath="sub/config.txt",
        sha256="abc123hash",
        size=42,
        mode=0o100644,
        uid=1000,
        gid=1000,
        mtime_ns=123456789,
        entropy=4.5,
        content="hello=world\n",
        partial_hash=False,
    )
    store.set_entry(entry)

    loaded = store.get_entry("test_root", "sub/config.txt")
    assert loaded is not None
    assert loaded.relpath == "sub/config.txt"
    assert loaded.sha256 == "abc123hash"
    assert loaded.content == "hello=world\n"
    assert loaded.size == 42

    all_entries = store.get_all_entries("test_root")
    assert "sub/config.txt" in all_entries
    assert len(all_entries) == 1

    assert store.remove_entry("test_root", "sub/config.txt") is True
    assert store.get_entry("test_root", "sub/config.txt") is None


def test_baseline_excludes_and_hidden_files(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    (root / ".ssh").mkdir()
    (root / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAAC3 test")
    (root / "regular.txt").write_text("plain text")
    (root / "cache").mkdir()
    (root / "cache" / "temp.tmp").write_text("temporary")

    db_file = tmp_path / "baseline.db"
    store = BaselineStore(str(db_file))

    # G1: hidden files allowed when ignore_hidden=False (default for Sentinel)
    count = scan_and_save_baseline(
        store,
        "root1",
        str(root),
        excludes=["cache/**", "*.tmp"],
        ignore_hidden=False,
    )

    assert count == 2
    entries = store.get_all_entries("root1")
    assert ".ssh/authorized_keys" in entries
    assert "regular.txt" in entries
    assert "cache/temp.tmp" not in entries


def test_symlink_ignored(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    real_target = tmp_path / "outside.txt"
    real_target.write_text("outside secrets")
    (root / "link_outside").symlink_to(real_target)

    db_file = tmp_path / "baseline.db"
    store = BaselineStore(str(db_file))

    count = scan_and_save_baseline(store, "r", str(root), ignore_hidden=False)
    assert count == 0
    assert store.get_all_entries("r") == {}


def test_sensitive_content_deny_list(tmp_path):
    assert is_sensitive_content("etc/shadow", "/etc/shadow") is True
    assert is_sensitive_content(".ssh/id_rsa", "/home/user/.ssh/id_rsa") is True
    assert is_sensitive_content("cert.pem", "/app/cert.pem") is True
    assert is_sensitive_content("normal.txt", "/app/normal.txt") is False

    root = tmp_path / "secrets"
    root.mkdir()
    key_file = root / "id_rsa"
    key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...")

    db_file = tmp_path / "baseline.db"
    store = BaselineStore(str(db_file))

    scan_and_save_baseline(
        store,
        "sec",
        str(root),
        capture_content=True,
        ignore_hidden=False,
    )
    entry = store.get_entry("sec", "id_rsa")
    assert entry is not None
    # Fingerprint must be recorded, but content must NEVER be saved
    assert entry.sha256 != ""
    assert entry.content is None


def test_db_permissions_secured(tmp_path):
    db_file = tmp_path / "baseline_dir" / "secure.db"
    store = BaselineStore(str(db_file))
    mode = stat.S_IMODE(os.stat(str(db_file)).st_mode)
    assert mode == 0o600
