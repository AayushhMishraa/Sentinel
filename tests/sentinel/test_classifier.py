"""Tests for Sentinel models and Change classifier."""

import os
import stat
import pytest
from sentinel.models import Meta, Change, EventEnvelope, Alert
from sentinel.baseline_store import BaselineEntry
from sentinel.classifier import classify_file_change, generate_text_diff


def test_models_serialization_round_trip():
    meta = Meta(sha256="1234", size=10, mode=0o644, uid=1000, gid=1000, mtime_ns=100, entropy=3.2)
    change = Change(kinds=["modified"], old=meta, new=meta, diff="--- a\n+++ b\n")
    envelope = EventEnvelope(
        root_id="ssh",
        path="/home/user/.ssh/authorized_keys",
        host_id="box-1",
        ts=1700000000.0,
        change=change,
        signals=["DECOY"],
        severity="critical",
        summary="Key modified",
    )

    json_str = envelope.to_json()
    reconstructed = EventEnvelope.from_json(json_str)

    assert reconstructed.schema_version == 1
    assert reconstructed.host_id == "box-1"
    assert reconstructed.change.kinds == ["modified"]
    assert reconstructed.change.old.sha256 == "1234"
    assert reconstructed.signals == ["DECOY"]
    assert reconstructed.severity == "critical"


def test_classify_created_file(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    new_f = root / "new.txt"
    new_f.write_text("hello new world\n")

    change = classify_file_change(
        root_id="r1",
        root_path=str(root),
        relpath="new.txt",
        baseline_entry=None,
        capture_content=True,
    )

    assert change is not None
    assert change.kinds == ["created"]
    assert change.old is None
    assert change.new is not None
    assert change.new.size == len("hello new world\n")
    assert "+hello new world" in (change.diff or "")


def test_classify_deleted_file(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()

    base_entry = BaselineEntry(
        root_id="r1",
        relpath="old.txt",
        sha256="hash123",
        size=15,
        mode=0o100644,
        uid=1000,
        gid=1000,
        mtime_ns=1000,
        entropy=2.0,
        content="line1\nline2\n",
    )

    change = classify_file_change(
        root_id="r1",
        root_path=str(root),
        relpath="old.txt",
        baseline_entry=base_entry,
    )

    assert change is not None
    assert change.kinds == ["deleted"]
    assert change.old is not None
    assert change.new is None
    assert "-line1" in (change.diff or "")


def test_classify_modified_and_permissions(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    f = root / "test.txt"
    f.write_text("after edit\n")
    os.chmod(f, 0o777)

    base_entry = BaselineEntry(
        root_id="r1",
        relpath="test.txt",
        sha256="different_hash",
        size=10,
        mode=0o100644,
        uid=os.getuid(),
        gid=os.getgid(),
        mtime_ns=1000,
        entropy=2.0,
        content="before edit\n",
    )

    change = classify_file_change(
        root_id="r1",
        root_path=str(root),
        relpath="test.txt",
        baseline_entry=base_entry,
        capture_content=True,
    )

    assert change is not None
    assert set(change.kinds) == {"modified", "permissions"}
    assert "-before edit" in (change.diff or "")
    assert "+after edit" in (change.diff or "")


def test_classify_touch_only_ignored(tmp_path):
    root = tmp_path / "monitored"
    root.mkdir()
    f = root / "untouched.txt"
    f.write_text("same content")

    st = os.stat(f)
    base_entry = BaselineEntry(
        root_id="r1",
        relpath="untouched.txt",
        sha256=hash_file(str(f)),
        size=st.st_size,
        mode=st.st_mode,
        uid=st.st_uid,
        gid=st.st_gid,
        mtime_ns=st.st_mtime_ns,
        entropy=1.0,
        content="same content",
    )

    # Touch mtime
    os.utime(f, (st.st_atime + 10, st.st_mtime + 10))

    change = classify_file_change(
        root_id="r1",
        root_path=str(root),
        relpath="untouched.txt",
        baseline_entry=base_entry,
    )

    assert change is None


def test_diff_truncation():
    old_lines = "\n".join([f"line {i}" for i in range(300)])
    new_lines = "\n".join([f"line {i} changed" for i in range(300)])
    diff_text, truncated = generate_text_diff(old_lines, new_lines, "large.txt")
    assert diff_text is not None
    assert truncated is True
    assert "... [diff truncated for length] ..." in diff_text


def hash_file(path):
    import hashlib
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()
