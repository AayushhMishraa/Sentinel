"""Change classifier and diff engine.

Compares file events against the baseline store to identify all applicable change kinds
(created, modified, deleted, permissions, owner) and generate contextual diffs.
"""

from __future__ import annotations

import difflib
import os
import stat
from typing import List, Optional, Tuple

from core.events import FileEvent
from sentinel.baseline_store import (
    BaselineEntry,
    BaselineStore,
    hash_file_capped,
    inspect_file,
    is_sensitive_content,
    MAX_CAPTURE_CONTENT_BYTES,
)
from sentinel.models import Change, Meta

MAX_DIFF_LINES = 200
MAX_DIFF_BYTES = 32768


def generate_text_diff(
    old_text: Optional[str],
    new_text: Optional[str],
    filename: str
) -> Tuple[Optional[str], bool]:
    """Generate a unified diff between old and new text.

    Returns (diff_string, is_truncated).
    """
    if old_text is None and new_text is None:
        return None, False

    old_lines = (old_text or "").splitlines(keepends=True)
    new_lines = (new_text or "").splitlines(keepends=True)

    diff = list(difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        n=3
    ))
    if not diff:
        return None, False

    full_diff = "".join(diff)
    truncated = False

    if len(diff) > MAX_DIFF_LINES or len(full_diff.encode("utf-8", "replace")) > MAX_DIFF_BYTES:
        truncated = True
        kept = diff[:MAX_DIFF_LINES]
        full_diff = "".join(kept) + "\n... [diff truncated for length] ...\n"

    return full_diff, truncated


def classify_file_change(
    root_id: str,
    root_path: str,
    relpath: str,
    baseline_entry: Optional[BaselineEntry],
    max_hash_bytes: int = 104857600,
    capture_content: bool = False,
    initial_mode: Optional[int] = None,
    events: Optional[List[FileEvent]] = None,
) -> Optional[Change]:
    """Compare real file at root_path/relpath against baseline_entry.

    Returns Change object, or None if no material change occurred (e.g. mtime touch only).
    """
    norm_rel = relpath.replace("\\", "/").strip("/")
    abspath = os.path.join(root_path, norm_rel)

    exists_now = os.path.exists(abspath)
    is_symlink = os.path.islink(abspath)

    # 1. File does not exist now
    if not exists_now or is_symlink:
        if baseline_entry is None:
            return None  # Wasn't in baseline, doesn't exist now -> ignore
        # Was in baseline, now deleted
        old_meta = Meta(
            sha256=baseline_entry.sha256,
            size=baseline_entry.size,
            mode=baseline_entry.mode,
            uid=baseline_entry.uid,
            gid=baseline_entry.gid,
            mtime_ns=baseline_entry.mtime_ns,
            entropy=baseline_entry.entropy,
        )
        diff_text = None
        diff_truncated = False
        if baseline_entry.content is not None:
            diff_text, diff_truncated = generate_text_diff(
                baseline_entry.content, "", os.path.basename(norm_rel)
            )
        return Change(
            kinds=["deleted"],
            old=old_meta,
            new=None,
            diff=diff_text,
            diff_truncated=diff_truncated,
        )

    # 2. File exists now
    try:
        current_entry = inspect_file(root_id, root_path, norm_rel, max_hash_bytes, capture_content)
    except OSError:
        return None

    if current_entry is None:
        return None

    new_meta = Meta(
        sha256=current_entry.sha256,
        size=current_entry.size,
        mode=current_entry.mode,
        uid=current_entry.uid,
        gid=current_entry.gid,
        mtime_ns=current_entry.mtime_ns,
        entropy=current_entry.entropy,
    )

    # 3. Newly created file (not in baseline)
    if baseline_entry is None:
        diff_text = None
        diff_truncated = False
        if current_entry.content is not None:
            diff_text, diff_truncated = generate_text_diff(
                "", current_entry.content, os.path.basename(norm_rel)
            )

        kinds = ["created"]
        file_mode = stat.S_IMODE(current_entry.mode)

        # Check for permission changes during creation / debounce window
        has_permission_change = False
        if initial_mode is not None and stat.S_IMODE(initial_mode) != file_mode:
            has_permission_change = True
        elif events and len(events) > 1:
            saw_create = False
            for ev in events:
                if ev.event_type == "created":
                    saw_create = True
                elif saw_create and ev.event_type in ("modified", "permissions", "attrib"):
                    if (file_mode & 0o111) != 0 or file_mode == 0o777:
                        has_permission_change = True
                        break
        elif (file_mode & 0o111) != 0 or file_mode == 0o777:
            has_permission_change = True

        if has_permission_change and "permissions" not in kinds:
            kinds.append("permissions")

        return Change(
            kinds=kinds,
            old=None,
            new=new_meta,
            diff=diff_text,
            diff_truncated=diff_truncated,
        )

    # 4. File in baseline: compare attributes
    old_meta = Meta(
        sha256=baseline_entry.sha256,
        size=baseline_entry.size,
        mode=baseline_entry.mode,
        uid=baseline_entry.uid,
        gid=baseline_entry.gid,
        mtime_ns=baseline_entry.mtime_ns,
        entropy=baseline_entry.entropy,
    )

    kinds: List[str] = []

    # Content change
    if current_entry.sha256 != baseline_entry.sha256:
        kinds.append("modified")

    # Permissions change (st_mode bits)
    if stat.S_IMODE(current_entry.mode) != stat.S_IMODE(baseline_entry.mode):
        kinds.append("permissions")

    # Owner change (uid or gid)
    if current_entry.uid != baseline_entry.uid or current_entry.gid != baseline_entry.gid:
        kinds.append("owner")

    if not kinds:
        # If modification events were captured before protect mode auto-restore reverted
        # the file back to baseline, record modified so behavioral alerts are preserved
        if events and any(ev.event_type in ("modified", "created") for ev in events):
            kinds.append("modified")
        else:
            # Only mtime or atime changed, content and permissions identical
            return None

    diff_text = None
    diff_truncated = False
    if "modified" in kinds:
        # Attempt text diff if content is available
        old_c = baseline_entry.content
        new_c = current_entry.content
        if old_c is not None or new_c is not None:
            diff_text, diff_truncated = generate_text_diff(
                old_c or "", new_c or "", os.path.basename(norm_rel)
            )

    return Change(
        kinds=kinds,
        old=old_meta,
        new=new_meta,
        diff=diff_text,
        diff_truncated=diff_truncated,
    )

