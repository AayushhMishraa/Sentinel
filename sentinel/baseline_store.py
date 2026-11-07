"""Persistent baseline storage and builder for Sentinel.

Records file metadata (sha256, size, permissions, uid, gid, mtime, entropy, content)
into an agent-side SQLite database. Supports hidden files (G1), glob exclusion,
caps on file count and hash size, and strict deny list enforcement for sensitive secrets.
"""

from __future__ import annotations

import fnmatch
import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple

from detection.entropy_checker import calculate_entropy
from recovery.manifest import sha256_file

# Strictly denied from ever capturing file text/content
SENSITIVE_CONTENT_DENY_PATTERNS = {
    "*/shadow", "*/gshadow", "*id_rsa*", "*id_ed25519*", "*id_ecdsa*",
    "*.pem", "*.key", "*_rsa", "*_ed25519", "*/etc/shadow", "*/etc/gshadow"
}
MAX_CAPTURE_CONTENT_BYTES = 65536  # 64 KB limit


@dataclass
class BaselineEntry:
    root_id: str
    relpath: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    mtime_ns: int
    entropy: float
    content: Optional[str] = None
    partial_hash: bool = False
    updated_at: float = 0.0


def is_sensitive_content(relpath: str, abspath: str) -> bool:
    """Return True if path matches sensitive secret/key file patterns."""
    basename = os.path.basename(abspath)
    for pat in SENSITIVE_CONTENT_DENY_PATTERNS:
        if fnmatch.fnmatch(basename, pat) or fnmatch.fnmatch(relpath, pat) or fnmatch.fnmatch(abspath, pat):
            return True
    return False


def _path_matches_any(relpath: str, patterns: Iterable[str]) -> bool:
    """Check if relative path matches any glob pattern."""
    parts = relpath.replace("\\", "/").strip("/").split("/")
    norm_rel = "/".join(parts)
    for pat in patterns:
        norm_pat = pat.replace("\\", "/").strip("/")
        if fnmatch.fnmatch(norm_rel, norm_pat) or fnmatch.fnmatch(os.path.basename(norm_rel), norm_pat):
            return True
        if norm_pat.endswith("/**"):
            prefix = norm_pat[:-3]
            if norm_rel == prefix or norm_rel.startswith(prefix + "/"):
                return True
    return False


def hash_file_capped(abspath: str, max_bytes: int) -> Tuple[str, bool]:
    """Calculate SHA256. If larger than max_bytes, hash first max_bytes and flag as partial."""
    try:
        size = os.path.getsize(abspath)
    except OSError:
        return "", False

    if size <= max_bytes:
        return sha256_file(abspath), False

    # Partial hash
    import hashlib
    h = hashlib.sha256()
    try:
        with open(abspath, "rb") as f:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(remaining, 65536))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest(), True
    except OSError:
        return "", False


class BaselineStore:
    """Agent-side SQLite database storing the baseline file state for watched paths."""

    def __init__(self, db_path: str) -> None:
        self.db_path = os.path.abspath(os.path.expanduser(db_path))
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        # Secure file permissions (0600)
        parent = os.path.dirname(self.db_path)
        if os.path.exists(parent):
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass

        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baseline (
                    root_id TEXT NOT NULL,
                    relpath TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mode INTEGER NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    entropy REAL NOT NULL,
                    content TEXT,
                    partial_hash INTEGER DEFAULT 0,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (root_id, relpath)
                )
            """)
            conn.commit()

        if os.path.exists(self.db_path):
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass

    def get_entry(self, root_id: str, relpath: str) -> Optional[BaselineEntry]:
        norm_rel = relpath.replace("\\", "/").strip("/")
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM baseline WHERE root_id = ? AND relpath = ?",
                (root_id, norm_rel)
            ).fetchone()
            if not row:
                return None
            return BaselineEntry(
                root_id=row["root_id"],
                relpath=row["relpath"],
                sha256=row["sha256"],
                size=row["size"],
                mode=row["mode"],
                uid=row["uid"],
                gid=row["gid"],
                mtime_ns=row["mtime_ns"],
                entropy=row["entropy"],
                content=row["content"],
                partial_hash=bool(row["partial_hash"]),
                updated_at=row["updated_at"],
            )

    def get_all_entries(self, root_id: str) -> Dict[str, BaselineEntry]:
        entries: Dict[str, BaselineEntry] = {}
        with self._get_connection() as conn:
            for row in conn.execute("SELECT * FROM baseline WHERE root_id = ?", (root_id,)):
                entries[row["relpath"]] = BaselineEntry(
                    root_id=row["root_id"],
                    relpath=row["relpath"],
                    sha256=row["sha256"],
                    size=row["size"],
                    mode=row["mode"],
                    uid=row["uid"],
                    gid=row["gid"],
                    mtime_ns=row["mtime_ns"],
                    entropy=row["entropy"],
                    content=row["content"],
                    partial_hash=bool(row["partial_hash"]),
                    updated_at=row["updated_at"],
                )
        return entries

    def list_entries(self, root_id: str) -> List[BaselineEntry]:
        return list(self.get_all_entries(root_id).values())

    def set_entry(self, entry: BaselineEntry) -> None:
        norm_rel = entry.relpath.replace("\\", "/").strip("/")
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO baseline
                (root_id, relpath, sha256, size, mode, uid, gid, mtime_ns, entropy, content, partial_hash, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.root_id,
                norm_rel,
                entry.sha256,
                entry.size,
                entry.mode,
                entry.uid,
                entry.gid,
                entry.mtime_ns,
                entry.entropy,
                entry.content,
                1 if entry.partial_hash else 0,
                entry.updated_at or time.time(),
            ))
            conn.commit()

    def remove_entry(self, root_id: str, relpath: str) -> bool:
        norm_rel = relpath.replace("\\", "/").strip("/")
        with self._get_connection() as conn:
            cur = conn.execute(
                "DELETE FROM baseline WHERE root_id = ? AND relpath = ?",
                (root_id, norm_rel)
            )
            conn.commit()
            return cur.rowcount > 0

    def clear_root(self, root_id: str) -> int:
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM baseline WHERE root_id = ?", (root_id,))
            conn.commit()
            return cur.rowcount


def inspect_file(
    root_id: str,
    root_path: str,
    relpath: str,
    max_hash_bytes: int,
    capture_content: bool
) -> Optional[BaselineEntry]:
    """Inspect a single real file and build its BaselineEntry."""
    norm_rel = relpath.replace("\\", "/").strip("/")
    abspath = os.path.join(root_path, norm_rel)

    try:
        st = os.lstat(abspath)
    except OSError:
        return None

    # Never follow symlinks outside or monitor symlinks themselves as regular files
    if stat.S_ISLNK(st.st_mode):
        return None
    if not stat.S_ISREG(st.st_mode):
        return None

    sha, partial = hash_file_capped(abspath, max_hash_bytes)
    try:
        entropy = calculate_entropy(abspath)
    except Exception:
        entropy = 0.0

    captured_text: Optional[str] = None
    if capture_content and not is_sensitive_content(norm_rel, abspath):
        if st.st_size <= MAX_CAPTURE_CONTENT_BYTES:
            try:
                with open(abspath, "r", encoding="utf-8", errors="replace") as f:
                    captured_text = f.read()
            except Exception:
                captured_text = None

    return BaselineEntry(
        root_id=root_id,
        relpath=norm_rel,
        sha256=sha,
        size=st.st_size,
        mode=st.st_mode,
        uid=st.st_uid,
        gid=st.st_gid,
        mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)),
        entropy=entropy,
        content=captured_text,
        partial_hash=partial,
        updated_at=time.time(),
    )


def scan_and_save_baseline(
    store: BaselineStore,
    root_id: str,
    root_path: str,
    *,
    includes: Optional[List[str]] = None,
    excludes: Optional[List[str]] = None,
    max_files: int = 50000,
    max_hash_bytes: int = 104857600,
    capture_content: bool = False,
    ignore_hidden: bool = False,
) -> int:
    """Scan root_path and store all valid files in the baseline. Returns count saved."""
    root_path = os.path.abspath(os.path.expanduser(root_path))
    if not os.path.isdir(root_path):
        return 0

    excludes = list(excludes or [])
    includes = list(includes or [])
    count = 0

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root_path).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""

        # Filter directories
        kept_dirs = []
        for d in dirnames:
            if ignore_hidden and d.startswith("."):
                continue
            child_rel = f"{rel_dir}/{d}".strip("/")
            if _path_matches_any(child_rel, excludes):
                continue
            kept_dirs.append(d)
        dirnames[:] = kept_dirs

        for f in filenames:
            if ignore_hidden and f.startswith("."):
                continue
            child_rel = f"{rel_dir}/{f}".strip("/")
            if excludes and _path_matches_any(child_rel, excludes):
                continue
            if includes and not _path_matches_any(child_rel, includes):
                continue

            entry = inspect_file(root_id, root_path, child_rel, max_hash_bytes, capture_content)
            if entry:
                store.set_entry(entry)
                count += 1
                if count >= max_files:
                    return count

    return count

