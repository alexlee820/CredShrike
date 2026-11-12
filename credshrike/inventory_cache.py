"""Shared inventory cache: SMB enumeration + file reads persisted to SQLite.

Two purposes, one database at ``<audit_dir>/.cache/inventory.db``:

1. **Cross-run speedup** — re-sweeping the same lab skips domain-computer
   queries, share listings, directory walks and unchanged file reads.
2. **Resume support** — a restarted run reuses the same enumeration data
   (see ``runstate.py`` for the per-run progress manifest).

Only the three data-retrieval methods of :class:`SMBSession` are cached
(``list_shares`` / ``list_dir`` / ``read_file``). Permission probes
(``stat`` / ``get_security`` / ``effective_access``) deliberately stay live —
a cached ACL verdict would be actively misleading on a live target.

Freshness model:
- shares / dir listings / domain computers: TTL (``cache_ttl_hours``).
- file reads: valid indefinitely while the freshest cached parent listing
  still reports the same size and ``written`` mtime for the file; any change
  evicts that path's rows. Without listing metadata, reads fall back to TTL.

Thread model: one shared sqlite connection (``check_same_thread=False``)
behind an RLock, never held during network fetches, plus per-key single-flight
locks so 10 pool threads missing the same key fetch it once.
"""
from __future__ import annotations

import base64
import json
import os
import sqlite3
import threading
import time
from typing import Any, Optional

from .smb_session import DEFAULT_MAX_ENTRIES, DEFAULT_MAX_READ_BYTES, SMBSession

_SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS shares (
    host TEXT PRIMARY KEY,
    shares_json TEXT NOT NULL,
    fetched_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS dir_listings (
    host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL,
    max_entries INTEGER NOT NULL, truncated INTEGER NOT NULL,
    listing_json TEXT NOT NULL, fetched_at REAL NOT NULL,
    PRIMARY KEY (host, share, path));
CREATE TABLE IF NOT EXISTS file_reads (
    host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL,
    offset INTEGER NOT NULL, length INTEGER NOT NULL, truncated INTEGER NOT NULL,
    file_size INTEGER, mtime TEXT,
    content_b64 TEXT NOT NULL, fetched_at REAL NOT NULL,
    PRIMARY KEY (host, share, path, offset));
CREATE TABLE IF NOT EXISTS domain_computers (
    cache_key TEXT PRIMARY KEY,
    computers_json TEXT NOT NULL, fetched_at REAL NOT NULL);
"""


def norm_share(name: str) -> str:
    """SMB share names are case-insensitive — one canonical key per share."""
    return (name or "").strip().lower()


def norm_path(path: str) -> str:
    """Canonical path key. Deliberately identical to ``_norm()`` in
    stream_analysis.py so ShareLedger verdict keys and cache keys agree —
    a mismatch would silently re-read/re-analyze everything after resume."""
    return (path or "").lower().replace("\\", "/").strip("/")


def sanitize_name(name: str, cap: int = 64) -> str:
    """Filesystem-safe single path component (audit.py filename policy)."""
    import re
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:cap] or "_"


class InventoryCache:
    """SQLite-backed enumeration cache. Thread-safe; fetch callbacks are
    invoked OUTSIDE the db lock."""

    def __init__(self, db_path: str, *, ttl_seconds: float,
                 cache_content: bool = True):
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.db_path = db_path
        self.ttl_seconds = float(ttl_seconds)
        self.cache_content = bool(cache_content)
        self._lock = threading.RLock()
        self._key_locks: dict[tuple, threading.Lock] = {}
        self._hits = 0
        self._misses = 0
        self._stale_evictions = 0
        self._bytes_served = 0
        self._bytes_written = 0
        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.executescript(_DDL)
        self._db.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)",
                         (str(_SCHEMA_VERSION),))
        self._db.commit()

    # -- construction ------------------------------------------------------ #
    @classmethod
    def open(cls, audit_dir: str, policy) -> Optional["InventoryCache"]:
        """Build from a Policy; returns None when caching is disabled (the
        complete-bypass contract: no db file is even touched)."""
        if not getattr(policy, "inventory_cache", True):
            return None
        db_path = os.path.join(audit_dir, ".cache", "inventory.db")
        return cls(db_path,
                   ttl_seconds=float(getattr(policy, "cache_ttl_hours", 24)) * 3600.0,
                   cache_content=bool(getattr(policy, "cache_content", True)))

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            except sqlite3.Error:
                pass

    def wipe(self) -> None:
        """Drop every cached row (--refresh)."""
        with self._lock:
            for table in ("shares", "dir_listings", "file_reads", "domain_computers"):
                self._db.execute(f"DELETE FROM {table}")
            self._db.commit()

    def stats(self) -> dict:
        with self._lock:
            return {"hits": self._hits, "misses": self._misses,
                    "stale_evictions": self._stale_evictions,
                    "bytes_served": self._bytes_served,
                    "bytes_written": self._bytes_written,
                    "db_path": self.db_path}

    # -- single-flight ------------------------------------------------------ #
    def _key_lock(self, key: tuple) -> threading.Lock:
        with self._lock:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    def _fetch_once(self, key: tuple, fetch):
        """Run ``fetch`` at most once for ``key`` across threads (double-checked
        locking; the fetch itself runs without any cache lock held)."""
        lock = self._key_lock(key)
        with lock:
            return fetch()

    def _count(self, hit: bool, served: int = 0, written: int = 0) -> None:
        with self._lock:
            if hit:
                self._hits += 1
            else:
                self._misses += 1
            self._bytes_served += served
            self._bytes_written += written

    def _written(self, n: int) -> None:
        with self._lock:
            self._bytes_written += n

    def _fresh(self, fetched_at: float) -> bool:
        return (time.time() - fetched_at) <= self.ttl_seconds

    # -- shares ------------------------------------------------------------- #
    def get_shares(self, host: str) -> Optional[list]:
        with self._lock:
            row = self._db.execute(
                "SELECT shares_json, fetched_at FROM shares WHERE host = ?",
                (host,)).fetchone()
        if row and self._fresh(row[1]):
            self._count(True)
            return json.loads(row[0])
        self._count(False)
        return None

    def put_shares(self, host: str, shares: list) -> None:
        payload = json.dumps(shares)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO shares (host, shares_json, fetched_at) "
                "VALUES (?, ?, ?)", (host, payload, time.time()))
            self._db.commit()
        self._written(0)

    # -- dir listings -------------------------------------------------------- #
    def get_listing(self, host: str, share: str, path: str,
                    max_entries: int) -> Optional[dict]:
        key = (host, norm_share(share), norm_path(path))
        hit = self._get_listing_row(key, max_entries)
        if hit is not None:
            self._count(True)
            listing = json.loads(hit)
            # echo the caller's spelling, not the first caller's
            listing = dict(listing, share=share, path=path or "")
            return listing
        self._count(False)
        return None

    def _get_listing_row(self, key: tuple, max_entries: int) -> Optional[str]:
        with self._lock:
            row = self._db.execute(
                "SELECT max_entries, truncated, listing_json, fetched_at "
                "FROM dir_listings WHERE host=? AND share=? AND path=?",
                key).fetchone()
        if not row or not self._fresh(row[3]):
            return None
        cached_max, cached_trunc, payload = row[0], row[1], row[2]
        # a complete listing serves any smaller cap; a truncated one only
        # serves the identical cap (preserving the truncation contract)
        if cached_trunc and max_entries != cached_max:
            return None
        if not cached_trunc and max_entries > cached_max:
            return None
        return payload

    def put_listing(self, host: str, share: str, path: str, max_entries: int,
                    listing: dict) -> None:
        payload = json.dumps(listing)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO dir_listings "
                "(host, share, path, max_entries, truncated, listing_json, fetched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host, norm_share(share), norm_path(path), int(max_entries),
                 1 if listing.get("truncated") else 0, payload, time.time()))
            self._db.commit()
        self._written(0)

    # -- file metadata (from the freshest cached parent listing) ------------- #
    def _file_meta(self, host: str, share: str, path: str) -> Optional[tuple]:
        """(size, written) for ``path`` from the cached listing of its parent
        directory, or None when no fresh listing knows this file."""
        p = norm_path(path)
        parent, _, name = p.rpartition("/")
        with self._lock:
            row = self._db.execute(
                "SELECT listing_json, fetched_at FROM dir_listings "
                "WHERE host=? AND share=? AND path=?",
                (host, norm_share(share), parent)).fetchone()
        if not row or not self._fresh(row[1]):
            return None
        for entry in json.loads(row[0]).get("entries", []):
            if (entry.get("name") or "").lower() == name:
                return entry.get("size"), entry.get("written")
        return None

    # -- file reads (range-cover) --------------------------------------------- #
    def get_read(self, host: str, share: str, path: str, offset: int,
                 max_bytes: int) -> Optional[dict]:
        """Serve ``[offset, offset+max_bytes)`` from a cached row that covers it.

        Cover rules: the row must start at or before ``offset``; a truncated
        row (read hit the cap) covers exactly up to ``offset+length``; an
        EOF row (``truncated=0``) covers anything up to end-of-file, so a
        request reaching past EOF returns a short slice — the same shape a
        live read of the tail produces. Validity: size/mtime from the
        freshest parent listing when known (evict on change), else TTL.
        """
        if not self.cache_content:
            return None
        key = (host, norm_share(share), norm_path(path))
        meta = self._file_meta(host, share, path)
        with self._lock:
            rows = self._db.execute(
                "SELECT offset, length, truncated, file_size, mtime, content_b64, "
                "fetched_at FROM file_reads "
                "WHERE host=? AND share=? AND path=? ORDER BY offset DESC",
                key).fetchall()
        if not rows:
            self._count(False)
            return None
        if meta is not None:
            # rows were stored with metadata: valid only while unchanged
            known_size, known_mtime = meta
            stored = next(((r[3], r[4]) for r in rows
                           if r[3] is not None or r[4] is not None), None)
            if stored is not None:
                stored_size, stored_mtime = stored
                changed = ((stored_size is not None and known_size is not None
                            and stored_size != known_size) or
                           (stored_mtime and known_mtime and stored_mtime != known_mtime))
                if changed:
                    with self._lock:
                        self._db.execute(
                            "DELETE FROM file_reads WHERE host=? AND share=? AND path=?",
                            key)
                        self._db.commit()
                        self._stale_evictions += 1
                    self._count(False)
                    return None
        elif not self._fresh(rows[0][6]):
            # no listing metadata available → plain TTL freshness
            self._count(False)
            return None
        for row_offset, length, trunc, _fs, _mt, b64, _fa in rows:
            if row_offset > offset:
                continue
            end = row_offset + length
            data = base64.b64decode(b64)
            if trunc:
                if offset + max_bytes > end:
                    continue          # cap-limited row: hard end
            else:
                data = data[:max(0, end - row_offset)]  # clamp to EOF
            lo = offset - row_offset
            slice_b = data[lo:lo + max_bytes] if lo < len(data) else b""
            if not slice_b:
                continue
            self._count(True, served=len(slice_b))
            return {"share": share, "path": path, "offset": offset,
                    "size": len(slice_b),
                    "truncated": len(slice_b) == max_bytes,
                    "content_b64": base64.b64encode(slice_b).decode("ascii")}
        self._count(False)
        return None

    def put_read(self, host: str, share: str, path: str, result: dict) -> None:
        if not self.cache_content:
            return
        meta = self._file_meta(host, share, path)
        size, mtime = meta if meta else (None, None)
        content = base64.b64decode(result.get("content_b64", ""))
        payload = result.get("content_b64", "")
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO file_reads "
                "(host, share, path, offset, length, truncated, file_size, mtime, "
                " content_b64, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (host, norm_share(share), norm_path(path),
                 int(result.get("offset", 0)), len(content),
                 1 if result.get("truncated") else 0,
                 size, mtime, payload, time.time()))
            self._db.commit()
        self._written(0)

    # -- domain computers ------------------------------------------------------ #
    def get_computers(self, dc: str, source: str, filter_ext: str) -> Optional[list]:
        with self._lock:
            row = self._db.execute(
                "SELECT computers_json, fetched_at FROM domain_computers "
                "WHERE cache_key = ?", (self._computers_key(dc, source, filter_ext),)
            ).fetchone()
        if row and self._fresh(row[1]):
            self._count(True)
            return json.loads(row[0])
        self._count(False)
        return None

    def put_computers(self, dc: str, source: str, filter_ext: str,
                      computers: list) -> None:
        payload = json.dumps(computers)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO domain_computers (cache_key, computers_json, "
                "fetched_at) VALUES (?, ?, ?)",
                (self._computers_key(dc, source, filter_ext), payload, time.time()))
            self._db.commit()
        self._written(0)

    @staticmethod
    def _computers_key(dc: str, source: str, filter_ext: str) -> str:
        return f"{dc or ''}|{source or ''}|{filter_ext or ''}"


class CachedSMBSession(SMBSession):
    """SMBSession whose three data-retrieval methods consult the shared
    inventory cache first. Cache hits never touch ``self.conn`` — the socket
    is only opened on a miss. Permission/security methods stay live."""

    def __init__(self, credential, host, cache: InventoryCache,
                 port: int = 445, timeout: int = 30, resolver=None):
        super().__init__(credential, host, port=port, timeout=timeout,
                         resolver=resolver)
        self._cache = cache

    def list_shares(self):
        hit = self._cache.get_shares(self.host)
        if hit is not None:
            return hit

        def _fetch():
            out = super(CachedSMBSession, self).list_shares()
            self._cache.put_shares(self.host, out)
            return out

        return self._cache._fetch_once(("shares", self.host), _fetch)

    def list_dir(self, share: str, path: str = "",
                 max_entries: int = DEFAULT_MAX_ENTRIES):
        hit = self._cache.get_listing(self.host, share, path, max_entries)
        if hit is not None:
            return hit

        def _fetch():
            out = super(CachedSMBSession, self).list_dir(share, path, max_entries)
            self._cache.put_listing(self.host, share, path, max_entries, out)
            return out

        return self._cache._fetch_once(
            ("dir", self.host, norm_share(share), norm_path(path)), _fetch)

    def read_file(self, share: str, path: str, offset: int = 0,
                  max_bytes: int = DEFAULT_MAX_READ_BYTES):
        hit = self._cache.get_read(self.host, share, path, offset, max_bytes)
        if hit is not None:
            return hit

        def _fetch():
            out = super(CachedSMBSession, self).read_file(share, path, offset,
                                                          max_bytes)
            self._cache.put_read(self.host, share, path, out)
            return out

        return self._cache._fetch_once(
            ("read", self.host, norm_share(share), norm_path(path), offset,
             max_bytes), _fetch)
