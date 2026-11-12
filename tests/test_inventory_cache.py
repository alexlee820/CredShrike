"""Tests for the shared inventory cache (credshrike/inventory_cache.py)."""
import base64
import json
import threading
from pathlib import Path

import pytest

import credshrike.inventory_cache as ic
from credshrike.inventory_cache import (CachedSMBSession, InventoryCache,
                                        norm_path, norm_share, sanitize_name)


class CountingSMB:
    """Stands in for SMBSession's three cached methods (super() calls land
    here via monkeypatching the real class)."""

    def __init__(self):
        self.list_shares_calls = 0
        self.list_dir_calls = 0
        self.read_calls = 0
        self.shares = [{"name": "IT", "remark": "", "type": 0,
                        "type_name": "DISK", "special": False}]
        self.entries = [{"name": "creds.txt", "is_dir": False, "size": 100,
                         "attributes": "0x80", "created": "2026-01-01T00:00:00",
                         "accessed": "2026-01-01T00:00:00",
                         "written": "2026-01-02T03:04:05"},
                        {"name": "sub", "is_dir": True, "size": 0,
                         "attributes": "0x10", "created": "", "accessed": "",
                         "written": ""}]

    def list_shares(self):
        self.list_shares_calls += 1
        return [dict(s) for s in self.shares]

    def list_dir(self, share, path="", max_entries=500):
        self.list_dir_calls += 1
        entries = self.entries[:max_entries]
        return {"share": share, "path": path, "entries": entries,
                "truncated": len(self.entries) > max_entries,
                "total_seen": len(self.entries)}

    def read_file(self, share, path, offset=0, max_bytes=262144):
        self.read_calls += 1
        data = b"0123456789" * 30  # 300 bytes
        chunk = data[offset:offset + max_bytes]
        return {"share": share, "path": path, "offset": offset,
                "size": len(chunk), "truncated": len(chunk) == max_bytes,
                "content_b64": base64.b64encode(chunk).decode()}


@pytest.fixture()
def counter():
    return CountingSMB()


@pytest.fixture()
def cache(tmp_path):
    c = InventoryCache(str(tmp_path / "inv.db"), ttl_seconds=3600)
    yield c
    c.close()


@pytest.fixture()
def patched(counter, monkeypatch):
    """Route CachedSMBSession's super() calls to the counting fake."""
    monkeypatch.setattr(ic.SMBSession, "list_shares",
                        lambda self: counter.list_shares())
    monkeypatch.setattr(ic.SMBSession, "list_dir",
                        lambda self, share, path="", max_entries=500:
                        counter.list_dir(share, path, max_entries))
    monkeypatch.setattr(ic.SMBSession, "read_file",
                        lambda self, share, path, offset=0, max_bytes=262144:
                        counter.read_file(share, path, offset, max_bytes))


def _session(cache, host="fs01"):
    return CachedSMBSession(credential=None, host=host, cache=cache)


# --------------------------------------------------------------------------- #
# shares + listings
# --------------------------------------------------------------------------- #

def test_shares_cached_after_first_fetch(cache, patched, counter):
    s = _session(cache)
    first = s.list_shares()
    second = s.list_shares()
    assert counter.list_shares_calls == 1
    assert first == second


def test_listing_cached_and_truncation_semantics(cache, patched, counter):
    s = _session(cache)
    s.list_dir("IT", "", 500)          # full listing (2 entries, cap 500)
    s.list_dir("IT", "", 10)           # smaller cap → served from cache
    assert counter.list_dir_calls == 1
    # larger cap on a non-truncated listing → must refetch
    s.list_dir("IT", "", 1000)
    assert counter.list_dir_calls == 2


def test_truncated_listing_only_serves_same_cap(cache, patched, counter):
    s = _session(cache)
    out = s.list_dir("IT", "", 1)      # truncated at 1
    assert out["truncated"] is True
    s.list_dir("IT", "", 1)            # identical cap → hit
    assert counter.list_dir_calls == 1
    s.list_dir("IT", "", 500)          # different cap → miss
    assert counter.list_dir_calls == 2


def test_share_and_path_normalization(cache, patched, counter):
    s = _session(cache)
    s.list_dir("IT", "Sub\\Folder", 500)
    s.list_dir("it", "sub/folder", 500)   # same keys, different spelling
    assert counter.list_dir_calls == 1
    # the hit re-echoes the CALLER's spelling
    out = s.list_dir("it", "sub/folder", 500)
    assert out["share"] == "it" and out["path"] == "sub/folder"


def test_ttl_expiry_backdates_stale_rows(cache, patched, counter):
    s = _session(cache)
    s.list_shares()
    with cache._lock:
        cache._db.execute("UPDATE shares SET fetched_at = ?", (0.0,))
        cache._db.commit()
    s.list_shares()
    assert counter.list_shares_calls == 2   # refetched


# --------------------------------------------------------------------------- #
# reads: range-cover + invalidation
# --------------------------------------------------------------------------- #

def _prime_listing_and_read(cache, patched, counter, size=100, written="2026-01-02T03:04:05"):
    counter.entries[0]["size"] = size
    counter.entries[0]["written"] = written
    s = _session(cache)
    s.list_dir("IT", "", 500)             # metadata source
    s.read_file("IT", "creds.txt", 0, 100)  # cache row [0,100)
    counter.read_calls = 0
    return s


def test_read_range_cover_hits(cache, patched, counter):
    s = _prime_listing_and_read(cache, patched, counter)
    out = s.read_file("IT", "creds.txt", 0, 50)     # inside [0,100)
    assert out["size"] == 50
    # same shape a LIVE read returns: slice == cap -> truncated=True
    assert out["truncated"] is True
    assert base64.b64decode(out["content_b64"]) == b"0123456789" * 5
    out = s.read_file("IT", "creds.txt", 50, 50)    # tail of [0,100)
    assert out["size"] == 50 and out["truncated"] is True
    assert counter.read_calls == 0


def test_read_range_miss_beyond_row(cache, patched, counter):
    s = _prime_listing_and_read(cache, patched, counter)
    s.read_file("IT", "creds.txt", 0, 200)          # needs [0,200)
    assert counter.read_calls == 1


def test_read_size_change_evicts(cache, patched, counter):
    s = _prime_listing_and_read(cache, patched, counter, size=100)
    # file grew: the listing now reports a different size
    counter.entries[0]["size"] = 4096
    s.list_dir("IT", "", 1000)   # larger cap → refetch → fresh metadata
    s.read_file("IT", "creds.txt", 0, 50)
    assert counter.read_calls == 1
    st = cache.stats()
    assert st["stale_evictions"] >= 1


def test_read_mtime_change_evicts(cache, patched, counter):
    s = _prime_listing_and_read(cache, patched, counter,
                                written="2026-01-02T03:04:05")
    counter.entries[0]["written"] = "2026-11-01T00:00:00"
    s.list_dir("IT", "", 1000)
    s.read_file("IT", "creds.txt", 0, 50)
    assert counter.read_calls == 1


def test_read_without_listing_uses_ttl(cache, patched, counter):
    s = _session(cache)
    s.read_file("IT", "creds.txt", 0, 100)   # no listing primed
    s.read_file("IT", "creds.txt", 0, 50)
    assert counter.read_calls == 1           # TTL-fresh → hit
    with cache._lock:
        cache._db.execute("UPDATE file_reads SET fetched_at = 0.0")
        cache._db.commit()
    s.read_file("IT", "creds.txt", 0, 50)
    assert counter.read_calls == 2           # expired → miss


def test_no_content_cache_bypasses_reads(cache, patched, tmp_path):
    c = InventoryCache(str(tmp_path / "x.db"), ttl_seconds=60,
                       cache_content=False)
    try:
        s = CachedSMBSession(None, "fs01", cache=c)
        s.read_file("IT", "creds.txt", 0, 50)
        s.read_file("IT", "creds.txt", 0, 50)
        assert c.stats()["hits"] == 0
    finally:
        c.close()


def test_wipe_clears_everything(cache, patched, counter):
    s = _session(cache)
    s.list_shares()
    s.list_dir("IT", "", 500)
    s.read_file("IT", "creds.txt", 0, 100)
    cache.wipe()
    s.list_shares()
    assert counter.list_shares_calls == 2


def test_stats_counters_move(cache, patched, counter):
    s = _session(cache)
    s.list_shares(); s.list_shares()
    st = cache.stats()
    assert st["hits"] == 1 and st["misses"] == 1


# --------------------------------------------------------------------------- #
# concurrency + factory + misc
# --------------------------------------------------------------------------- #

def test_concurrent_reads_single_flight(cache, patched, counter):
    s = _session(cache)
    results = []
    errors = []

    def worker():
        try:
            results.append(s.list_dir("IT", "", 500))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert counter.list_dir_calls == 1   # fetched exactly once


def test_factory_arm_and_disarm(monkeypatch):
    import credshrike.smb_session as ss
    calls = []
    monkeypatch.setattr(ss, "SMBSession",
                        lambda *a, **k: calls.append("plain"))
    # unarmed → plain session (module-global name lookup keeps test patches alive)
    ss.create_smb_session(None, "fs01")
    assert calls == ["plain"]


def test_open_returns_none_when_disabled(tmp_path):
    from types import SimpleNamespace
    assert InventoryCache.open(str(tmp_path), SimpleNamespace(
        inventory_cache=False)) is None
    c = InventoryCache.open(str(tmp_path), SimpleNamespace(
        inventory_cache=True, cache_ttl_hours=2, cache_content=True))
    try:
        assert c.ttl_seconds == 7200 and c.cache_content is True
    finally:
        c.close()


def test_domain_computers_roundtrip(cache):
    assert cache.get_computers("dc01", "ldap", "(objectClass=computer)") is None
    cache.put_computers("dc01", "ldap", "(objectClass=computer)",
                        [{"cn": "WS01", "dns_name": "ws01.corp.local"}])
    got = cache.get_computers("dc01", "ldap", "(objectClass=computer)")
    assert got[0]["dns_name"] == "ws01.corp.local"
    assert cache.get_computers("dc02", "ldap", "") is None   # different key


def test_normalization_helpers():
    assert norm_share("  IT ") == "it"
    assert norm_path("Sub\\Folder\\") == "sub/folder"
    assert norm_path("") == ""
    assert sanitize_name("WS01.corp.local" + "\\\\$evil") == "WS01.corp.local___evil"


def test_cache_db_lives_under_dot_cache_dir(tmp_path):
    c = InventoryCache(str(tmp_path / "runs" / ".cache" / "inventory.db"),
                       ttl_seconds=60)
    try:
        assert (tmp_path / "runs" / ".cache" / "inventory.db").exists()
    finally:
        c.close()
