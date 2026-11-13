"""AgentSession: everything a tool handler needs, nothing it shouldn't have.

Holds the Credential (injected into handlers — never into the LLM context),
the per-host SMB session cache, directory-source cache, budget counters and
the audit log. This is the object that makes the executor's read-only
guarantee structural: handlers can only reach the read-only methods exposed
by SMBSession / the directory sources.
"""

from __future__ import annotations

import time
from queue import Queue
from typing import Optional

from ..config import Policy
from ..credentials import Credential
from ..smb_session import SMBSession, create_smb_session
from .audit import AuditLog


class Budget:
    """Reads limits live from the Policy (single source of truth) and tracks
    spend per run: tool calls, bytes read, wall clock."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.tool_calls = 0
        self.bytes_read = 0
        self.started = time.monotonic()

    @property
    def max_tool_calls(self) -> int:
        return self.policy.max_tool_calls

    @property
    def max_total_read_bytes(self) -> int:
        return self.policy.max_total_read_bytes

    @property
    def wall_clock_seconds(self) -> int:
        return self.policy.wall_clock_seconds

    @property
    def exhausted(self) -> bool:
        return (self.tool_calls >= self.max_tool_calls
                or self.bytes_read >= self.max_total_read_bytes
                or (time.monotonic() - self.started) > self.wall_clock_seconds)

    def why(self) -> Optional[str]:
        if self.tool_calls >= self.max_tool_calls:
            return f"tool-call budget exhausted ({self.max_tool_calls} calls)"
        if self.bytes_read >= self.max_total_read_bytes:
            return f"byte budget exhausted ({self.max_total_read_bytes} bytes read)"
        if (time.monotonic() - self.started) > self.wall_clock_seconds:
            return f"time budget exhausted ({self.wall_clock_seconds}s)"
        return None

    def snapshot(self) -> dict:
        return {"tool_calls": self.tool_calls, "max_tool_calls": self.max_tool_calls,
                "bytes_read": self.bytes_read, "max_total_read_bytes": self.max_total_read_bytes,
                "elapsed_s": int(time.monotonic() - self.started),
                "wall_clock_seconds": self.wall_clock_seconds}


class AgentSession:
    def __init__(self, credential: Credential, policy: Policy, audit: AuditLog,
                 mask_factory=None,
                 hosts: Optional[list[str]] = None, dc: str = "",
                 domain_source: str = "auto"):
        self.credential = credential
        self.policy = policy
        self.audit = audit
        self.dc = dc
        self.domain_source = domain_source
        self.allowed_hosts = list(hosts or policy.allowed_hosts or [])
        self.budget = Budget(policy)
        self._smb_cache: dict[str, SMBSession] = {}
        self._dir_sources: dict[str, object] = {}
        # files the read gate flagged instead of reading (harness-side record,
        # independent of whatever the model says in its report)
        self.flagged_files: list[dict] = []
        # total redaction hits scrubbed from tool results before they reached
        # the LLM (harness-side counter for /budget)
        self.redactions_applied = 0
        # PasteGuard-style privacy masking: None when disabled. One Masker per
        # session = one placeholder namespace per context window.
        from ..masking import Masker
        self.masker = Masker.from_policy(policy,
                                         shared_factory=mask_factory)
        self.masked_values = 0
        # full results of every smb_scan_share sweep (for the HTML report)
        self.scan_results: list[dict] = []
        # domain computer inventory (domain_list_computers results, deduped)
        self.domain_computers: list[dict] = []
        # per-host share inventory: host -> [share dicts] (smb_list_shares)
        self.share_inventories: dict[str, list] = {}
        # debug mode: full rendered tool results exactly as the model saw them
        # ({tool, args, chars, content}), capped to keep memory sane
        self.debug_results: list[dict] = []
        # optional progress hook for UIs/echo: emit(kind, data) — set by the
        # web app so mid-sweep progress reaches the browser
        self.event_hook = None
        # connection pool for parallel file reads (created lazily per host)
        self._read_pools: dict[str, Queue] = {}
        self.read_threads = int(getattr(policy, "read_threads", 10))

    def emit(self, kind: str, data: dict) -> None:
        if self.event_hook is not None:
            try:
                self.event_hook(kind, data)
            except Exception:  # noqa: BLE001 - UI problems must never stop the agent
                pass

    def flag_file(self, host: str, share: str, path: str, reason: str,
                  size_bytes: "int | None" = None) -> dict:
        import time as _time
        entry = {"host": host, "share": share, "path": path,
                 "size_bytes": size_bytes, "reason": reason,
                 "ts": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())}
        self.flagged_files.append(entry)
        return entry

    # -- scope enforcement ------------------------------------------------- #
    def host_allowed(self, host: str) -> bool:
        if not self.allowed_hosts:
            return True  # unrestricted session (CLI ran without --host)
        return host.lower() in {h.lower() for h in self.allowed_hosts}

    # -- SMB --------------------------------------------------------------- #
    def smb(self, host: str) -> SMBSession:
        """Cached read-only SMB session per host."""
        if host not in self._smb_cache:
            session = create_smb_session(self.credential, host, timeout=30)
            session.connect()
            self._smb_cache[host] = session
        return self._smb_cache[host]

    def get_read_pool(self, host: str) -> Queue:
        """Get or create a connection pool for parallel file reads on a host.
        Each pool has `read_threads` independent SMB connections."""
        if host not in self._read_pools:
            pool: Queue = Queue()
            for _ in range(max(1, self.read_threads)):
                try:
                    reader = create_smb_session(self.credential, host, timeout=30)
                    reader.connect()
                    pool.put(reader)
                except Exception:  # noqa: BLE001 — mock env, fall back below
                    pass
            if pool.qsize() == 0:
                pool.put(self.smb(host))  # fall back to shared connection
            self._read_pools[host] = pool
        return self._read_pools[host]

    def any_smb_resolver(self):
        """Resolver from any live SMB session (LSA-capable), or a plain
        well-known/static resolver when no session is open yet."""
        if self._smb_cache:
            return next(iter(self._smb_cache.values())).resolver
        from ..acl import SidResolver
        return SidResolver()

    # -- directory --------------------------------------------------------- #
    def directory(self, source: str = "auto"):
        """Cached directory source; 'auto' prefers ldap, falls back to adws."""
        key = source
        if key == "auto":
            key = "ldap"  # auto = try ldap first; adws chosen explicitly or on error
        if key not in self._dir_sources:
            if key == "ldap":
                from ..domain.ldap_source import LdapSource
                self._dir_sources[key] = LdapSource(self.credential, self.dc)
            elif key == "adws":
                from ..domain.adws_source import AdwsSource
                self._dir_sources[key] = AdwsSource(self.credential, self.dc)
            else:
                raise ValueError(f"unknown directory source '{source}'")
        return self._dir_sources[key]

    # -- lifecycle --------------------------------------------------------- #
    def close_smb(self) -> None:
        """Close SMB read pools + cached sessions. Does NOT touch the audit
        log — safe for short-lived per-share/per-batch sessions that share
        the run's single audit writer."""
        for pool in self._read_pools.values():
            while True:
                try:
                    reader = pool.get_nowait()
                except Exception:  # noqa: BLE001 — Queue.Empty
                    break
                try:
                    reader.close()
                except Exception:  # noqa: BLE001
                    pass
        self._read_pools.clear()
        for session in self._smb_cache.values():
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
        self._smb_cache.clear()

    def close(self) -> None:
        self.close_smb()
        for source in self._dir_sources.values():
            closer = getattr(source, "close", None)
            if closer:
                try:
                    closer()
                except Exception:  # noqa: BLE001
                    pass
        self._dir_sources.clear()
        self.audit.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
