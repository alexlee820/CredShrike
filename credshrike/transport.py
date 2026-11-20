"""Enumeration transport interface.

Everything above this layer — agent tools, directory walkers, stream
analysis, triage, masking, reports — reaches a target through these
methods only. Implementations:

* ``ImpacketTransport`` (credshrike/smb_session.py) — direct SMB over
  sockets; the default and exactly the pre-existing behavior
* ``CobaltStrikeTransport`` (planned) — routes enumeration through a
  Cobalt Strike beacon via the official CS MCP server

The interface is deliberately narrow. Enumeration is READ-ONLY: there is
no method to write, create, delete or execute, so a transport can never
grant a capability that does not exist in its signature — the same
construction principle as the tool registry.

This module is intentionally dependency-free (no package imports) so any
module may import it safely in any order.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class TransportUnsupported(NotImplementedError):
    """A transport legitimately cannot serve this method (e.g. DACL probes
    over Cobalt Strike). Callers degrade gracefully — the executor records
    the error per call — instead of the whole run crashing."""


class EnumerationTransport(ABC):
    """Read-only enumeration surface for ONE host."""

    host: str

    # ---- core enumeration (every transport MUST implement these) ------- #
    @abstractmethod
    def list_shares(self) -> list[dict]:
        """Shares on the host: [{name, remark, type, type_name, special}]."""

    @abstractmethod
    def list_dir(self, share: str, path: str = "",
                 max_entries: int = 500) -> dict:
        """One directory listing inside a share:
        {share, path, entries: [{name, is_dir, size, attributes,
        created, accessed, written}], truncated, total_seen}."""

    @abstractmethod
    def read_file(self, share: str, path: str, offset: int = 0,
                  max_bytes: int = 262144) -> dict:
        """Bytes from one file: {share, path, offset, size, truncated,
        content_b64}. Capped; callers page with offset."""

    @abstractmethod
    def stat(self, share: str, path: str) -> dict:
        """Metadata for one file/dir (same entry shape as list_dir)."""

    # ---- optional capabilities ------------------------------------------
    # Impacket serves these natively; a transport that cannot (yet) raises
    # TransportUnsupported and the executor surfaces a per-call error.
    def get_security(self, share: str, path: str) -> dict:
        raise TransportUnsupported(
            f"{type(self).__name__} does not serve file security descriptors")

    def get_share_security(self, share: str) -> dict:
        raise TransportUnsupported(
            f"{type(self).__name__} does not serve share security descriptors")

    def effective_access(self, share: str, path: str) -> dict:
        raise TransportUnsupported(
            f"{type(self).__name__} does not serve effective-access probes")

    # ---- lifecycle -------------------------------------------------------
    # Subclasses override as needed; the defaults make a connectionless
    # transport (e.g. one backed by a queue) a no-op to connect/close.
    def connect(self) -> "EnumerationTransport":
        return self

    def close(self) -> None:
        return None

    def __enter__(self) -> "EnumerationTransport":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
