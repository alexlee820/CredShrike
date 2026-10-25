"""Unified credential model for the four supported authentication types.

The :class:`Credential` is pure data plus small helpers. Protocol-specific
materialization lives next to each consumer (``smb_session``,
``domain.ldap_source``, ``domain.adws_source``) so the model itself never
imports impacket — which keeps it trivially testable.

Secrets hygiene: ``redacted()`` is the ONLY representation of a credential
that may appear in logs, audit files or LLM context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AuthType(str, Enum):
    PASSWORD = "password"   # domain\user + plaintext password
    NTLM = "ntlm"           # LM:NT hash pair (NT-only is fine)
    AES = "aes"             # aes256-cts-hmac-sha1-96 (or aes128) key -> Kerberos
    TICKET = "ticket"       # Kerberos ticket file, .ccache or .kirbi


_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")


@dataclass
class Credential:
    auth_type: AuthType
    username: str
    domain: str
    password: str = ""
    lmhash: str = ""
    nthash: str = ""
    aes_key: str = ""                # hex string, 32 bytes for aes256 / 16 for aes128
    ticket_path: str = ""            # .ccache or .kirbi file
    kdc_host: str = ""               # optional KDC override (ip/host[:port])
    extra: dict = field(default_factory=dict)

    # ------------------------------------------------------------------ #
    # construction helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def from_args(
        cls,
        auth_type: str,
        username: str,
        domain: str,
        password: str = "",
        hashes: str = "",
        aes_key: str = "",
        ticket: str = "",
        kdc: str = "",
    ) -> "Credential":
        """Build from CLI-style flags. ``hashes`` is the impacket-style
        ``LM:NT`` string (either half may be empty, e.g. ``:NTHASH``)."""
        at = AuthType(auth_type.lower())
        cred = cls(auth_type=at, username=username, domain=domain, kdc_host=kdc)
        if at is AuthType.PASSWORD:
            cred.password = password
        elif at is AuthType.NTLM:
            lm, nt = cls._split_hashes(hashes or password)
            cred.lmhash, cred.nthash = lm, nt
        elif at is AuthType.AES:
            cred.aes_key = aes_key.replace(":", "")
        elif at is AuthType.TICKET:
            cred.ticket_path = ticket
        return cred

    @classmethod
    def from_profile(cls, data: dict) -> "Credential":
        """Build from a parsed YAML profile dict (keys mirror from_args)."""
        return cls.from_args(
            auth_type=data["auth_type"],
            username=data["username"],
            domain=data.get("domain", ""),
            password=data.get("password", ""),
            hashes=data.get("hashes", ""),
            aes_key=data.get("aes_key", ""),
            ticket=data.get("ticket", ""),
            kdc=data.get("kdc", ""),
        )

    @staticmethod
    def _split_hashes(hashes: str) -> tuple[str, str]:
        if ":" in hashes:
            lm, nt = hashes.split(":", 1)
        else:
            lm, nt = "", hashes  # bare NT hash
        for name, val in (("LM", lm), ("NT", nt)):
            if val and not _HASH_RE.match(val):
                raise ValueError(f"invalid {name} hash (expected 32 hex chars): {val[:4]}…")
        return lm.lower(), nt.lower()

    # ------------------------------------------------------------------ #
    # predicates / views
    # ------------------------------------------------------------------ #
    @property
    def is_kerberos(self) -> bool:
        return self.auth_type in (AuthType.AES, AuthType.TICKET)

    @property
    def principal(self) -> str:
        return f"{self.domain}\\{self.username}" if self.domain else self.username

    def redacted(self) -> dict[str, Any]:
        """Log-safe / LLM-safe representation — every secret becomes '<redacted>'."""
        return {
            "auth_type": self.auth_type.value,
            "username": self.username,
            "domain": self.domain,
            "principal": self.principal,
            "has_password": bool(self.password),
            "has_lmhash": bool(self.lmhash),
            "has_nthash": bool(self.nthash),
            "has_aes_key": bool(self.aes_key),
            "ticket_path": self.ticket_path or None,
            "kdc_host": self.kdc_host or None,
        }

    def validate(self) -> None:
        """Fail fast on combinations that cannot authenticate anything."""
        if not self.username:
            raise ValueError("credential missing username")
        if self.auth_type is AuthType.PASSWORD and not self.password:
            raise ValueError("password auth requires --password / profile password")
        if self.auth_type is AuthType.NTLM and not self.nthash:
            raise ValueError("ntlm auth requires --hashes LM:NT (or bare NT)")
        if self.auth_type is AuthType.AES and not self.aes_key:
            raise ValueError("aes auth requires --aes-key")
        if self.auth_type is AuthType.TICKET and not self.ticket_path:
            raise ValueError("ticket auth requires --ticket <file.ccache|file.kirbi>")
        if self.is_kerberos and not self.domain:
            raise ValueError(f"{self.auth_type.value} auth requires a domain (realm)")
