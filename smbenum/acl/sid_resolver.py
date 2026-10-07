"""SID -> principal name resolution.

Three layers, cheapest first:
1. well-known SID table (static, no network);
2. an injected static map (e.g. objectSid values pulled from LDAP in bulk);
3. an optional async/remote lookup callback — the SMB session wires this to
   LsarLookupSids2 over the lsarpc pipe.

The resolver is intentionally independent of impacket so it can be unit
tested with plain dictionaries.
"""

from __future__ import annotations
import logging
from typing import Callable, Iterable, Optional

LOG = logging.getLogger(__name__)

# --- well-known / built-in table ------------------------------------------- #
WELL_KNOWN = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "Local",
    "S-1-2-1": "Console Logon",
    "S-1-3-0": "Creator Owner",
    "S-1-3-1": "Creator Group",
    "S-1-3-4": "Owner Rights",
    "S-1-5-1": "Dialup",
    "S-1-5-2": "Network",
    "S-1-5-3": "Batch",
    "S-1-5-4": "Interactive",
    "S-1-5-6": "Service",
    "S-1-5-7": "Anonymous",
    "S-1-5-8": "Proxy",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "Principal Self",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-12": "Restricted Code",
    "S-1-5-13": "Terminal Server Users",
    "S-1-5-14": "Remote Interactive Logon",
    "S-1-5-15": "This Organization",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "SYSTEM (LocalSystem)",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-547": "BUILTIN\\Power Users",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-552": "BUILTIN\\Replicator",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
    "S-1-5-32-556": "BUILTIN\\Network Configuration Operators",
    "S-1-5-32-557": "BUILTIN\\Incoming Forest Trust Builders",
    "S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
    "S-1-5-32-559": "BUILTIN\\Performance Log Users",
    "S-1-5-32-560": "BUILTIN\\Windows Authorization Access Group",
    "S-1-5-32-561": "BUILTIN\\Terminal Server License Servers",
    "S-1-5-32-562": "BUILTIN\\Distributed COM Users",
    "S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
    "S-1-5-32-573": "BUILTIN\\Event Log Readers",
    "S-1-5-32-574": "BUILTIN\\Certificate Service DCOM Access",
    "S-1-5-64-10": "NTLM Authentication",
    "S-1-5-64-14": "SChannel Authentication",
    "S-1-5-64-21": "Digest Authentication",
    "S-1-5-65-1": "This Organization Certificate",
    "S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
}

# RIDs relative to a domain SID (S-1-5-21-<domain>-<rid>)
_DOMAIN_RIDS = {
    500: "Administrator",
    501: "Guest",
    502: "krbtgt",
    512: "Domain Admins",
    513: "Domain Users",
    514: "Domain Guests",
    515: "Domain Computers",
    516: "Domain Controllers",
    517: "Cert Publishers",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    521: "Read-only Domain Controllers",
    522: "Cloneable Domain Controllers",
    526: "Key Admins",
    527: "Enterprise Key Admins",
    553: "RAS and IAS Servers",
    571: "Allowed RODC Password Replication Group",
    572: "Denied RODC Password Replication Group",
}


def _domain_ride_name(sid: str) -> Optional[str]:
    parts = sid.split("-")
    if len(parts) == 8 and parts[:4] == ["S", "1", "5", "21"]:
        try:
            rid = int(parts[7])
        except ValueError:
            return None
        name = _DOMAIN_RIDS.get(rid)
        return f"<domain-SID>-{rid} ({name})" if name else None
    return None


class SidResolver:
    """Layered resolver: well-known table -> static map -> remote callback."""

    def __init__(
        self,
        static_map: Optional[dict[str, str]] = None,
        remote_lookup: Optional[Callable[[Iterable[str]], dict[str, str]]] = None,
    ):
        self.static_map = dict(static_map or {})
        self.remote_lookup = remote_lookup

    def resolve(self, sid: str) -> str:
        return self.resolve_many([sid]).get(sid, sid)

    def resolve_many(self, sids: Iterable[str]) -> dict[str, str]:
        pending: list[str] = []
        out: dict[str, str] = {}
        for sid in dict.fromkeys(sids):  # dedupe, keep order
            if sid in WELL_KNOWN:
                out[sid] = WELL_KNOWN[sid]
            elif sid in self.static_map:
                out[sid] = self.static_map[sid]
            else:
                fallback = _domain_ride_name(sid)
                if fallback:
                    out[sid] = fallback
                else:
                    pending.append(sid)
        if pending and self.remote_lookup is not None:
            try:
                got = self.remote_lookup(pending)
                out.update({k: v for k, v in got.items() if v})
            except Exception as exc:  # noqa: BLE001 - resolution must never break enumeration
                LOG.debug("remote SID lookup failed: %s", exc)
        return out

    def annotate(self, parsed_sd: dict) -> dict:
        """Add trustee_name/owner_name/group_name to a parsed SD in place."""
        sids: list[str] = []
        if parsed_sd.get("owner"):
            sids.append(parsed_sd["owner"])
        if parsed_sd.get("group"):
            sids.append(parsed_sd["group"])
        for acl in (parsed_sd.get("dacl"), parsed_sd.get("sacl")):
            for ace in (acl or {}).get("aces", []):
                if ace.get("trustee"):
                    sids.append(ace["trustee"])
        names = self.resolve_many(sids)
        if parsed_sd.get("owner"):
            parsed_sd["owner_name"] = names.get(parsed_sd["owner"], parsed_sd["owner"])
        if parsed_sd.get("group"):
            parsed_sd["group_name"] = names.get(parsed_sd["group"], parsed_sd["group"])
        for acl in (parsed_sd.get("dacl"), parsed_sd.get("sacl")):
            for ace in (acl or {}).get("aces", []):
                if ace.get("trustee"):
                    ace["trustee_name"] = names.get(ace["trustee"], ace["trustee"])
        return parsed_sd
