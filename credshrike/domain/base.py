"""Unified interface for domain computer queries.

Two implementations: LDAP (:mod:`.ldap_source`) and ADWS
(:mod:`.adws_source`). Both map rows onto :class:`ComputerRecord` so callers
(including the LLM tool layer) never care which transport answered.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional, Protocol


@dataclass
class ComputerRecord:
    cn: str = ""                       # common name (NetBIOS-style)
    dns_name: str = ""                 # dNSHostName
    sam_account: str = ""              # sAMAccountName (usually CN$)
    operating_system: str = ""         # operatingSystem [+ version]
    os_version: str = ""
    object_sid: str = ""
    description: str = ""
    distinguished_name: str = ""
    member_of: list[str] = field(default_factory=list)
    last_logon: Optional[str] = None
    when_changed: Optional[str] = None
    is_dc: bool = False                # userAccountControl & 0x2000
    disabled: bool = False             # userAccountControl & 0x2
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# userAccountControl flags we decode
UF_ACCOUNTDISABLE = 0x0002
UF_SERVER_TRUST_ACCOUNT = 0x2000
UF_WORKSTATION_TRUST_ACCOUNT = 0x1000


def computer_record_from_attributes(attrs: dict) -> ComputerRecord:
    """Build a ComputerRecord from a generic {ldap_attr_name: [values]} map,
    normalizing what both LDAP and ADWS return."""
    def first(name, default=""):
        vals = attrs.get(name) or []
        return vals[0] if vals else default

    uac = 0
    try:
        uac = int(first("userAccountControl", "0") or 0)
    except ValueError:
        pass
    os_name = first("operatingSystem")
    os_ver = first("operatingSystemVersion")
    return ComputerRecord(
        cn=first("cn"),
        dns_name=first("dNSHostName"),
        sam_account=first("sAMAccountName"),
        operating_system=os_name,
        os_version=os_ver,
        object_sid=first("objectSid"),
        description=first("description"),
        distinguished_name=first("distinguishedName"),
        member_of=list(attrs.get("memberOf") or []),
        last_logon=first("lastLogonTimestamp") or None,
        when_changed=first("whenChanged") or None,
        is_dc=bool(uac & UF_SERVER_TRUST_ACCOUNT),
        disabled=bool(uac & UF_ACCOUNTDISABLE),
        raw={k: v for k, v in attrs.items()
             if k not in ("objectSid", "userAccountControl", "memberOf")},
    )


COMPUTER_ATTRS = ["cn", "dNSHostName", "sAMAccountName", "operatingSystem",
                  "operatingSystemVersion", "objectSid", "description",
                  "distinguishedName", "memberOf", "lastLogonTimestamp",
                  "whenChanged", "userAccountControl"]

DEFAULT_COMPUTER_FILTER = "(objectClass=computer)"


class DirectorySource(Protocol):
    """Anything that can enumerate computer objects from the directory."""

    name: str

    def list_computers(self, filter_ext: str = "", attrs: Optional[list[str]] = None) -> list[ComputerRecord]:
        ...
