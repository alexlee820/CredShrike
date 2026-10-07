"""LDAP source: paged computer search over impacket's LDAP client.

Using impacket's LDAP (rather than ldap3) keeps the whole auth matrix in one
place: password/NTLM via ``login`` (sicilyNegotiate), AES key / Kerberos
ticket via ``kerberosLogin`` — identical semantics to the SMB stack, and
paging is handled by the client when a SimplePagedResultsControl is passed.
"""

from __future__ import annotations

import logging
from typing import Optional

from impacket.ldap import ldap as ldap_impacket
from impacket.ldap.ldapasn1 import SimplePagedResultsControl

from ..credentials import AuthType, Credential
from ..krbutil import extract_for_spn, load_ticket
from .base import (COMPUTER_ATTRS, DEFAULT_COMPUTER_FILTER, ComputerRecord,
                   computer_record_from_attributes)

LOG = logging.getLogger(__name__)


def decode_sid(raw) -> str:
    """Render raw objectSid bytes in canonical S-1-5-… form."""
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 8:
        return ""
    rev, count = raw[0], raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    subs = [int.from_bytes(raw[8 + 4 * i: 12 + 4 * i], "little") for i in range(count)]
    return f"S-1-{authority}-" + "-".join(str(s) for s in subs) if subs else f"S-1-{authority}"


def _vals_to_str(value_set) -> list:
    out = []
    for v in value_set or []:
        if isinstance(v, bytes):
            out.append(v)
        else:
            out.append(str(v))
    return out


class LdapSource:
    name = "ldap"

    def __init__(self, credential: Credential, dc: str, port: int = 389,
                 use_ssl: bool = False, page_size: int = 1000):
        self.credential = credential
        self.dc = dc
        self.port = port
        self.use_ssl = use_ssl
        self.page_size = page_size
        self._conn = None

    # -- connection -------------------------------------------------------- #
    def connect(self) -> "LdapSource":
        if self._conn is not None:
            return self
        scheme = "ldaps" if self.use_ssl else "ldap"
        url = f"{scheme}://{self.dc}:{self.port}"
        conn = ldap_impacket.LDAPConnection(url, "")
        cred = self.credential
        cred.validate()
        if cred.auth_type in (AuthType.PASSWORD, AuthType.NTLM):
            conn.login(cred.username, cred.password, cred.domain,
                       cred.lmhash or "", cred.nthash or "")
        elif cred.auth_type is AuthType.AES:
            conn.kerberosLogin(cred.username, "", cred.domain,
                               aesKey=cred.aes_key, kdcHost=cred.kdc_host or None)
        elif cred.auth_type is AuthType.TICKET:
            ccache = load_ticket(cred.ticket_path)
            domain, user, tgt, tgs = extract_for_spn(
                ccache, cred.domain, cred.username, f"ldap/{self.dc.split(':')[0]}")
            conn.kerberosLogin(user or cred.username, "", domain or cred.domain,
                               kdcHost=cred.kdc_host or None, TGT=tgt, TGS=tgs)
        self._conn = conn
        return self

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # -- queries ----------------------------------------------------------- #
    def default_naming_context(self) -> str:
        conn = self.connect()._conn
        entries = conn.search(searchBase="", scope=ldap_impacket.Scope("baseObject"),
                              attributes=["defaultNamingContext"],
                              searchFilter="(objectClass=*)")
        for entry in entries:
            for attr in entry["attributes"]:
                if str(attr["type"]) == "defaultNamingContext":
                    vals = _vals_to_str(attr["vals"])
                    return vals[0].decode() if vals and isinstance(vals[0], bytes) else (vals[0] if vals else "")
        return ""

    def list_computers(self, filter_ext: str = "",
                       attrs: Optional[list[str]] = None) -> list[ComputerRecord]:
        conn = self.connect()._conn
        wanted = attrs or COMPUTER_ATTRS
        base = self.default_naming_context()
        search_filter = f"(&{DEFAULT_COMPUTER_FILTER}{filter_ext})" if filter_ext \
            else DEFAULT_COMPUTER_FILTER
        controls = [SimplePagedResultsControl(size=self.page_size)]
        answers = conn.search(searchBase=base, searchFilter=search_filter,
                              attributes=wanted, searchControls=controls)
        records: list[ComputerRecord] = []
        for entry in answers:
            raw: dict[str, list] = {}
            for attr in entry["attributes"]:
                name = str(attr["type"])
                raw[name] = _vals_to_str(attr["vals"])
            if "objectSid" in raw and raw["objectSid"]:
                raw["objectSid"] = [decode_sid(raw["objectSid"][0])]
            records.append(computer_record_from_attributes(raw))
        return records
