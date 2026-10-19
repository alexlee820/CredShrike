"""Tests for the domain layer: ComputerRecord mapping, LDAP source (mocked
impacket LDAP), ADWS source (canned SOAP envelopes)."""

import base64
import struct

import pytest

from credshrike.credentials import Credential

from credshrike.domain.base import computer_record_from_attributes
from credshrike.domain.ldap_source import LdapSource, decode_sid


# --------------------------------------------------------------------------- #
# base mapping
# --------------------------------------------------------------------------- #
def _sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    subs = [int(p) for p in parts[3:]]
    out = bytes([1, len(subs)]) + int(parts[2]).to_bytes(6, "big")
    for s in subs:
        out += struct.pack("<I", s)
    return out


def test_decode_sid_bytes():
    assert decode_sid(_sid_bytes("S-1-5-21-1-2-3-1104")) == "S-1-5-21-1-2-3-1104"
    assert decode_sid("already-text") == "already-text"
    assert decode_sid(b"\x01") == ""


def test_computer_record_from_attributes():
    rec = computer_record_from_attributes({
        "cn": ["WS01"],
        "dNSHostName": ["ws01.corp.local"],
        "sAMAccountName": ["WS01$"],
        "operatingSystem": ["Windows 11 Pro"],
        "operatingSystemVersion": ["10.0 (26100)"],
        "objectSid": ["S-1-5-21-1-2-3-1104"],
        "userAccountControl": ["4096"],
        "memberOf": ["CN=Servers,OU=Groups,DC=corp,DC=local"],
    })
    assert rec.cn == "WS01" and rec.dns_name == "ws01.corp.local"
    assert rec.is_dc is False and rec.disabled is False
    d = rec.to_dict()
    assert d["object_sid"] == "S-1-5-21-1-2-3-1104"


def test_computer_record_dc_and_disabled_flags():
    rec = computer_record_from_attributes({"userAccountControl": ["8192"]})   # 0x2000 DC
    assert rec.is_dc and not rec.disabled
    rec2 = computer_record_from_attributes({"userAccountControl": ["4098"]})  # 0x2 disabled
    assert rec2.disabled


# --------------------------------------------------------------------------- #
# LDAP source with a fake impacket LDAPConnection
# --------------------------------------------------------------------------- #
class FakeLdapConn:
    """Mimics impacket LDAPConnection: login + rootDSE + paged search."""

    def __init__(self, url, base):
        self.url, self.base = url, base
        self.login_calls = []

    def login(self, user, password, domain="", lmhash="", nthash=""):
        self.login_calls.append(("login", user, domain))

    def kerberosLogin(self, user, password, domain="", lmhash="", nthash="", aesKey="",
                      kdcHost=None, TGT=None, TGS=None, useCache=True):
        self.login_calls.append(("kerberos", user, domain, aesKey, TGT is not None))

    def close(self):
        pass

    def search(self, searchBase=None, scope=None, derefAliases=None, sizeLimit=0,
               timeLimit=0, typesOnly=False, searchFilter="(objectClass=*)",
               attributes=None, searchControls=None, perRecordCallback=None):
        if searchFilter == "(objectClass=*)" and searchBase == "":
            return [_fake_entry("", [("defaultNamingContext", ["DC=corp,DC=local"])])]
        assert "objectClass=computer" in searchFilter
        return [
            _fake_entry("CN=WS01,DC=corp,DC=local", [
                ("cn", ["WS01"]), ("dNSHostName", ["ws01.corp.local"]),
                ("sAMAccountName", ["WS01$"]), ("userAccountControl", ["4096"]),
                ("objectSid", [_sid_bytes("S-1-5-21-1-2-3-1104")]),
            ]),
            _fake_entry("CN=DC01,DC=corp,DC=local", [
                ("cn", ["DC01"]), ("dNSHostName", ["dc01.corp.local"]),
                ("userAccountControl", ["8192"]),
            ]),
        ]


def _fake_entry(dn, attr_pairs):
    """Mirror impacket's pyasn1 SearchResultEntry interface:
    getComponentByName + iteration + isValue + asOctets."""

    class Val:
        isValue = True

        def __init__(self, raw):
            self._raw = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode()

        def asOctets(self):
            return self._raw

    class ValSeq(list):
        isValue = True

    class Attr:
        isValue = True

        def __init__(self, name, values):
            self._type, self._vals = name, ValSeq(Val(v) for v in values)

        def getComponentByName(self, name):
            return {"type": self._type, "vals": self._vals}[name]

    class AttrSeq(list):
        isValue = True

    class Entry:
        isValue = True

        def __init__(self, dn, attrs):
            self._attrs = AttrSeq(Attr(n, v) for n, v in attrs)

        def getComponentByName(self, name):
            return self._attrs if name == "attributes" else None

    return Entry(dn, attr_pairs)


@pytest.fixture
def ldap_source(monkeypatch):
    fake = FakeLdapConn("", "")

    def factory(credential, dc, port=389, use_ssl=False, page_size=1000):
        return LdapSource(credential, dc, port=port, use_ssl=use_ssl, page_size=page_size)

    import credshrike.domain.ldap_source as mod
    orig_init = mod.LdapSource.connect

    def patched_connect(self):
        if self._conn is None:
            self._conn = fake
            cred = self.credential
            if cred.auth_type.value in ("password", "ntlm"):
                fake.login(cred.username, cred.password, cred.domain,
                           cred.lmhash or "", cred.nthash or "")
        return self

    monkeypatch.setattr(mod.LdapSource, "connect", patched_connect)
    return fake


def test_ldap_list_computers(ldap_source):
    cred = Credential.from_args("password", "jdoe", "corp.local", password="pw")
    src = LdapSource(cred, "dc01.corp.local")
    with src:
        assert src.default_naming_context() == "DC=corp,DC=local"
        records = src.list_computers()
    assert len(records) == 2
    assert records[0].dns_name == "ws01.corp.local"
    assert records[0].object_sid == "S-1-5-21-1-2-3-1104"
    assert records[1].is_dc is True


