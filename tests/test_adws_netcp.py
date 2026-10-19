"""ADWS net.tcp stack tests (offline): NBFSE codec round-trip, NMF framing,
template shapes, and the full AdwsSource Enumerate/Pull flow against a fake
ADWSConnect (no sockets)."""

import base64 as b64
import struct
import xml.etree.ElementTree as ET

from credshrike.credentials import Credential
from credshrike.domain.adws.encoder import Encoder
from credshrike.domain.adws.ms_nmf import NMFSizedEnvelope
from credshrike.domain.adws.soap_templates import LDAP_QUERY_FSTRING, LDAP_ROOT_DSE_FSTRING
import credshrike.domain.adws_source as adws_mod
from credshrike.domain.adws_source import AdwsSource, _release_envelope
from credshrike.domain.adws import NTLMAuth

NS_AD = "http://schemas.microsoft.com/2008/1/ActiveDirectory"
NS_ADDATA = f"{NS_AD}/Data"
NS_WSEN = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

WS01_SID = "S-1-5-21-1-2-3-1104"


def _sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    subs = [int(p) for p in parts[3:]]
    out = bytes([1, len(subs)]) + int(parts[2]).to_bytes(6, "big")
    for s in subs:
        out += struct.pack("<I", s)
    return out


PULL_XML = f"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsen="{NS_WSEN}"
  xmlns:addata="{NS_ADDATA}"
  xmlns:ad="{NS_AD}">
  <s:Body><wsen:PullResponse>
    <wsen:Items>
      <addata:computer>
        <addata:cn><ad:value>WS01</ad:value></addata:cn>
        <addata:dnshostname><ad:value>ws01.corp.local</ad:value></addata:dnshostname>
        <addata:samaccountname><ad:value>WS01$</ad:value></addata:samaccountname>
        <addata:objectsid><ad:value>__SID_B64__</ad:value></addata:objectsid>
        <addata:useraccountcontrol><ad:value>4096</ad:value></addata:useraccountcontrol>
        <addata:memberof><ad:value>CN=Servers,DC=corp,DC=local</ad:value><ad:value>CN=Web,DC=corp,DC=local</ad:value></addata:memberof>
      </addata:computer>
    </wsen:Items>
  </wsen:PullResponse></s:Body>
</s:Envelope>"""


# --------------------------------------------------------------------------- #
# codec + framing
# --------------------------------------------------------------------------- #
def test_nbfse_codec_roundtrip():
    encoder = Encoder(0x8)
    xml = LDAP_ROOT_DSE_FSTRING.format(uuid="00000000-0000-0000-0000-000000000000",
                                       fqdn="dc01.corp.local")
    blob = encoder.encode(xml)
    assert isinstance(blob, bytes) and blob
    decoded = encoder.decode(blob)
    assert ET.fromstring(decoded).tag.endswith("Envelope")


def test_nmf_sized_envelope_roundtrip():
    payload = b"\x01\x02\x03soap"
    data = NMFSizedEnvelope(payload=payload).getData()
    assert data[0] == 0x06          # record type: SizedEnvelope
    # header = type byte + 7-bit size (single byte for a small payload)
    assert data[1] == len(payload)
    assert bytes(data[2:]) == payload


def test_enumerate_template_shape():
    sel = '<ad:SelectionProperty>addata:cn</ad:SelectionProperty>'
    soap = LDAP_QUERY_FSTRING.format(uuid="u1", fqdn="dc01.corp.local",
                                     query="(objectClass=computer)",
                                     attributes=sel, baseobj="DC=corp,DC=local")
    assert "enumeration/Enumerate" in soap
    assert "ldap:389" in soap                                  # instance header literal
    assert "net.tcp://dc01.corp.local:9389" in soap
    assert "Dialect/LdapQuery" in soap and "(objectClass=computer)" in soap


def test_release_envelope_shape():
    env = _release_envelope("dc01.corp.local", "CTX-9")
    assert "enumeration/Release" in env
    assert "CTX-9" in env and "dc01.corp.local" in env


# --------------------------------------------------------------------------- #
# full source flow against a fake connection
# --------------------------------------------------------------------------- #
class FakeNMF:
    def __init__(self):
        self.sent = []
        self._pulls = 0

    def send(self, soap: str):
        self.sent.append(soap)

    def recv(self) -> str:
        last = self.sent[-1]
        if "transfer/Get" in last:
            return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                    f'xmlns:ad="{NS_AD}" xmlns:addata="{NS_ADDATA}">'
                    "<s:Body><addata:rootdse>"
                    "<addata:defaultNamingContext><ad:value>DC=corp,DC=local</ad:value></addata:defaultNamingContext>"
                    "</addata:rootdse></s:Body></s:Envelope>")
        if "/enumeration/Enumerate" in last:
            return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                    f'xmlns:wsen="{NS_WSEN}">'
                    "<s:Body><wsen:EnumerateResponse>"
                    "<wsen:EnumerationContext>CTX-1234</wsen:EnumerationContext>"
                    "</wsen:EnumerateResponse></s:Body></s:Envelope>")
        if "/enumeration/Release" in last:
            return "<s:Envelope/>"
        self._pulls += 1
        if self._pulls == 1:
            return PULL_XML.replace("__SID_B64__", b64.b64encode(_sid_bytes(WS01_SID)).decode())
        return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
                f'xmlns:wsen="{NS_WSEN}">'
                "<s:Body><wsen:PullResponse><wsen:Items/>"
                "<wsen:EndOfSequence/></wsen:PullResponse></s:Body></s:Envelope>")


class FakeADWSConnect:
    def __init__(self, fqdn, domain, username, auth, resource):
        self._nmf = FakeNMF()
        self._fqdn, self._domain, self._username = fqdn, domain, username
        self._auth = auth
        self._resource = resource

    def get_rootdse_contexts(self, remoteName, nmf):
        nmf.send(LDAP_ROOT_DSE_FSTRING.format(uuid="u1", fqdn=remoteName))
        et = ET.fromstring(nmf.recv())
        val = et.find(".//addata:defaultNamingContext/ad:value",
                      {"ad": NS_AD, "addata": NS_ADDATA})
        return {"defaultNamingContext": val.text.strip()}

    def _query_enumeration(self, remoteName, nmf, query, attributes,
                           base_object_dn_for_soap=None, use_schema=False, schema_dn=None):
        sel = "".join(f"<ad:SelectionProperty>addata:{a}</ad:SelectionProperty>" for a in attributes)
        soap = LDAP_QUERY_FSTRING.format(uuid="u2", fqdn=remoteName, query=query,
                                         attributes=sel, baseobj=base_object_dn_for_soap)
        nmf.send(soap)
        self._last_enumerate_soap = soap
        et = ET.fromstring(nmf.recv())
        ctx = et.find(".//wsen:EnumerationContext", {"wsen": NS_WSEN})
        return ctx.text if ctx is not None else None

    def _pull_results(self, remoteName, nmf, enum_ctx):
        nmf.send(f"<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope'>"
                 f"<s:Body xmlns:wsen='{NS_WSEN}'>"
                 f"<wsen:Pull><wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext>"
                 f"</wsen:Pull></s:Body></s:Envelope>")
        et = ET.fromstring(nmf.recv())
        more = et.find(".//wsen:EndOfSequence", {"wsen": NS_WSEN}) is None
        return et, more


def test_adws_list_computers_full_flow(monkeypatch):
    monkeypatch.setattr(adws_mod, "ADWSConnect", FakeADWSConnect)
    cred = Credential.from_args("password", "jdoe", "corp.local", password="pw")
    with AdwsSource(cred, "dc01.corp.local") as src:
        records = src.list_computers()
        fake = src._client
    assert len(records) == 1
    rec = records[0]
    assert rec.cn == "WS01"
    assert rec.dns_name == "ws01.corp.local"       # lowercase wire name -> canonical
    assert rec.sam_account == "WS01$"
    assert rec.is_dc is False
    assert rec.object_sid == WS01_SID              # base64 binary attr decoded
    assert len(rec.member_of) == 2                 # multi-valued preserved
    # base DN came from RootDSE, lowercase attrs + filter in the request
    assert "DC=corp,DC=local" in fake._last_enumerate_soap
    assert "addata:dnshostname" in fake._last_enumerate_soap
    assert "(objectClass=computer)" in fake._last_enumerate_soap
    # the enumeration context was released exactly once after the pull loop
    releases = [s for s in fake._nmf.sent if "/enumeration/Release" in s]
    assert len(releases) == 1


def test_adws_ntlm_hash_auth_selection(monkeypatch):
    captured = {}

    class Capturing(FakeADWSConnect):
        def __init__(self, fqdn, domain, username, auth, resource):
            captured["auth"], captured["user"] = auth, username
            super().__init__(fqdn, domain, username, auth, resource)

    monkeypatch.setattr(adws_mod, "ADWSConnect", Capturing)
    cred = Credential.from_args("ntlm", "jdoe", "corp.local", hashes=":" + "ab" * 16)
    with AdwsSource(cred, "dc01.corp.local") as src:
        src.default_naming_context()
    assert isinstance(captured["auth"], NTLMAuth)
    assert captured["auth"].nt == "ab" * 16      # bare NT hash per vendored convention
