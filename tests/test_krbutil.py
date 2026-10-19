"""kirbi -> ccache conversion against a synthetic KRB-CRED built with pyasn1.

pyasn1 note: components inside impacket's ASN.1 specs carry implicit context
tags, so values must be cloned from the initialized schema component — never
built from the bare top-level classes.
"""

from datetime import datetime, timedelta

from pyasn1.codec.der import encoder
from pyasn1.type import univ

from impacket.krb5.asn1 import (EncKrbCredPart, EncryptedData, KRB_CRED,
                                KrbCredInfo, Ticket)
from impacket.krb5.ccache import CCache

from credshrike.krbutil import kirbi_to_ccache, load_ticket


def _set(parent, name, value=None):
    """Initialize an optional tagged component and optionally set its value."""
    parent.setComponentByName(name)
    if value is not None:
        parent[name] = parent[name].clone(value)
    return parent[name]


def _krbtime(parent, name, offset_hours: int):
    base = datetime(2026, 10, 7, 12, 0, 0) + timedelta(hours=offset_hours)
    return _set(parent, name, base.strftime("%Y%m%d%H%M%SZ"))


def _principal(parent, name, name_type: int, components: list[str]):
    comp = _set(parent, name)
    _set(comp, "name-type", name_type)
    seq = _set(comp, "name-string")
    for c in components:
        seq.append(c)
    return comp


def _build_ticket() -> Ticket:
    t = Ticket()
    _set(t, "tkt-vno", 5)
    _set(t, "realm", "CORP.LOCAL")
    _principal(t, "sname", 2, ["cifs", "filesrv01.corp.local"])
    enc = _set(t, "enc-part")
    _set(enc, "etype", 18)
    _set(enc, "kvno", 2)
    _set(enc, "cipher", b"\x01" * 32)
    return t


def build_kirbi() -> bytes:
    info = KrbCredInfo()
    key = _set(info, "key")
    _set(key, "keytype", 18)
    _set(key, "keyvalue", b"\x02" * 32)
    _set(info, "prealm", "CORP.LOCAL")
    _principal(info, "pname", 1, ["jdoe"])
    _set(info, "flags", "1" + "0" * 31)  # forwardable (bit 0)
    _krbtime(info, "authtime", 0)
    _krbtime(info, "starttime", 0)
    _krbtime(info, "endtime", 10)
    _krbtime(info, "renew-till", 240)
    _set(info, "srealm", "CORP.LOCAL")
    _principal(info, "sname", 2, ["krbtgt", "CORP.LOCAL"])

    enc_part = EncKrbCredPart()
    enc_part.setComponentByName("ticket-info")
    enc_part["ticket-info"].append(info)

    tickets = univ.SequenceOf()
    tickets.append(_build_ticket())

    cred = KRB_CRED()
    _set(cred, "pvno", 5)
    _set(cred, "msg-type", 22)
    tickets_comp = _set(cred, "tickets")
    for t in tickets:
        tickets_comp.append(t)
    enc_data = _set(cred, "enc-part")
    _set(enc_data, "etype", 0)  # NULL etype: EncKrbCredPart travels in cleartext
    _set(enc_data, "cipher", encoder.encode(enc_part))
    return encoder.encode(cred)


def test_kirbi_to_ccache_roundtrip():
    ccache = kirbi_to_ccache(build_kirbi())
    assert isinstance(ccache, CCache)
    assert len(ccache.credentials) == 1
    cred = ccache.credentials[0]
    assert cred["client"].prettyPrint() == b"jdoe@CORP.LOCAL"
    assert cred["server"].prettyPrint() == b"krbtgt/CORP.LOCAL@CORP.LOCAL"
    assert cred["key"]["keytype"] == 18
    assert cred["key"]["keyvalue"] == b"\x02" * 32
    assert cred["time"]["endtime"] > cred["time"]["starttime"]
    # ticket blob must be valid DER of the original Ticket
    from pyasn1.codec.der import decoder
    from impacket.krb5.asn1 import Ticket as TicketSpec
    decoded = decoder.decode(bytes(cred.ticket["data"]), asn1Spec=TicketSpec())[0]
    assert int(decoded["tkt-vno"]) == 5


def test_getcredential_finds_tgt_after_conversion():
    ccache = kirbi_to_ccache(build_kirbi())
    found = ccache.getCredential("krbtgt/CORP.LOCAL@CORP.LOCAL")
    assert found is not None
    # extract_for_spn should hand back domain/user + a TGT usable by kerberosLogin
    from credshrike.krbutil import extract_for_spn
    domain, user, tgt, tgs = extract_for_spn(ccache, spn="cifs/filesrv01.corp.local")
    assert domain == "CORP.LOCAL" and user == "jdoe"
    assert tgt is not None and tgs is None
    # the TGT dict carries the AS_REP + session key the SMB stack expects
    assert set(tgt) >= {"KDC_REP", "cipher", "sessionKey"}
    assert tgt["KDC_REP"]


def test_load_ticket_dispatches_by_magic(tmp_path):
    kirbi = tmp_path / "tkt.kirbi"
    kirbi.write_bytes(build_kirbi())
    ccache = load_ticket(str(kirbi))
    assert len(ccache.credentials) == 1

    # a real ccache file: serialize the converted cache back out
    from credshrike.krbutil import ccache_to_bytes
    ccache2_path = tmp_path / "tkt.ccache"
    ccache2_path.write_bytes(ccache_to_bytes(ccache))
    loaded = load_ticket(str(ccache2_path))
    assert loaded.credentials[0]["server"].prettyPrint() == b"krbtgt/CORP.LOCAL@CORP.LOCAL"
    assert loaded.credentials[0]["key"]["keyvalue"] == b"\x02" * 32


def test_load_ticket_rejects_garbage(tmp_path):
    bad = tmp_path / "garbage.bin"
    bad.write_bytes(b"\x00\x01\x02\x03junk")
    try:
        load_ticket(str(bad))
        raised = False
    except ValueError:
        raised = True
    assert raised
