"""Kerberos helpers: ticket loading (.ccache / .kirbi), TGT/TGS extraction,
and KDC discovery.

The kirbi (Rubeus KRB-CRED, ASN.1) -> ccache conversion is done in memory:
we decode the KRB-CRED with pyasn1 using impacket's ASN.1 specs and rebuild
an ``impacket.krb5.ccache.CCache`` object directly, so no temp files and no
KRB5CCNAME environment mutation ever happen.
"""

from __future__ import annotations

import calendar
import logging
from datetime import datetime

from impacket.krb5.asn1 import EncKrbCredPart, KRB_CRED
from impacket.krb5.ccache import CCache, CountedOctetString, Credential, KeyBlockV4, Principal, Times
from impacket.krb5 import types as krb5_types

LOG = logging.getLogger(__name__)

KRB_TIME_FMT = "%Y%m%d%H%M%SZ"


# --------------------------------------------------------------------------- #
# ticket loading
# --------------------------------------------------------------------------- #
def load_ticket(path: str) -> CCache:
    """Load a Kerberos ticket file; dispatches on format, not extension.

    ccache files start with a 2-byte big-endian version (0x0503 / 0x0504);
    a KRB-CRED (kirbi) is DER with application tag 22 (0x76) as first byte.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if not data:
        raise ValueError(f"ticket file is empty: {path}")
    if data[0] == 0x76:  # DER application-constructed [22] => KRB-CRED
        return kirbi_to_ccache(data)
    if data[:2] in (b"\x05\x04", b"\x05\x03"):
        return CCache(data)
    # fall back on extension guess before giving up
    if path.lower().endswith((".kirbi", ".kirbi.bin")):
        return kirbi_to_ccache(data)
    raise ValueError(f"unrecognized ticket format (first bytes {data[:4].hex()}): {path}")


# --------------------------------------------------------------------------- #
# kirbi -> ccache conversion (in memory)
# --------------------------------------------------------------------------- #
def _krbtime_to_posix(value) -> int:
    if value is None or not hasattr(value, "__str__") or not str(value):
        return 0
    try:
        dt = datetime.strptime(str(value), KRB_TIME_FMT)
        return int(calendar.timegm(dt.timetuple()))
    except ValueError:
        return 0


def _seq_to_str(seq) -> str:
    """Join principal name-string components with '/' (e.g. ['krbtgt','REALM']
    -> 'krbtgt/REALM'); a single component joins to itself."""
    if seq is None:
        return ""
    return "/".join(str(c) for c in seq)


def _comp(parent, name):
    """pyasn1-safe optional component access: returns the value or None when
    the optional component is absent from the decoded structure."""
    try:
        comp = parent.getComponentByName(name)
    except Exception:  # noqa: BLE001 - defensive against pyasn1 versions
        return None
    if comp is None or not getattr(comp, "isValue", True):
        return None
    return comp


def _build_principal(realm: str, name_type: int, components: str) -> Principal:
    # types.Principal expects the full 'comp1/comp2@REALM' form; the realm is
    # carried separately in KrbCredInfo so we re-attach it here
    full = f"{components}@{realm}" if realm and components else components
    principal = krb5_types.Principal(full, type=name_type)
    p = Principal()
    p.fromPrincipal(principal)
    return p


def kirbi_to_ccache(kirbi_bytes: bytes) -> CCache:
    """Convert a Rubeus-style .kirbi (KRB-CRED) into an impacket CCache."""
    from pyasn1.codec.der import decoder, encoder  # local import: pyasn1 is an impacket dep

    try:
        krb_cred = decoder.decode(kirbi_bytes, asn1Spec=KRB_CRED())[0]
    except Exception as exc:  # noqa: BLE001 - surface a readable error
        raise ValueError(f"not a valid KRB-CRED (.kirbi): {exc}") from exc

    enc_part = krb_cred["enc-part"]
    if int(enc_part["etype"]) != 0:  # KRBCRED enc-part uses NULL etype (cleartext)
        raise ValueError(f"unsupported KRB-CRED enc-part etype {int(enc_part['etype'])}")
    enc_krb_cred = decoder.decode(bytes(enc_part["cipher"]), asn1Spec=EncKrbCredPart())[0]
    infos = enc_krb_cred["ticket-info"]
    tickets = krb_cred["tickets"]

    ccache = CCache()
    first_client: Principal | None = None
    for index in range(len(tickets)):
        ticket = tickets[index]
        info = infos[index] if index < len(infos) else None
        key = _comp(info, "key") if info is not None else None

        prealm_comp = _comp(info, "prealm") if info is not None else None
        prealm = str(prealm_comp) if prealm_comp is not None else ""
        pname = _comp(info, "pname") if info is not None else None
        srealm_comp = _comp(info, "srealm") if info is not None else None
        srealm = str(srealm_comp) if srealm_comp is not None else prealm
        sname = _comp(info, "sname") if info is not None else None

        cred = Credential()
        ptype = int(_comp(pname, "name-type")) if pname is not None and _comp(pname, "name-type") else 1
        pstr = _seq_to_str(_comp(pname, "name-string")) if pname is not None else ""
        stype = int(_comp(sname, "name-type")) if sname is not None and _comp(sname, "name-type") else 2
        sstr = _seq_to_str(_comp(sname, "name-string")) if sname is not None else ""
        cred["client"] = _build_principal(prealm, ptype, pstr)
        cred["server"] = _build_principal(srealm, stype, sstr)

        kb = KeyBlockV4()
        kb["keytype"] = int(_comp(key, "keytype")) if key is not None and _comp(key, "keytype") else 0
        kb["etype"] = kb["keytype"]
        keyvalue = bytes(_comp(key, "keyvalue")) if key is not None and _comp(key, "keyvalue") else b""
        kb["keylen"] = len(keyvalue)
        kb["keyvalue"] = keyvalue
        cred["key"] = kb

        times = Times()
        for asn_field, ts_field in (("authtime", "authtime"), ("starttime", "starttime"),
                                    ("endtime", "endtime"), ("renew-till", "renew_till")):
            comp = _comp(info, asn_field) if info is not None else None
            times[ts_field] = _krbtime_to_posix(comp) if comp is not None else 0
        cred["time"] = times
        flags = _comp(info, "flags") if info is not None else None
        cred["tktflags"] = int(flags) if flags is not None else 0

        ticket_der = encoder.encode(ticket)
        octets = CountedOctetString()
        octets["length"] = len(ticket_der)
        octets["data"] = ticket_der
        cred.ticket = octets
        cred.secondTicket = CountedOctetString()
        cred.secondTicket["length"] = 0
        cred.secondTicket["data"] = b""

        if first_client is None:
            first_client = cred["client"]
        ccache.credentials.append(cred)

    if first_client is None:
        raise ValueError("KRB-CRED contains no tickets")
    ccache.principal = first_client
    ccache.headers = []  # required by CCache.getData() for serialization
    return ccache


def ccache_to_bytes(ccache: CCache) -> bytes:
    """Serialize an in-memory CCache (v4, zero header) back to file bytes —
    the inverse of ``CCache(data)`` for converted kirbi caches."""
    mini = CCache.MiniHeader()
    mini["headerlen"] = 0
    data = mini.getData()
    data += ccache.principal.getData()
    for cred in ccache.credentials:
        data += cred.getData()
    return data


def ccache_from_tgt(tgt_blob: bytes, client_key, session_key,
                    username: str, domain: str) -> CCache:
    """Build an in-memory CCache holding one TGT credential from
    ``getKerberosTGT`` output. NOTE impacket returns
    ``(as_rep, cipher, oldSessionKey, sessionKey)`` where oldSessionKey is
    the CLIENT key (used to decrypt the AS-REP enc-part) — fromTGT needs
    both. Storing the raw AS_REP as the ticket blob (instead of going
    through fromTGT) breaks ticket reuse, since toTGT() expects the inner
    Ticket DER."""
    ccache = CCache()
    ccache.fromTGT(tgt_blob, client_key, session_key)
    return ccache


# --------------------------------------------------------------------------- #
# TGT/TGS extraction
# --------------------------------------------------------------------------- #
def _as_text(value) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


def extract_for_spn(ccache: CCache, domain: str = "", username: str = "", spn: str = ""):
    """Return ``(domain, username, TGT, TGS)`` for a target SPN like
    ``cifs/filesrv01.corp.local`` — mirrors ``CCache.parseFile`` semantics
    (impacket 0.10 ships that logic only as a classmethod on the env cache).
    Prefers a matching TGS, falls back to the TGT (the SMB stack will then
    obtain the service ticket itself)."""
    if domain == "":
        domain = _as_text(ccache.principal.realm["data"])
    creds = None
    if spn:
        creds = ccache.getCredential(f"{spn.upper()}@{domain.upper()}")
    tgt = tgs = None
    if creds is None:
        creds = ccache.getCredential(f"krbtgt/{domain.upper()}@{domain.upper()}")
        if creds is not None:
            tgt = creds.toTGT()
    else:
        tgs = creds.toTGS(f"{spn.upper()}@{domain.upper()}")
    if username == "" and creds is not None:
        username = _as_text(creds["client"].prettyPrint().split(b"@")[0])
    elif username == "" and ccache.principal.components:
        username = _as_text(ccache.principal.components[0]["data"])
    return domain, username, tgt, tgs


# --------------------------------------------------------------------------- #
# KDC discovery
# --------------------------------------------------------------------------- #
def discover_kdc(domain: str) -> str:
    """Resolve a KDC hostname via the standard ``_ldap._tcp.dc._msdcs``
    SRV record. Returns the first target; raises if DNS has no answer."""
    import dns.resolver

    answer = dns.resolver.resolve(f"_ldap._tcp.dc._msdcs.{domain}", "SRV")
    for rr in answer:
        target = str(rr.target).rstrip(".")
        if target:
            return target
    raise ValueError(f"no SRV record found for domain {domain}")
