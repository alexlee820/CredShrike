# Vendored from https://github.com/j4s0nmo0n/Soaphound.py (MIT, see LICENSE
# in this directory). Local changes: relative imports fixed for the
# smbenum package layout; no functional changes.

import datetime
import logging
import socket
import struct

import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from impacket.hresult_errors import ERROR_MESSAGES
from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, AP_REQ, Authenticator, EncAPRepPart, TGS_REP, seq_set
from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import (
    GSSAPI,
    GSS_C_CONF_FLAG,
    GSS_C_INTEG_FLAG,
    GSS_C_MUTUAL_FLAG,
    GSS_C_REPLAY_FLAG,
    GSS_C_SEQUENCE_FLAG,
    KRB5_AP_REQ,
    CheckSumField,
)
# RFC 4121 constants used by our GSS_Wrap_LDAP / GSS_Unwrap_LDAP fallback
# for impacket versions older than 0.13 that do not expose these methods.
try:
    from impacket.krb5.gssapi import KG_USAGE_INITIATOR_SEAL, KG_USAGE_ACCEPTOR_SEAL
except ImportError:
    # RFC 4121 values in case they are not exposed by impacket
    KG_USAGE_INITIATOR_SEAL = 24
    KG_USAGE_ACCEPTOR_SEAL = 22
from impacket.krb5.kerberosv5 import getKerberosTGS
from impacket.krb5.types import KerberosTime, Principal, Ticket
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from .encoder.records.utils import Net7BitInteger

KRB5_AP_REP = b"\x02\x00"


# ---------------------------------------------------------------------------
# Compatibility fallback for impacket versions without GSS_Wrap_LDAP
# ---------------------------------------------------------------------------
# The GSSAPI_AES{128,256}.GSS_Wrap_LDAP and GSS_Unwrap_LDAP methods were only
# added to impacket starting in version 0.13. On older versions (0.11/0.12,
# still shipped on Parrot OS, Kali stable, etc.) we re-implement the same
# logic here using the primitives available in impacket and pycryptodomex.
# toutes les versions: WRAP(), cipherType(), rotate(), unrotate().
# RFC 4121 §4.2.6.2: the AP-REP from the KDC provides the sub-key, RRC is 28
# when encryption is requested.

def _gss_wrap_ldap_aes_compat(gss, sessionKey, data, sequenceNumber):
    """Equivalent de GSSAPI_AES.GSS_Wrap_LDAP pour impacket < 0.13.

    Returns (cipherText, header) where header is the RFC 4121 WRAP token
    and cipherText the full encrypted+rotated payload.
    """
    token = gss.WRAP()
    cipher = gss.cipherType()

    # En LDAP/ADWS: pas de padding (use_padding=False)
    pad = 0
    rrc = 28

    token['Flags'] = 6
    token['EC'] = pad
    token['RRC'] = 0
    token['SND_SEQ'] = struct.pack('>Q', sequenceNumber)

    cipherText = cipher.encrypt(
        sessionKey, KG_USAGE_INITIATOR_SEAL, data + token.getData(), None
    )
    token['RRC'] = rrc
    cipherText = gss.rotate(cipherText, token['RRC'] + token['EC'])

    return cipherText, token.getData()


def _gss_unwrap_ldap_aes_compat(gss, sessionKey, data, sequenceNumber, direction='accept'):
    """Equivalent de GSSAPI_AES.GSS_Unwrap_LDAP pour impacket < 0.13."""
    cipher = gss.cipherType()
    token = gss.WRAP(data[:16])
    rotated = data[16:]

    cipherText = gss.unrotate(rotated, token['RRC'] + token['EC'])
    plainText = cipher.decrypt(sessionKey, KG_USAGE_ACCEPTOR_SEAL, cipherText)

    return plainText[:-(token['EC'] + 16)], None


def _gss_wrap_ldap(gss, sessionKey, data, sequenceNumber):
    """Wrapper qui utilise GSS_Wrap_LDAP s'il existe, sinon notre fallback."""
    if hasattr(gss, 'GSS_Wrap_LDAP'):
        return gss.GSS_Wrap_LDAP(sessionKey, data, sequenceNumber)
    return _gss_wrap_ldap_aes_compat(gss, sessionKey, data, sequenceNumber)


def _gss_unwrap_ldap(gss, sessionKey, data, sequenceNumber, direction='accept'):
    """Wrapper qui utilise GSS_Unwrap_LDAP s'il existe, sinon notre fallback."""
    if hasattr(gss, 'GSS_Unwrap_LDAP'):
        return gss.GSS_Unwrap_LDAP(sessionKey, data, sequenceNumber, direction=direction)
    return _gss_unwrap_ldap_aes_compat(gss, sessionKey, data, sequenceNumber, direction)



def hexdump(data, length=16):
    def to_ascii(byte):
        if 32 <= byte <= 126:
            return chr(byte)
        else:
            return "."

    def format_line(offset, line_bytes):
        hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
        ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
        return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

    lines = []
    for i in range(0, len(data), length):
        line_bytes = data[i : i + length]
        lines.append(format_line(i, line_bytes))

    return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
    structure: tuple[tuple[str, str], ...]

    def send(self, sock: socket.socket):
        sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
    structure = (
        ("message_id", ">B"),
        ("major_version", ">B"),
        ("minor_version", ">B"),
        ("payload_len", ">H-payload"),
        ("payload", ":"),
    )

    # During negotitiate, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ NTLMSSP

    # For Kerberos
    # NNS Headers
    # |_ Payload ( GSS-API )
    #   |_ SPNEGO ( NegTokenInit )
    #     |_ krb5_blob
    #       |_ Kerberos ( AP REQ )

    ###

    # During challenge, payload will be the GSSAPI, containing SPNEGO
    # w/ NTLMSSP for NTLM or
    # w/ krb5_blob for the AP REQ)

    # For NTLM
    # NNS Headers
    # |_ Payload ( GSS-API, SPNEGO, no GSS-API headers )
    #     |_ NegTokenTarg ( NegTokenResp )
    #       |_ NTLMSSP

    def __init__(
        self, message_id: int, major_version: int, minor_version: int, payload: bytes
    ):
        impacket.structure.Structure.__init__(self)
        self["message_id"] = message_id
        self["major_version"] = major_version
        self["minor_version"] = minor_version
        self["payload"] = payload


class NNS_data(NNS_pkt):
    # NNS data message, used after auth is completed

    structure = (
        ("payload_size", "<L-payload"),
        ("payload", ":"),
    )


class NNS_Signed_payload(impacket.structure.Structure):
    structure = (
        ("signature", ":"),
        ("cipherText", ":"),
    )


class MessageID:
    IN_PROGRESS: int = 0x16
    ERROR: int = 0x15
    DONE: int = 0x14


def _decode_der_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first < 0x80:
        return first, offset

    length_size = first & 0x7F
    return int.from_bytes(data[offset : offset + length_size], "big"), offset + length_size


def _unwrap_gss_mech_token(data: bytes) -> bytes:
    if not data.startswith(b"\x60"):
        raise ValueError("GSS mechanism token must start with APPLICATION 0")

    token_length, offset = _decode_der_length(data, 1)
    token = data[offset : offset + token_length]
    if not token.startswith(b"\x06"):
        raise ValueError("GSS mechanism token missing OID")

    oid_length, oid_value_offset = _decode_der_length(token, 1)
    return token[oid_value_offset + oid_length :]


class NNS:
    """[MS-NNS]: .NET NegotiateStream Protocol

    The .NET NegotiateStream Protocol provides mutually authenticated
    and confidential communication over a TCP connection.

    It defines a framing mechanism used to transfer (GSS-API) security tokens
    between a client and server. It also defines a framing mechanism used
    to transfer signed and/or encrypted application data once the GSS-API
    security context initialization has completed.
    """

    def __init__(
        self,
        socket: socket.socket,
        fqdn: str,
        domain: str,
        username: str,
        password: str | None = None,
        nt: str = "",
        lm: str = "",
        auth_protocol: str = "ntlm",
        kdc_host: str | None = None,
    ):
        self._sock = socket

        self._nt = self._fix_hashes(nt)
        self._lm = self._fix_hashes(lm)

        self._username = username
        self._password = password

        self._domain = domain
        self._fqdn = fqdn
        self._auth_protocol = auth_protocol
        self._kdc_host = kdc_host

        self._session_key: bytes = b""
        self._flags: int = -1
        self._sequence: int = 0
        self._server_sequence: int = 0
        self._gss = None

    def _recv_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self._sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Connection closed while reading NNS data")
            data += chunk
        return data

    def _recv_handshake(self) -> NNS_handshake:
        return NNS_handshake(
            message_id=int.from_bytes(self._recv_exact(1), "big"),
            major_version=int.from_bytes(self._recv_exact(1), "big"),
            minor_version=int.from_bytes(self._recv_exact(1), "big"),
            payload=self._recv_exact(int.from_bytes(self._recv_exact(2), "big")),
        )

    def _raise_auth_error(self, auth_name: str, nns_msg: NNS_handshake) -> None:
        if nns_msg["message_id"] != MessageID.ERROR:
            return

        error_code = int.from_bytes(nns_msg["payload"], "big")
        err_type, err_msg = ERROR_MESSAGES.get(
            error_code,
            (f"0x{error_code:08x}", "Unknown error"),
        )
        raise SystemExit(f"[-] {auth_name} Auth Failed with error {err_type} {err_msg}")

    def auth(self) -> None:
        if self._auth_protocol == "kerberos":
            self.auth_krb()
            return

        self.auth_ntlm()

    def _fix_hashes(self, hash: str | bytes) -> bytes | str:
        """fixes up hash if present into bytes and
        ensures length is 32.

        If no hash is present, returns empty bytes

        Args:
            hash (str | bytes): nt or lm hash

        Returns:
            bytes: bytes version
        """

        if not hash:
            return ""

        if len(hash) % 2:
            hash = hash.zfill(32)

        return bytes.fromhex(hash) if isinstance(hash, str) else hash

    def seal(self, data: bytes) -> tuple[bytes, bytes]:
        """seals data with the current context

        Args:
            data (bytes): bytes to seal

        Returns:
            tuple[bytes, bytes]: output_data, signature
        """

        server = bool(
            self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        )

        output, sig = impacket.ntlm.SEAL(
            self._flags,
            self._server_signing_key if server else self._client_signing_key,
            self._server_sealing_key if server else self._client_sealing_key,
            data,
            data,
            self._sequence,
            self._server_sealing_handle if server else self._client_sealing_handle,
        )

        return output, sig.getData()

    def recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.

        Args:
            _ (int, optional): For interoperability with socket.socket. Defaults to 0.

        Returns:
            bytes: unsealed nns message
        """
        first_pkt = self._recv()

        # if it isnt an envelope, throw it back
        if first_pkt[0] != 0x06:
            return first_pkt

        nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

        # its all just one packet
        if nmfsize < 0xFC30:
            return first_pkt

        # otherwise, we have a multi part message
        pkt = first_pkt
        nmfsize -= len(first_pkt[nmflenlen:])

        while nmfsize > 0:
            thisFragment = self._recv()

            pkt += thisFragment
            nmfsize -= len(thisFragment)

        return pkt

    def _recv(self, _: int = 0) -> bytes:
        """Recive an NNS packet and return the entire
        decrypted contents.

        The paramiter is used to allow interoperability with socket.socket.recv.
        Does not respect any passed buffer sizes.
        """
        nns_data = NNS_data()
        size = int.from_bytes(self._recv_exact(4), "little")

        payload = self._recv_exact(size)
        nns_data["payload"] = payload

        if self._auth_protocol == "kerberos":
            clear_text = self._kerberos_unwrap(nns_data["payload"])
            logging.debug(
                "Kerberos NNS recv seq=%d payload=%s clear=%s",
                self._server_sequence,
                nns_data["payload"][:16].hex(),
                clear_text[:16].hex(),
            )
            self._server_sequence += 1
            return clear_text

        nns_signed_payload = NNS_Signed_payload()
        nns_signed_payload["signature"] = nns_data["payload"][0:16]
        nns_signed_payload["cipherText"] = nns_data["payload"][16:]

        clearText, sig = self.seal(nns_signed_payload["cipherText"])
        return clearText

    def sendall(self, data: bytes):
        """Send to server in sealed NNS data packet via tcp socket.

        Args:
            data (bytes): utf-16le encoded payload data
        """

        pkt = NNS_data()

        if self._auth_protocol == "kerberos":
            cipherText, sig = _gss_wrap_ldap(
                self._gss,
                self._session_key,
                data,
                self._sequence,
            )
            pkt["payload"] = sig + cipherText
            logging.debug(
                "Kerberos NNS send seq=%d clear=%s payload=%s",
                self._sequence,
                data[:16].hex(),
                pkt["payload"][:16].hex(),
            )
        else:
            cipherText, sig = impacket.ntlm.SEAL(
                self._flags,
                self._client_signing_key,
                self._client_sealing_key,
                data,
                data,
                self._sequence,
                self._client_sealing_handle,
            )

            # then we build the payload, which is the signature prepended
            # on the actual ciphertext.  This goes in the payload of
            # the NNS data packet
            payload = NNS_Signed_payload()
            payload["signature"] = sig
            payload["cipherText"] = cipherText
            pkt["payload"] = payload.getData()

        self._sock.sendall(pkt.getData())

        # and we increment the sequence number after sending
        self._sequence += 1

    def _build_kerberos_blob(self) -> tuple[object, object, bytes]:
        target = f"LDAP/{self._fqdn}"
        domain, username, tgt, tgs = CCache.parseFile(
            domain=self._domain,
            username=self._username,
            target=target,
        )
        self._domain = domain
        self._username = username

        if tgs is not None:
            tgs_bytes = tgs["KDC_REP"]
            cipher = tgs["cipher"]
            session_key = tgs["sessionKey"]
        else:
            if tgt is None:
                raise SystemExit(
                    "[-] Kerberos authentication requires a usable TGS or TGT in KRB5CCNAME"
                )

            logging.debug("Could not find an LDAP TGS in cache, requesting one with cached TGT")
            server_principal = Principal(
                target,
                type=constants.PrincipalNameType.NT_SRV_INST.value,
            )
            tgs_bytes, cipher, _, session_key = getKerberosTGS(
                serverName=server_principal,
                domain=self._domain,
                kdcHost=self._kdc_host or self._fqdn,
                tgt=tgt["KDC_REP"],
                cipher=tgt["cipher"],
                sessionKey=tgt["sessionKey"],
            )

        tgs_rep = decoder.decode(tgs_bytes, asn1Spec=TGS_REP())[0]
        self._domain = str(tgs_rep["crealm"])
        service_ticket = Ticket()
        service_ticket.from_asn1(tgs_rep["ticket"])

        user_principal = Principal(
            self._username,
            type=constants.PrincipalNameType.NT_PRINCIPAL.value,
        )

        ap_req = AP_REQ()
        ap_req["pvno"] = 5
        ap_req["msg-type"] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        ap_req["ap-options"] = constants.encodeFlags(
            [constants.APOptions.mutual_required.value]
        )
        seq_set(ap_req, "ticket", service_ticket.to_asn1)

        authenticator = Authenticator()
        authenticator["authenticator-vno"] = 5
        authenticator["crealm"] = self._domain
        seq_set(authenticator, "cname", user_principal.components_to_asn1)

        now = datetime.datetime.now(datetime.timezone.utc)
        authenticator["cusec"] = now.microsecond
        authenticator["ctime"] = KerberosTime.to_asn1(now)

        authenticator["cksum"] = noValue
        authenticator["cksum"]["cksumtype"] = 0x8003
        checksum = CheckSumField()
        checksum["Lgth"] = 16
        checksum["Flags"] = (
            GSS_C_CONF_FLAG
            | GSS_C_INTEG_FLAG
            | GSS_C_MUTUAL_FLAG
            | GSS_C_REPLAY_FLAG
            | GSS_C_SEQUENCE_FLAG
        )
        authenticator["cksum"]["checksum"] = checksum.getData()
        authenticator["seq-number"] = 0

        encrypted_authenticator = cipher.encrypt(
            session_key,
            11,
            encoder.encode(authenticator),
            None,
        )
        ap_req["authenticator"] = noValue
        ap_req["authenticator"]["etype"] = cipher.enctype
        ap_req["authenticator"]["cipher"] = encrypted_authenticator

        neg_token_init = impacket.spnego.SPNEGO_NegTokenInit()
        neg_token_init["MechTypes"] = [
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
        ]
        neg_token_init["MechToken"] = struct.pack(
            "B",
            impacket.spnego.ASN1_AID,
        ) + impacket.spnego.asn1encode(
            struct.pack("B", impacket.spnego.ASN1_OID)
            + impacket.spnego.asn1encode(
                impacket.spnego.TypesMech["KRB5 - Kerberos 5"]
            )
            + KRB5_AP_REQ
            + encoder.encode(ap_req)
        )

        return cipher, session_key, neg_token_init.getData()

    def _kerberos_unwrap(self, payload: bytes) -> bytes:
        if payload.startswith(b"\x60"):
            return self._kerberos_unwrap_rc4(payload)

        clear_text, _ = _gss_unwrap_ldap(
            self._gss,
            self._session_key,
            payload,
            self._server_sequence,
            direction="accept",
        )
        return clear_text

    def _kerberos_unwrap_rc4(self, payload: bytes) -> bytes:
        token_data = _unwrap_gss_mech_token(payload)
        wrap_len = len(self._gss.WRAP())
        wrap = self._gss.WRAP(token_data[:wrap_len])
        cipher_text = token_data[wrap_len:]

        kseq = HMAC.new(self._session_key.contents, struct.pack("<L", 0), MD5).digest()
        kseq = HMAC.new(kseq, wrap["SGN_CKSUM"], MD5).digest()
        snd_seq = ARC4.new(kseq).encrypt(wrap["SND_SEQ"])

        klocal = bytearray()
        for value in self._session_key.contents:
            klocal.append(value ^ 0xF0)

        kcrypt = HMAC.new(klocal, struct.pack("<L", 0), MD5).digest()
        kcrypt = HMAC.new(kcrypt, snd_seq[:4], MD5).digest()

        plain_text = ARC4.new(kcrypt).decrypt(wrap["Confounder"] + cipher_text)[8:]
        return plain_text[:-1]

    def _extract_kerberos_response_token(self, response_token: bytes) -> bytes:
        if response_token.startswith(b"\x60"):
            response_token = _unwrap_gss_mech_token(response_token)

        if response_token.startswith(KRB5_AP_REP):
            response_token = response_token[len(KRB5_AP_REP) :]

        return response_token

    def _process_ap_rep(self, cipher, session_key, payload: bytes) -> tuple[object, object]:
        neg_token_resp = impacket.spnego.SPNEGO_NegTokenResp(payload)
        if "ResponseToken" not in neg_token_resp.fields:
            return cipher, session_key

        response_token = self._extract_kerberos_response_token(
            neg_token_resp["ResponseToken"]
        )
        ap_rep = decoder.decode(response_token, asn1Spec=AP_REP())[0]
        plain_text = cipher.decrypt(session_key, 12, ap_rep["enc-part"]["cipher"])
        enc_ap_rep_part = decoder.decode(plain_text, asn1Spec=EncAPRepPart())[0]

        if enc_ap_rep_part["seq-number"].hasValue():
            self._server_sequence = int(enc_ap_rep_part["seq-number"])

        if enc_ap_rep_part["subkey"].hasValue():
            cipher = _enctype_table[int(enc_ap_rep_part["subkey"]["keytype"])]()
            session_key = Key(
                cipher.enctype,
                enc_ap_rep_part["subkey"]["keyvalue"].asOctets(),
            )

        return cipher, session_key

    def auth_krb(self) -> None:
        """Authenticate to the dest with Kerberos authentication from KRB5CCNAME."""

        cipher, session_key, nego_data = self._build_kerberos_blob()

        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=nego_data,
        ).send(self._sock)

        nns_msg_done = self._recv_handshake()
        self._raise_auth_error("Kerberos", nns_msg_done)
        if nns_msg_done["message_id"] != MessageID.DONE:
            raise ConnectionError(
                f"Unexpected Kerberos handshake response: {nns_msg_done['message_id']:#x}"
            )

        cipher, session_key = self._process_ap_rep(
            cipher,
            session_key,
            nns_msg_done["payload"],
        )

        self._session_key = session_key
        self._gss = GSSAPI(cipher)
        self._sequence = 0

    def auth_ntlm(self) -> None:
        """Authenticate to the dest with NTLMV2 authentication"""

        # Initial negotiation sent from client
        NegTokenInit: impacket.spnego.SPNEGO_NegTokenInit
        NtlmSSP_nego: impacket.ntlm.NTLMAuthNegotiate

        # Generate a NTLMSSP
        NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
            workstation="",  # These fields don't get populated for some reason
            domain="",  # These fields don't get populated for some reason
            signingRequired=True,  # TODO: Somehow determine this; can we send a Negotiate Protocol Request and derive this dynamically?
            use_ntlmv2=True,  # TODO: See above comment
        )

        # Generate the NegTokenInit
        # Impacket has this inherit from GSSAPI, so we will also have the OID and other headers :D
        NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
        NegTokenInit["MechTypes"] = [
            impacket.spnego.TypesMech[
                "NTLMSSP - Microsoft NTLM Security Support Provider"
            ],
            impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
            impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
            impacket.spnego.TypesMech[
                "NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
            ],
        ]
        NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

        # Fit it all into an NNS NTLMSSP_NEGOTIATE Message
        # Begin authentication ( NTLMSSP_NEGOTIATE )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=NegTokenInit.getData(),
        ).send(self._sock)

        # Response with challenge from server
        NNS_msg_chall: NNS_handshake
        s_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall: impacket.ntlm.NTLMAuthChallenge

        # Receive the NNS NTLMSSP_Challenge
        NNS_msg_chall = self._recv_handshake()
        self._raise_auth_error("NTLM", NNS_msg_chall)

        # Extract the NegTokenResp ( NegTokenTarg )
        # Note: Potentially consider SupportedMech from s_NegTokenTarg for determining stuff like signing?
        s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

        # Create an NtlmAuthChallenge from the NTLMSSP ( ResponseToken )
        NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

        # TODO: see if this is relevant https://github.com/fortra/impacket/blob/15eff8805116007cfb59332a64194a5b9c8bcf25/impacket/smb3.py#L1015
        # if NTLMSSP_chall[ 'TargetInfoFields_len' ] > 0:
        #     av_pairs   = impacket.ntlm.AV_PAIRS( NTLMSSP_chall[ 'TargetInfoFields' ][ :NTLMSSP_chall[ 'TargetInfoFields_len' ] ] )
        #     if av_pairs[ impacket.ntlm.NTLMSSP_AV_HOSTNAME ] is not None:
        #         print( "TODO AV PAIRS IDK IF ITS RELEVANT" )

        # Response with authentication from client
        c_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
        NTLMSSP_chall_resp: impacket.ntlm.NTLMAuthChallengeResponse

        # Create the NTLMSSP challenge response
        # If password is used, then the lm and nt hashes must be pass
        # an empty str, NOT, empty byte str.......
        NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
            type1=NtlmSSP_nego,
            type2=NTLMSSP_chall.getData(),
            user=self._username,
            password=self._password,
            domain=self._domain,
            lmhash=self._lm,
            nthash=self._nt,
        )

        # set up info for crypto
        self._flags = NTLMSSP_chall_resp["flags"]
        self._sequence = 0

        if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            logging.debug("We are doing extended ntlm security")
            self._client_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key
            )
            self._server_signing_key = impacket.ntlm.SIGNKEY(
                self._flags, self._session_key, "Server"
            )
            self._client_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key
            )
            self._server_sealing_key = impacket.ntlm.SEALKEY(
                self._flags, self._session_key, "Server"
            )

            # prepare keys to handle states
            cipher1 = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher1.encrypt
            cipher2 = ARC4.new(self._server_sealing_key)
            self._server_sealing_handle = cipher2.encrypt

        else:
            logging.debug("We are doing basic ntlm auth")
            # same key for both ways
            self._client_signing_key = self._session_key
            self._server_signing_key = self._session_key
            self._client_sealing_key = self._session_key
            self._server_sealing_key = self._session_key
            cipher = ARC4.new(self._client_sealing_key)
            self._client_sealing_handle = cipher.encrypt
            self._server_sealing_handle = cipher.encrypt

        # Fit the challenge response into the ResponseToken of our NegTokenTarg
        c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
        c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

        # Fit our challenge response into an NNS message
        # Send the NTLMSSP_AUTH ( challenge response )
        NNS_handshake(
            message_id=MessageID.IN_PROGRESS,
            major_version=1,
            minor_version=0,
            payload=c_NegTokenTarg.getData(),
        ).send(self._sock)

        # Response from server ending handshake
        NNS_msg_done: NNS_handshake

        # Check for success
        NNS_msg_done = self._recv_handshake()

        # check for errors
        self._raise_auth_error("NTLM", NNS_msg_done)
        if NNS_msg_done["message_id"] != MessageID.DONE:
            raise ConnectionError(
                f"Unexpected NTLM handshake response: {NNS_msg_done['message_id']:#x}"
            )
