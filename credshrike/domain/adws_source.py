"""ADWS source: computer search over the real ADWS transport.

ADWS on TCP 9389 is a WCF **net.tcp** service — NOT plain HTTP/SOAP:
MC-NMF framing → MS-NNS NegotiateStream (SPNEGO auth + mandatory per-message
sign/seal) → binary XML (MC-NBFSE 0x08) carrying WS-Transfer / WS-Enumeration
messages. The whole transport stack is vendored in :mod:`.adws` (Soaphound.py,
MIT); this module only adapts it to our ``DirectorySource`` interface:

- RootDSE via WS-Transfer Get on ``Windows/Resource`` → defaultNamingContext
  (replaces any "GetDomainControllerInfo" discovery — that action does not
  exist; the ``ad:instance`` header is the literal ``ldap:389``);
- search = WS-Enumeration ``Enumerate`` + ``Pull`` loop on
  ``Windows/Enumeration`` with the LdapQuery dialect; the enumeration context
  is connection-scoped, so Enumerate + every Pull ride the same NMF
  connection.

Auth mapping: password/NTLM hash → NTLM NegotiateStream; AES key / Kerberos
ticket → a ccache written to a temp file and exposed via KRB5CCNAME for the
connect call only (the env var is saved/restored; never left set).
"""

from __future__ import annotations

import base64
import logging
import os
import tempfile
from typing import Optional
from xml.etree import ElementTree as ET

from ..credentials import AuthType, Credential
from ..krbutil import ccache_from_tgt, ccache_to_bytes, load_ticket
from .adws import ADWSConnect, ADWSError, KerberosAuth, NTLMAuth
from .adws.soap_templates import NAMESPACES
from .base import (COMPUTER_ATTRS, DEFAULT_COMPUTER_FILTER, ComputerRecord,
                   computer_record_from_attributes)
from .ldap_source import decode_sid

LOG = logging.getLogger(__name__)

ADWS_PORT = 9389

# canonical (LDAP-cased) name -> lowercase wire name used by ADWS responses
_CANON_TO_LOWER = {a: a.lower() for a in COMPUTER_ATTRS}
_LOWER_TO_CANON = {v: k for k, v in _CANON_TO_LOWER.items()}

# attribute names whose values arrive base64-encoded (binary LDAP attrs)
BINARY_ATTRS = {"objectsid", "objectguid", "ntsecuritydescriptor", "sidhistory",
                "msds-allowedtoactonbehalfofotheridentity", "cacertificate"}


class AdwsError(RuntimeError):
    pass


class AdwsSource:
    name = "adws"

    def __init__(self, credential: Credential, dc: str, port: int = ADWS_PORT,
                 timeout: int = 30):
        if port != ADWS_PORT:
            LOG.warning("ADWS is fixed to port %d; ignoring port=%d", ADWS_PORT, port)
        self.credential = credential
        self.dc = dc
        self.timeout = timeout
        self._client: Optional[ADWSConnect] = None
        self._ccache_path: Optional[str] = None
        self._saved_krb5ccname: Optional[str] = None

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def connect(self) -> "AdwsSource":
        if self._client is not None:
            return self
        cred = self.credential
        cred.validate()
        if cred.is_kerberos:
            from ..krbutil import ensure_kdc
            ensure_kdc(cred)
        try:
            LOG.info("[ADWS] connecting to %s:9389 (net.tcp, %s auth)",
                     self.dc, cred.auth_type.value)
            if cred.auth_type in (AuthType.PASSWORD, AuthType.NTLM):
                # vendored NTLMAuth takes the BARE NT hash (its .nt feeds NNS)
                hashes = cred.nthash if cred.auth_type is AuthType.NTLM else None
                auth = NTLMAuth(password=cred.password or None, hashes=hashes or None)
            else:
                self._prepare_kerberos_ccache()
                auth = KerberosAuth(kdc_host=cred.kdc_host or None)
            self._client = ADWSConnect(self.dc, cred.domain, cred.username,
                                       auth, "Enumeration")
        except SystemExit as exc:  # vendored NNS raises SystemExit on auth failure
            self._restore_env()
            raise AdwsError(f"ADWS authentication failed: {exc}") from exc
        except ADWSError:
            self._restore_env()
            raise
        finally:
            self._restore_env()  # KRB5CCNAME only needs to exist during connect
        return self

    def _prepare_kerberos_ccache(self) -> None:
        """Materialize a ccache temp file for the vendored NNS client
        (ticket: converted as-is; AES key: TGT fetched first)."""
        cred = self.credential
        if cred.auth_type is AuthType.TICKET:
            ccache = load_ticket(cred.ticket_path)
        else:
            from impacket.krb5.kerberosv5 import getKerberosTGT
            from impacket.krb5 import types as krb5_types
            from impacket.krb5 import constants
            user = krb5_types.Principal(cred.username,
                                        type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            tgt_blob, _cipher, client_key, session_key = getKerberosTGT(
                user, "", cred.domain, "", "", cred.aes_key, cred.kdc_host or None)
            ccache = ccache_from_tgt(tgt_blob, client_key, session_key,
                                     cred.username, cred.domain)
        fd, path = tempfile.mkstemp(prefix="credshrike_adws_", suffix=".ccache")
        with os.fdopen(fd, "wb") as fh:
            fh.write(ccache_to_bytes(ccache))
        self._ccache_path = path
        self._saved_krb5ccname = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = path

    def _restore_env(self) -> None:
        if self._saved_krb5ccname is not None or "KRB5CCNAME" in os.environ:
            if self._saved_krb5ccname is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = self._saved_krb5ccname
            self._saved_krb5ccname = None

    def close(self) -> None:
        if self._client is not None:
            sock = getattr(self._client._nmf, "_sock", None)
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self._client = None
        if self._ccache_path and os.path.exists(self._ccache_path):
            try:
                os.unlink(self._ccache_path)
            except OSError:
                pass
        self._ccache_path = None
        self._restore_env()

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()

    # ------------------------------------------------------------------ #
    # queries
    # ------------------------------------------------------------------ #
    def default_naming_context(self) -> str:
        client = self.connect()._client
        contexts = client.get_rootdse_contexts(self.dc, client._nmf)
        return contexts.get("defaultNamingContext") or ""

    def list_computers(self, filter_ext: str = "",
                       attrs: Optional[list[str]] = None) -> list[ComputerRecord]:
        client = self.connect()._client
        wanted = list(attrs or COMPUTER_ATTRS)
        base = self.default_naming_context()
        search_filter = f"(&{DEFAULT_COMPUTER_FILTER}{filter_ext})" if filter_ext \
            else DEFAULT_COMPUTER_FILTER

        ctx = client._query_enumeration(
            self.dc, client._nmf, search_filter,
            [a.lower() for a in wanted],          # ADWS wants lowercase names
            base_object_dn_for_soap=base,
        )
        if ctx is None:
            raise AdwsError("ADWS enumeration returned no EnumerationContext "
                            "(filter rejected or fault)")

        records: list[ComputerRecord] = []
        try:
            while True:
                items_et, more = client._pull_results(self.dc, client._nmf, ctx)
                if items_et is None:
                    break
                for raw in self._parse_items(items_et):
                    records.append(computer_record_from_attributes(
                        {_LOWER_TO_CANON.get(k, k): v for k, v in raw.items()}))
                if not more:
                    break
        finally:
            # be a good citizen: release the enumeration context
            # (max 5 active contexts per session, 30-min expiry)
            self._release(client, ctx)
        return records

    def _release(self, client, ctx: str) -> None:
        """Best-effort Release of the enumeration context (max 5 active per
        session — leaking them degrades the connection for later queries)."""
        soap = _release_envelope(self.dc, ctx)
        try:
            client._nmf.send(soap)
            client._nmf.recv()
        except Exception as exc:  # noqa: BLE001 - release is best effort
            LOG.debug("enumeration release failed (ignored): %s", exc)

    # ------------------------------------------------------------------ #
    # parsing
    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse_items(pull_et) -> list[dict[str, list[str]]]:
        """Pull response → list of {attr: [values]}. Objects are the children
        of ``wsen:Items`` (tag = objectClass, e.g. addata:computer); each
        attribute element carries one or more ``ad:value`` children. Binary
        attrs arrive base64-encoded."""
        objects: list[dict[str, list[str]]] = []
        items = pull_et.find(".//wsen:Items", NAMESPACES)
        if items is None:
            return objects
        for obj in items:
            attrs: dict[str, list[str]] = {}
            dn = obj.get("dn") if hasattr(obj, "get") else None
            if dn:
                attrs["distinguishedName"] = [dn]
            for attr_elem in obj:
                name = _localname(attr_elem.tag)
                if not name:
                    continue
                values = [v.text or "" for v in attr_elem if _localname(v.tag) == "value"]
                values = [v for v in values if v != ""] or \
                         ([attr_elem.text.strip()] if attr_elem.text and attr_elem.text.strip() else [])
                if name in BINARY_ATTRS and values:
                    try:
                        values = [decode_sid(base64.b64decode(values[0]))
                                  if name == "objectsid" else values[0]]
                    except Exception:  # noqa: BLE001 - keep raw on decode failure
                        pass
                if values:
                    attrs[name] = values
            if attrs:
                objects.append(attrs)
        return objects


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


_RELEASE_BODY = """<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
    xmlns:a="http://www.w3.org/2005/08/addressing">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Release</a:Action>
        <ad:instance xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory">ldap:389</ad:instance>
        <a:MessageID>urn:uuid:{uuid}</a:MessageID>
        <a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo>
        <a:To s:mustUnderstand="1">net.tcp://{fqdn}:9389/ActiveDirectoryWebServices/Windows/Enumeration</a:To>
    </s:Header>
    <s:Body xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
        <wsen:Release><wsen:EnumerationContext>{enum_ctx}</wsen:EnumerationContext></wsen:Release>
    </s:Body>
</s:Envelope>"""


def _release_envelope(fqdn: str, enum_ctx: str) -> str:
    import uuid
    return _RELEASE_BODY.format(uuid=uuid.uuid4(), fqdn=fqdn, enum_ctx=enum_ctx)
