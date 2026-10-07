"""ADWS transport stack, vendored from Soaphound.py (MIT, © j4s0nmo0n — see
LICENSE in this directory).

ADWS (Active Directory Web Services, TCP 9389) is a WCF **net.tcp** service,
not HTTP. The stack has four layers:

- ``ms_nmf`` — MC-NMF (.NET Message Framing) record framing + connection
  preamble/upgrade dance;
- ``ms_nns`` — MS-NNS (.NET NegotiateStream): SPNEGO auth (NTLM incl. hash,
  or Kerberos via KRB5CCNAME) with MANDATORY per-message sign/seal;
- ``encoder`` — MC-NBFSE binary XML codec (encoding 0x08 — the server
  rejects text XML);
- ``soap_templates`` + ``adws_client`` — WS-Transfer Get (RootDSE) and
  WS-Enumeration Enumerate/Pull (search) over the ``Windows/Resource`` and
  ``Windows/Enumeration`` endpoints.

Local changes: relative imports adjusted for the smbenum package layout and
the ``impacket.examples.logger`` side-effect import removed. No functional
changes; keep this directory in sync with upstream if it gets fixes.
"""

from .adws_client import ADWSConnect, ADWSError, NTLMAuth, KerberosAuth  # noqa: F401
