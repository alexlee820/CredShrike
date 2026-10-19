"""AISafetySMBEnum — multi-auth SMB enumeration, LDAP/ADWS domain queries,
and a capability-limited LLM agent.

The package is layered bottom-up:

- :mod:`credshrike.credentials` / :mod:`credshrike.krbutil` — unified credential
  model (password / NTLM hash / AES256 key / Kerberos ticket) materialized
  for each downstream protocol.
- :mod:`credshrike.smb_session` — read-only SMB browsing (shares, directories,
  files) plus security-descriptor queries and effective-access probes.
- :mod:`credshrike.acl` — pure-python parsing of self-relative security
  descriptors, access-mask decoding and SID resolution.
- :mod:`credshrike.domain` — unified domain computer queries over LDAP or ADWS.
- :mod:`credshrike.agent` — the constrained agent loop: the LLM can only call
  the read-only tool registry, enforced by the executor (not the prompt).
"""

__version__ = "0.1.0"
