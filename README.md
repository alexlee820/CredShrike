# AISafetySMBEnum

Multi-auth SMB enumeration toolkit with LDAP/ADWS domain queries and a
**capability-limited LLM agent** — the agent can browse and inspect, and
nothing else. Built for authorized security assessments.

```
   auth (password | NTLM hash | AES256 key | Kerberos ticket ccache/kirbi)
                     │
      ┌──────────────┼──────────────────┐
      ▼              ▼                  ▼
  SMB (445)      LDAP (389/636)     ADWS (9389, WCF net.tcp)
  shares/dirs    computer objects   computer objects (LDAP alternative)
  read (capped)                     │
  DACLs + probes                    │
      └──────────────┬──────────────┘
                     ▼
            agent tool registry (READ-ONLY, by construction)
                     │  allowlist → scope → normalize → caps → budgets → audit
                     ▼
            LLM agent loop (Anthropic API) — REPL + one-shot
```

## Components

| Layer | What | Where |
|---|---|---|
| Credentials | 4 auth types, one model, redaction-safe | `smbenum/credentials.py` |
| Kerberos | ccache load, **kirbi→ccache in memory**, TGT/TGS extraction, KDC discovery | `smbenum/krbutil.py` |
| SMB | shares, dirs, capped reads, **file/dir security descriptors**, share ACLs (NetrShareGetInfo 502), **effective-access probes** | `smbenum/smb_session.py` |
| ACL | pure-python self-relative SD parser, access-mask decoding, SID resolution (well-known + LSA + static) | `smbenum/acl/` |
| Domain | LDAP (impacket client, paged) + ADWS (WCF **net.tcp** 9389: MC-NMF framing → MS-NNS NegotiateStream sign/seal → binary XML, WS-Enumeration Enumerate/Pull) behind one interface | `smbenum/domain/` |
| Agent | tool registry, guarded executor, JSONL audit, prompt, manual loop | `smbenum/agent/` |

## Install & test

```bash
pip install -e .[dev]     # deps already present on the dev box: impacket, ldap3, anthropic, pyyaml, dnspython
pytest                    # 67 tests, fully offline (mocked transports + scripted fake LLM)
```

## CLI — manual use

Auth flags infer the type: `--ticket` (ccache/kirbi) → Kerberos ticket,
`--aes-key` → AES, `--hashes LM:NT` → NTLM, otherwise password.

```bash
# shares (+ per-share ACLs)
smbenum smb list-shares --host filesrv01.corp.local --user jdoe --domain corp.local --password '...'

# browse + capped read + metadata
smbenum smb ls --host filesrv01 --share IT --path Reports --auth ...
smbenum smb read --host filesrv01 --share IT --path Reports/notes.txt --max-bytes 4096
smbenum smb stat --host filesrv01 --share IT --path Reports/notes.txt

# permissions: parsed DACL (SIDs resolved to names) + optional open-probes
smbenum smb permissions --host filesrv01 --share IT --path Reports --probe

# domain computers via LDAP or ADWS
smbenum domain computers --dc dc01.corp.local --source ldap  --user ... --domain ...
smbenum domain computers --dc dc01.corp.local --source adws  --user ... --domain ...
```

## Agent — LLM-driven, read-only

```bash
export ANTHROPIC_API_KEY=...        # or: ant auth login
smbenum agent --profile policy.example.yaml --host filesrv01.corp.local --dc dc01.corp.local
goal> which files in the IT share can Everyone read? probe and summarize
```

One-shot: add `--goal "..."`. Follow-ups keep the conversation; `/budget`
shows remaining run budgets; `/quit` exits. Every tool call is echoed live
and written to a JSONL audit log under `runs/`.

### Safety model

- **Enforcement by construction** — `smbenum/agent/tools.py` is the entire
  capability surface. There is no write/delete/rename/execute handler
  anywhere; a hallucinated or injected "delete" call hits the registry
  allowlist and is refused + audited. Prompt rules are a second line, not
  the first.
- **Executor guards** (`agent/executor.py`): allowlist → host scope → path
  normalization (`..` rejected) → cap clamping (bytes/entries per call) →
  per-run budgets (tool calls / total bytes / wall clock). On budget
  exhaustion the model is asked to write a final report from collected
  evidence instead of dying silently.
- **Result feeding**: tool results are truncated to a char cap with an
  explicit `[TRUNCATED …]` marker so the model pages via `offset` /
  `max_entries` instead of re-reading.
- **Secrets boundary**: the credential never enters the LLM context or the
  audit log; the system prompt carries only `redacted()` output, and
  handlers inject the real credential server-side.
- **Evidence rule**: the system prompt requires every finding to cite the
  tool call that produced it.
- Model + budgets live in `policy.example.yaml` (`SMBENUM_MODEL` env
  overrides the model).

## Testing

`pytest` — everything external is mocked: impacket SMBConnection, the LDAP
client, the vendored ADWS connection (plus real offline round-trips of the
NBFSE codec and NMF framing), and a scripted fake Anthropic client driving
the full loop (tool_use → executor → tool_result → final report), including
refusals (unknown tool, out-of-scope host, traversal paths, over-cap reads)
and budget-exhaustion behavior.

## Live-validation notes (no lab DC yet)

Built against impacket 0.10.0 on Python 3.12. When a lab exists, smoke:

1. one command per auth type (password / ntlm / aes / ticket incl. kirbi),
2. `smb permissions --probe` on a known directory (compare with icacls),
3. `domain computers` via both `--source ldap` and `--source adws`,
4. an agent run with a small budget.

ADWS notes: the transport (`smbenum/domain/adws/`) is vendored from
[Soaphound.py](https://github.com/j4s0nmo0n/Soaphound.py) (MIT) — a proven
implementation of the net.tcp stack (NMF/NNS/NBFSE, WS-Enumeration) — with
only import-path fixes, so the wire behavior is field-tested upstream even
though THIS repo hasn't touched a live DC yet. Two impacket-version caveats
carried over from upstream: Kerberos sealing uses an embedded compat shim
because impacket < 0.13 lacks `GSS_Wrap_LDAP`, and NNS raises `SystemExit`
on auth failure (we convert that to `AdwsError` at the source boundary).
Also note the enumeration context is connection-scoped — Enumerate + all
Pulls ride one connection, and the context is Released after each query
(max 5 active, 30-min expiry).
