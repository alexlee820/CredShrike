# AISafetySMBEnum — Complete Reference

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Presets & Workflows](#presets--workflows)
   - [full-domain (default)](#full-domain-default)
   - [full](#full)
   - [snaffler](#snaffler)
   - [custom goal](#custom-goal)
3. [Configuration Reference](#configuration-reference)
   - [Policy YAML](#policy-yaml)
   - [CLI Flags](#cli-flags)
   - [Web UI Settings](#web-ui-settings)
4. [Authentication](#authentication)
5. [Context Window Management](#context-window-management)
6. [Findings Extraction Pipeline](#findings-extraction-pipeline)
7. [Report Output](#report-output)

---

## Architecture Overview

```
                    ┌─────────────────────────────────────┐
                    │           Credential                │
                    │  (password | NTLM | AES | ticket)   │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼──────────────────┐
              ▼                    ▼                  ▼
          SMB (445)           LDAP (389/636)     ADWS (9389)
          shares/dirs         computer objects   computer objects
          read (capped)                         (net.tcp NMF/NNS/NBFSE)
          DACLs + probes
              │                    │                  │
              └────────────────────┼──────────────────┘
                                   ▼
                        ┌─────────────────────┐
                        │   Agent Tool Registry  │
                        │   (9 tools, READ-ONLY) │
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │  Executor (safety)   │
                        │  allowlist → scope   │
                        │  → path check → caps │
                        │  → budget → redaction│
                        └──────────┬──────────┘
                                   │
                        ┌──────────▼──────────┐
                        │  LLM Agent Loop      │
                        │  (Anthropic API or   │
                        │   GLM/DeepSeek)      │
                        └──────────┬──────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
               HTML Report    JSONL Audit    Findings JSON
               (tabbed)       (per tool call) (extraction)
```

---

## Presets & Workflows

### full-domain (default)

**What it does:** Sweeps every computer in the domain. Each host gets its own
isolated context window. File reading is deterministic (code-side, not LLM-driven).

**Data workflow:**

```
① Domain computer query (LDAP or ADWS, code-side, zero LLM cost)
      ↓ list of hosts (e.g., DC01, SQL01, WEB01, FILE01)
② Per-host loop (sequential, each with a FRESH AgentLoop):
   ├── SMB 445 reachability check (3s timeout, skip unreachable)
   ├── Global budget gate (skip if tool calls/bytes/wall-clock exceeded)
   ├── CODE-SIDE DUMP (deterministic, zero LLM):
   │     list_shares → walk every folder → read every file (head 16KB)
   │     (all formats, no filtering; special shares like IPC$ skipped)
   │     → ALL content embedded into the goal message
   ├── LLM ANALYSIS (1 large request + follow-ups):
   │     Model receives: instruction + complete dump
   │     Model calls: smb_get_permissions (exposure),
   │                  smb_read_file (deep-read head_truncated files)
   ├── FINDINGS EXTRACTION (2 independent passes + union + regex cross-check)
   └── Per-host report (audit log + full HTML report)
③ Cross-host merge (deterministic, code-side):
      Same (username, secret) pair across hosts → one credential,
      all locations, max severity
④ Combined index.html:
      Coverage matrix + merged credentials + host filter + per-host links
```

**Context math:** Each conversation = ONE host's content (max, not sum).
A monster host cannot take down other hosts.

**Runtime example (FILE01, 16 tool calls):**

```
 1. smb_list_shares(FILE01)                        ← model double-checks
 2. smb_get_permissions(CTF$)                      ← share-level ACL
 3-12. smb_get_permissions × 10                    ← per-file exposure
 13-16. smb_read_file × 4                          ← deep reads (vault,
                                                       web.config, secrets)
```

No `smb_dump_share` calls in the audit — the dump happened code-side before
the LLM loop started. The model only performs judgment actions.

---

### full

**What it does:** Single-host (or explicit multi-host) full-content review.
The model calls `smb_dump_share` itself (paged).

**Data workflow:**

```
① Model calls smb_list_shares(host)
② Model calls smb_dump_share(host, share)          ← EVERY file, any format
      → Returns ~24K chars per page (≈15-30 files)
      → Model pages with skip_files=next_skip until null
      → head_truncated entries flagged for deep-read
③ Model calls smb_read_file + offset               ← for truncated files
④ Model calls smb_get_permissions                  ← for exposure checks
⑤ Findings extraction → per-host report
```

**Difference from full-domain:** The model decides when/what to dump (tool
calls appear in the audit). Full-domain does the dump before the model sees
anything.

---

### snaffler

**What it does:** Tier-based credential sweep (fast, regex-driven, for quick
triage). Only opens files matching red/yellow tier extensions.

**Data workflow:**

```
① Model calls smb_scan_share(host, share)          ← tier/regex sweep
      Red tier: .kdbx .key .pem .ppk .pfx .p12 .rdp .vnc .env
                + filenames containing "password", "secret", "id_rsa"...
      Yellow tier: .config .xml .ps1 .bat .sql .txt .csv .json...
      → Only tier-matching files are opened and regex-scanned
      → Hits returned with SECRET MASKED (password = ***)
      → Hits are PAGED (~50/page, follow next_skip)
      → data_files list: every CSV/TSV/JSON opened (regex can't judge
        structured data — model must READ these itself)
② Model judges each hit: true/false positive
      → smb_read_file around ambiguous hits
      → smb_read_file for every data_files entry
③ smb_get_permissions for confirmed items
④ Findings extraction → report
```

**Built-in regex patterns (patterns.py):**

| Pattern | What it catches |
|---------|----------------|
| password_assignment | `password = xxx` / `pwd: xxx` |
| pwd_assignment | `pwd = xxx` |
| secret_assignment | `secret = xxx` |
| connection_string_password | `Password=xxx;` in conn strings |
| private_key_block | `-----BEGIN PRIVATE KEY-----` |
| aws_access_key | AKIA/ASIA + 16 chars |
| github_token | ghp_ + 36 chars |
| slack_token | xox[baprs]- + 10+ chars |
| azure_storage_key | AccountKey= + 60+ chars |
| net_use_credential | `/user:DOMAIN\user password` |

**Custom patterns:** `--scan-patterns file.yaml` or policy `scan_extra_patterns`.

---

### custom goal

**What it does:** No canned instruction. You write the goal, the model
chooses its own strategy and tools.

**The model has all 9 tools available:**

| Tool | Purpose |
|------|---------|
| domain_list_computers | Query AD for computer objects (LDAP/ADWS) |
| smb_list_shares | List shares on a host |
| smb_list_dir | List a directory inside a share |
| smb_read_file | Read bytes from a file (capped) |
| smb_stat | File/directory metadata |
| smb_get_permissions | DACL + effective-access probes |
| sid_lookup | Resolve SIDs to names |
| smb_scan_share | Snaffler-style tier/regex sweep |
| smb_dump_share | Full-content dump (all formats, paged) |

**Guidance:** The system prompt steers the model: "review everything" tasks
→ dump tool; targeted questions → scan/read. But the model decides.

---

## Configuration Reference

### Policy YAML

Location: pass with `--policy mypolicy.yaml`, or use `policy.example.yaml`
as a starting point.

#### Core limits

| Key | Default | Description |
|-----|---------|-------------|
| `max_file_bytes` | 262144 | Per smb_read_file call (256 KiB) |
| `max_entries` | 500 | Per smb_list_dir call |
| `result_char_cap` | 8192 | Per tool_result fed to the LLM |
| `max_tool_calls` | 100 | Per run (refusals don't consume) |
| `max_total_read_bytes` | 10485760 | Per run (10 MiB total read) |
| `wall_clock_seconds` | 1800 | Per run (30 min) |

#### Read gate

| Key | Default | Description |
|-----|---------|-------------|
| `read_gate` | "none" | `none` = read freely; `ai` = flag if estimated tokens exceed limit; `size` = flag if actual file size exceeds limit |
| `max_read_tokens` | 8192 | ai mode: estimated-token ceiling per read |
| `chars_per_token` | 4.0 | ai mode: bytes→token estimation ratio |
| `flag_oversize_bytes` | 5242880 | size mode: 5 MiB threshold |

#### Redaction

| Key | Default | Description |
|-----|---------|-------------|
| `redact_literals` | [] | Exact strings to mask (e.g., codenames) |
| `redact_patterns` | [] | Regexes; with a capture group, only group is masked |
| `redact_replacement` | "[REDACTED]" | Replacement text |

#### Snaffler scan

| Key | Default | Description |
|-----|---------|-------------|
| `scan_depth` | 3 | Directory levels below the start path |
| `scan_max_files` | 200 | Candidate files opened per sweep |
| `scan_max_file_bytes` | 65536 | Per candidate file |
| `scan_tiers` | ["red","yellow"] | Which tiers to open |
| `scan_use_default_patterns` | true | Use built-in regex set |
| `scan_extra_patterns` | {} | Custom {name: regex}; same name replaces built-in |

#### Full-content dump

| Key | Default | Description |
|-----|---------|-------------|
| `dump_depth` | 6 | Directory levels |
| `dump_per_file_bytes` | 16384 | Head sent per file (16 KiB) |
| `dump_page_chars` | 24000 | Page target (tool char_cap is 40000) |
| `dump_max_files` | 500 | Per share |

#### Context window management

| Key | Default | Description |
|-----|---------|-------------|
| `context_token_limit` | 0 | Your model's window (0 = auto-compaction off). e.g., 128000 for GLM |
| `compact_at_ratio` | 0.75 | Compact old tool results at 75% of limit |
| `compact_keep_recent` | 4 | Newest N messages untouched by compaction |

#### LLM endpoint

| Key | Default | Description |
|-----|---------|-------------|
| `model` | "claude-opus-5" | Model ID (env `SMBENUM_MODEL` overrides) |
| `max_tokens` | 16000 | Per response |
| `api_base_url` | "" | Anthropic-compatible endpoint (GLM, DeepSeek, proxy) |
| `api_key` | "" | API key (empty = `ANTHROPIC_API_KEY` env) |
| `thinking_mode` | "adaptive" | `adaptive` or `off`; auto-set to `off` when `api_base_url` is set |

#### Debug

| Key | Default | Description |
|-----|---------|-------------|
| `debug` | false | Echo FULL tool results in console + report Debug tab |

#### Session scope

| Key | Default | Description |
|-----|---------|-------------|
| `allowed_hosts` | [] | Empty = unrestricted; CLI `--host` also sets this |

---

### CLI Flags

#### Authentication (shared across all subcommands)

| Flag | Description |
|------|-------------|
| `--user` | Username (sAMAccountName) |
| `--domain` | Domain FQDN or NETBIOS |
| `--password` | Plaintext password |
| `--hashes` | NTLM hash, format `LM:NT` (LM may be empty: `:NT`) |
| `--aes-key` | AES256 key (hex) → Kerberos |
| `--ticket` | Kerberos ticket file (.ccache or .kirbi) |
| `--kdc` | KDC hostname override (REQUIRED for AES/ticket in this lab) |
| `--profile` | YAML file with credential + policy (see policy.example.yaml) |

#### Agent mode

| Flag | Description |
|------|-------------|
| `--preset` | `full-domain` (default when bare) / `full` / `snaffler` |
| `--goal` | Custom goal (skips preset, one-shot mode) |
| `--repl` | Force interactive REPL (bare invocation defaults to full-domain) |
| `--host` | Host scope (comma-separated for multi-host) |
| `--dc` | Domain controller for domain queries |
| `--source` | Directory transport: `auto`(=LDAP) / `ldap` / `adws` |
| `--computers-filter` | full-domain: LDAP filter for host selection |
| `--max-hosts` | full-domain: cap the number of computers swept |
| `--read-gate` | `none` / `ai` / `size` |
| `--max-read-tokens` | ai gate threshold |
| `--flag-oversize-mb` | size gate threshold in MB |
| `--redact` | Comma-separated literals to mask |
| `--redact-pattern` | Regex (repeatable); group = masked portion |
| `--scan-patterns` | YAML file of custom regex patterns |
| `--context-limit` | Model's context window in tokens |
| `--api-base-url` | Anthropic-compatible endpoint |
| `--api-key` | API key for the endpoint |
| `--thinking` | `adaptive` / `off` |
| `--debug` | Show full tool results |
| `--model` | Model override |
| `--audit-dir` | Directory for audit logs (default: `runs/`) |

#### REPL commands

| Command | Description |
|---------|-------------|
| `/budget` | Show remaining budgets + context tokens + flagged count |
| `/flagged` | List all files the read gate refused |
| `/quit` | Exit |

---

### Web UI Settings

Start with `smbenum ui` → http://127.0.0.1:8080

| Section | Field | Description |
|---------|-------|-------------|
| Preset | Dropdown | full-domain (default) / full / snaffler / custom |
| Goal | Textarea | Only visible when preset = custom |
| Host(s) | Input | Comma-separated; empty = unrestricted |
| DC | Input | Domain controller hostname |
| Directory source | Dropdown | auto (LDAP) / ldap / adws |
| Auth type | Dropdown | password / ntlm / aes / ticket |
| Username | Input | sAMAccountName |
| Domain | Input | FQDN |
| Model | Input | e.g., glm-5.3 |
| API endpoint | Input | e.g., https://api.z.ai/api/anthropic |
| API key | Password | Leave empty to use env var |
| Read gate | Dropdown + value | none / ai / size |
| Redact literals | Input | Comma-separated |
| Redact regex | Textarea | One per line |
| Context limit | Number | Tokens (0 = off) |
| Computers filter | Input | full-domain: LDAP filter |
| Max hosts | Number | full-domain: cap (0 = all) |
| Debug | Checkbox | Show FULL tool results |

---

## Authentication

| Method | Flags | KDC needed? | How it works |
|--------|-------|-------------|--------------|
| Password | `--password` | No | NTLM login (impacket `conn.login`) |
| NTLM hash | `--hashes :NT` | No | Pass-the-hash via NTLM |
| AES key | `--aes-key <hex>` | **Yes** (`--kdc`) | Kerberos: key → TGT → TGS → AP |
| Ticket (.ccache) | `--ticket file` | **Yes** (`--kdc`) | Pass-the-ticket via KRB5CCNAME |
| Ticket (.kirbi) | `--ticket file` | **Yes** (`--kdc`) | Kirbi→ccache in-memory, then above |

**Note:** This lab's DNS has no SRV records and the domain A record points
to a non-KDC address — always pass `--kdc` for Kerberos-family auth.

---

## Context Window Management

Three layers of protection:

| Layer | Mechanism |
|-------|-----------|
| Tracking | `usage.input_tokens` from each API response → `loop.context_tokens` |
| Proactive compaction | At `compact_at_ratio` (default 75%) of `context_token_limit`: old tool_result contents (>200 chars, beyond newest 4 messages) replaced with `[compacted: was N chars]` placeholders |
| Overflow self-heal | If the API rejects with "prompt is too long": compact (aggressive on 2nd attempt = clear ALL tool results), retry up to twice |

**Goals are never compacted** — they are string user messages, compaction
only touches list-type tool_result blocks.

---

## Findings Extraction Pipeline

```
AI finishes analysis → report text written
  ↓
Extraction pass 1 (LLM call) → JSON A
Extraction pass 2 (LLM call) → JSON B     ← independent samples
  ↓
Union merge (code):
  credentials dedup by (username, secret) → max severity, evidence joined
  others dedup by (category, host, share, path)
  ↓
Regex cross-check (code):
  Scan report text for DOMAIN\user tokens
  → any token missing from union's usernames?
    YES → corrective round (LLM call, names the missing accounts)
    NO  → done
  ↓
Final findings → report tables
```

**Categories:** `credential` | `pii` | `financial` | `network_info` |
`sensitive_file` | `weak_acl` | `other`

**Sensitive item definition (from goal prompt):**
- PII: names, emails, phone numbers, addresses, IDs, salary/HR, health data
- Financial: bank accounts, credit cards, invoices, budgets, payroll
- Internal network: IPs, hostnames, diagrams, VPN/DNS configs, inventory

---

## Report Output

Per-run artifacts:

```
runs/
├── domain_<timestamp>/                    ← full-domain sweep
│   ├── <stamp>_<host>.jsonl              ← per-host audit log
│   ├── <stamp>_<host>.report.html        ← per-host full report
│   └── index.html                        ← combined index
├── <timestamp>.jsonl                      ← single-run audit log
└── <timestamp>.report.html               ← single-run report
```

Per-host report tabs: Overview / Credentials / Findings / Sweep hits /
Computers / Shares / SMB activity / AI report / Transcript / [Debug] / Audit

Index report sections: Coverage matrix / Merged credentials (host filter) /
Other findings (host filter) / Per-host AI reports
