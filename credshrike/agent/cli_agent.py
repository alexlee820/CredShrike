"""`credshrike agent …` — REPL and one-shot entry points."""

from __future__ import annotations

import argparse
import sys

from ..cli import add_auth_args, build_credential
from ..config import Policy


def _load_policy(args) -> Policy:
    policy = Policy.load(args.policy)
    if args.model:
        policy.model = args.model
    if args.read_gate:
        policy.read_gate = args.read_gate
    if args.max_read_tokens:
        policy.max_read_tokens = args.max_read_tokens
    if args.flag_oversize_mb:
        policy.flag_oversize_bytes = int(args.flag_oversize_mb * 1024 * 1024)
    if args.redact:
        policy.redact_literals = [w.strip() for w in args.redact.split(",") if w.strip()]
    if args.redact_pattern:
        policy.redact_patterns = list(args.redact_pattern)
    if getattr(args, "scan_patterns", None):
        import yaml as _yaml
        with open(args.scan_patterns, "r", encoding="utf-8") as fh:
            policy.scan_extra_patterns = _yaml.safe_load(fh) or {}
    if getattr(args, "api_base_url", None):
        policy.api_base_url = args.api_base_url
    if getattr(args, "api_key", None):
        policy.api_key = args.api_key
    if getattr(args, "thinking", None):
        policy.thinking_mode = args.thinking
    elif getattr(args, "api_base_url", None):
        # custom endpoint: adaptive thinking is Anthropic-specific — default off
        policy.thinking_mode = "off"
    if getattr(args, "debug", False):
        policy.debug = True
        import logging
        logging.getLogger("CredShrike").setLevel(logging.DEBUG)
    if getattr(args, "stream", False):
        policy.stream = True
    if getattr(args, "no_stream", False):
        policy.stream = False
    if getattr(args, "context_limit", None):
        policy.context_token_limit = int(args.context_limit)
    if getattr(args, "concurrency", None) is not None:
        policy.read_threads = int(args.concurrency)
    if getattr(args, "mask_pii", False):
        policy.mask_pii = True
    if getattr(args, "mask_secrets", False):
        policy.mask_secrets = True
    if getattr(args, "mask_semantic", False):
        policy.mask_semantic = True
    if getattr(args, "mask_semantic_model", None):
        policy.mask_semantic_model = args.mask_semantic_model
        policy.mask_semantic = True
    if getattr(args, "no_mask_restore", False):
        policy.mask_restore = False
    if getattr(args, "no_surrogates", False):
        policy.mask_same_length = []
    if getattr(args, "surrogate_style", None):
        policy.mask_surrogate_style = args.surrogate_style
    if getattr(args, "mask_email_domain", None):
        policy.mask_email_domain = args.mask_email_domain
    if getattr(args, "mask_netbios_domain", None):
        policy.mask_netbios_domain = args.mask_netbios_domain
    if getattr(args, "skip_exts", None) is not None:
        raw = args.skip_exts.strip().lower()
        if raw == "none" or raw == "":
            policy.dump_skip_exts = []
        else:
            policy.dump_skip_exts = [e.strip().lower() if e.strip().startswith(".")
                                      else "." + e.strip().lower()
                                      for e in raw.split(",") if e.strip()]
    return policy


def _build_session(args):
    credential = build_credential(args)
    policy = _load_policy(args)
    from .audit import AuditLog
    from .session import AgentSession
    audit = AuditLog.new_run(args.audit_dir)
    hosts = [h.strip() for h in (args.host or "").split(",") if h.strip()] if args.host else []
    session = AgentSession(credential, policy, audit, hosts=hosts,
                           dc=args.dc or "", domain_source=args.source)
    return session, policy, audit


SNAFFLER_PRESET = (
    "Run a credential sweep on the shares of the in-scope host(s): call "
    "smb_scan_share first (deterministic regex sweep). Hits are PAGED — while a "
    "result has next_skip set, call smb_scan_share again with skip_matches="
    "next_skip until it is null, so you see EVERY hit. Then JUDGE each one — "
    "classify true/false positive (read around the hit with smb_read_file when "
    "the snippet is ambiguous). ALSO read every entry in the result's data_files "
    "list (CSV/TSV/JSON) with smb_read_file — regex cannot see credential rows "
    "in structured data, you must extract username/password pairs yourself. "
    "Check real exposure with smb_get_permissions (probe=true) for files you "
    "confirm, and produce the final report. Use the sweep's coverage stats as "
    "your scope evidence."
)

FULL_PRESET = (
    "Run a FULL-CONTENT review of every share on the in-scope host(s): call "
    "smb_dump_share on each share — it sends EVERY file regardless of format, "
    "as decoded text. Pages are chained: while next_skip is set, call again "
    "with skip_files=next_skip until it is null, so you READ EVERY FILE. "
    "head_truncated entries hide content beyond the per-file head — page into "
    "them with smb_read_file + offset when the visible head looks interesting. "
    "Extract every credential or sensitive item you see (usernames, passwords, "
    "keys, tokens — including plain CSV/JSON rows), assess exposure with "
    "smb_get_permissions where relevant, and produce the final report. If the "
    "dump stops on byte-budget truncation, record exactly where it stopped "
    "under Limitations. Use the dump stats as your scope evidence."
)


def _emit_html_report(loop, session, policy, audit, client, report_md: str) -> str:
    """Generate the standalone HTML report next to the audit log."""
    from pathlib import Path
    from .findings import extract_findings
    from ..masking import restore_findings
    findings, extraction_error = [], ""
    try:
        findings = extract_findings(client, policy, loop.messages)
        # findings were parsed from a MASKED conversation — put values back
        # (unless the operator asked for placeholders to stay everywhere)
        restore_findings(findings, session.masker,
                         restore_values=policy.mask_restore)
    except Exception as exc:  # noqa: BLE001 - report must still build
        extraction_error = f"{type(exc).__name__}: {exc}"
    from ..report import write_report
    red = session.credential.redacted()
    path = str(Path(audit.path).with_suffix(".report.html"))
    write_report(path,
                 context={"principal": red["principal"], "auth_type": red["auth_type"],
                          "scope": session.allowed_hosts, "model": policy.model,
                          "endpoint": policy.api_base_url or "api.anthropic.com"},
                 masking=({"entities": session.masker.summary(),
                           "restored": policy.mask_restore}
                          if session.masker is not None else None),
                 findings=findings, scan_results=session.scan_results,
                 flagged=session.flagged_files, report_md=report_md,
                 audit_path=audit.path, redactions=session.redactions_applied,
                 extraction_error=extraction_error,
                 domain_computers=session.domain_computers,
                 share_inventories=session.share_inventories,
                 transcript=loop.transcript,
                 debug_results=session.debug_results if policy.debug else [])
    print(f"[agent] HTML report: {path}")
    return path


def _make_client(policy=None):
    try:
        from anthropic import Anthropic
    except ImportError as exc:
        raise SystemExit("anthropic SDK not installed: pip install anthropic") from exc
    kwargs = {}
    if policy is not None:
        if policy.api_base_url:
            kwargs["base_url"] = policy.api_base_url
        if policy.api_key:
            kwargs["api_key"] = policy.api_key
    return Anthropic(**kwargs)  # falls back to ANTHROPIC_API_KEY / auth profile


def _resolve_preset(args) -> Optional[str]:
    """Effective preset: explicit wins; bare invocation (no preset, no goal,
    not REPL) defaults to full-domain — the per-computer fan-out sweep."""
    if args.preset:
        return args.preset
    if getattr(args, "goal", None) or getattr(args, "repl", False):
        return None
    return "full-domain"


def cmd_agent(args) -> None:
    # build credential + policy once for ALL presets
    credential = build_credential(args)
    policy = _load_policy(args)
    concurrency = args.concurrency if args.concurrency is not None else policy.read_threads
    preset = _resolve_preset(args)

    # config banner for EVERY preset (full-domain, full, snaffler, custom)
    from .orchestrator import _print_config_banner
    _print_config_banner(credential, policy, args.dc or "", args.source,
                        concurrency, lambda l: print(l))

    # full-domain: per-computer fan-out with orchestrator
    if preset == "full-domain":
        from .orchestrator import run_domain_sweep
        run_domain_sweep(credential=credential, policy=policy,
                         audit_dir=args.audit_dir, dc=args.dc or "",
                         domain_source=args.source,
                         computers_filter=args.computers_filter or "",
                         max_hosts=args.max_hosts or None,
                         concurrency=concurrency)
        return

    # full (single host): code-side parallel dump + config banner, same as
    # full-domain but for just the specified host(s)
    if preset == "full":
        from .orchestrator import _dump_single_share, _analyze_share_batches
        from .session import AgentSession
        from ..report import write_report
        from pathlib import Path

        # config banner already printed at the top of cmd_agent
        hosts = [h.strip() for h in (args.host or "").split(",") if h.strip()]
        if not hosts:
            print("[error] --preset full requires --host <hostname>")
            return

        audit_dir = args.audit_dir
        for host in hosts:
            print(f"\n[agent] ── {host} ──")
            audit = AuditLog.new_run(audit_dir, suffix=host)
            session = AgentSession(credential, policy, audit, hosts=[host],
                                   dc=args.dc or "", domain_source=args.source)
            try:
                # get shares, dump each in parallel
                shares = session.smb(host).list_shares()
                session.share_inventories[host] = shares
                dumpable = [s for s in shares if not s.get("special")]
                print(f"[agent] {host}: {len(dumpable)} share(s) to analyze")

                all_findings, all_reports, all_skipped = [], [], []
                mask_entities: dict[str, int] = {}
                memory = ""    # rolling summary across shares
                for si, share_info in enumerate(dumpable, 1):
                    share_name = share_info["name"]
                    file_entries, stats, skipped = _dump_single_share(
                        session, host, share_name, policy,
                        lambda l: print(l), read_threads=concurrency)
                    all_skipped.extend(skipped)
                    session.budget.bytes_read += stats.get("bytes_read", 0)

                    # LLM analysis: one share = one context window, auto-split
                    # into multiple requests when the dump exceeds it
                    print(f"[share] {host}/{share_name}: analyzing...")
                    result = _analyze_share_batches(
                        credential, policy, audit, host, share_name,
                        file_entries, lambda: _make_client(policy),
                        lambda l: print(l), dc=args.dc or "",
                        domain_source=args.source, memory=memory)
                    memory = result["memory"]
                    all_reports.append(f"### {share_name}\n{result['report']}")
                    all_findings.extend(result["findings"])
                    for entity, count in result.get("masked_entities", {}).items():
                        mask_entities[entity] = mask_entities.get(entity, 0) + count
                    print(f"[share] {host}/{share_name}: "
                          f"{len(result['findings'])} finding(s)")

                # generate report
                report_md = "\n\n".join(all_reports)
                html_path = str(Path(audit.path).with_suffix(".report.html"))
                write_report(html_path,
                             context={"principal": credential.redacted()["principal"],
                                      "auth_type": credential.redacted()["auth_type"],
                                      "scope": [host], "model": policy.model,
                                      "endpoint": policy.api_base_url or "api.anthropic.com"},
                             masking=({"entities": mask_entities,
                                       "restored": policy.mask_restore}
                                      if (policy.mask_pii or policy.mask_secrets
                                          or policy.mask_semantic) else None),
                             findings=all_findings,
                             scan_results=[], flagged=[],
                             report_md=report_md,
                             audit_path=audit.path,
                             share_inventories=session.share_inventories,
                             skipped_files=all_skipped)
                print(f"\n[agent] {host}: done — report {html_path}")
                print("\n" + report_md[:2000] + ("\n... (full report in HTML)" if len(report_md) > 2000 else ""))
            finally:
                session.close()
        return

    # everything else: regular agent loop (custom goal, snaffler)
    session, policy, audit = _build_session(args)
    red = session.credential.redacted()
    print(f"[agent] credential {red['principal']} ({red['auth_type']}) | "
          f"model {policy.model} | scope {session.allowed_hosts or 'unrestricted'} | "
          f"dc {session.dc or '-'} | read-gate {policy.read_gate}")
    print(f"[agent] audit log: {audit.path}")
    client = _make_client(policy)

    from .loop import AgentLoop
    loop = AgentLoop(client, session, policy, audit, echo=lambda line: print(line))

    try:
        goal = args.goal
        if not goal and args.preset == "snaffler":
            goal = SNAFFLER_PRESET
        if goal:
            report = loop.run(goal)
            print(report)
            _emit_html_report(loop, session, policy, audit, client, report)
            return
        print("[agent] ready — describe a goal, or /budget /flagged /quit")
        while True:
            try:
                goal = input("goal> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not goal:
                continue
            if goal in ("/quit", "/exit", "q"):
                break
            if goal == "/budget":
                snap = session.budget.snapshot()
                snap["flagged_files"] = len(session.flagged_files)
                snap["context_tokens"] = loop.context_tokens
                snap["context_limit"] = policy.context_token_limit or "off"
                print(snap)
                continue
            if goal == "/flagged":
                import json as _json
                for entry in session.flagged_files:
                    print(_json.dumps(entry, ensure_ascii=False))
                continue
            try:
                report = loop.run(goal)
                print(report)
                _emit_html_report(loop, session, policy, audit, client, report)
            except KeyboardInterrupt:
                print("\n[interrupted — conversation kept, budgets still apply]")
            except Exception as exc:  # noqa: BLE001 - REPL boundary
                print(f"[error] {type(exc).__name__}: {exc}", file=sys.stderr)
    finally:
        session.close()


def register(subparsers) -> None:
    p = subparsers.add_parser("agent", help="capability-limited LLM enumeration agent")
    add_auth_args(p)
    p.add_argument("--host", help="host scope (comma-separated). Recommended: pin the target(s)")
    p.add_argument("--dc", help="domain controller for domain_list_computers")
    p.add_argument("--source", choices=["auto", "ldap", "adws"], default="auto",
                   help="directory transport (default auto=ldap)")
    p.add_argument("--policy", default=None, help="policy YAML (caps/model overrides)")
    p.add_argument("--model", default=None, help="model override (env SMBENUM_MODEL also works)")
    p.add_argument("--audit-dir", default="runs", help="directory for JSONL audit logs")
    p.add_argument("--read-gate", choices=["none", "ai", "size"], default=None,
                   help="smb_read_file gate: 'ai' flags requests whose estimated "
                        "tokens exceed --max-read-tokens; 'size' flags files larger "
                        "than --flag-oversize-mb; 'none' (default) reads freely")
    p.add_argument("--max-read-tokens", type=int, default=None,
                   help="ai gate: estimated-token ceiling per read (default 8192)")
    p.add_argument("--flag-oversize-mb", type=float, default=None,
                   help="size gate: files larger than this many MB are flagged, "
                        "not read (default 5)")
    p.add_argument("--redact", default=None,
                   help="comma-separated literal strings to mask in tool results "
                        "BEFORE they reach the LLM (e.g. --redact 'ProjectX,10.0.0.5')")
    p.add_argument("--redact-pattern", action="append", default=None,
                   help="regex redaction rule (repeatable). With a capture group "
                        "only the group is masked: --redact-pattern 'password\\\\s*=\\\\s*(\\\\S+)'")
    p.add_argument("--mask-pii", action="store_true",
                   help="PasteGuard-style masking of PII (emails, IPs, phone "
                        "numbers, credit cards, IBANs, EU VAT) before content "
                        "reaches the LLM provider")
    p.add_argument("--mask-secrets", action="store_true",
                   help="mask secrets (API keys, JWTs, bearer tokens, private "
                        "keys, passwords, connection strings) before content "
                        "reaches the LLM provider; values are restored in the "
                        "model's output so the report still carries evidence")
    p.add_argument("--mask-semantic", action="store_true",
                   help="also mask names/addresses with the GLiNER semantic "
                        "backend (PERSON/LOCATION; needs `pip install gliner`, "
                        "downloads urchade/gliner_multi_pii-v1 on first use)")
    p.add_argument("--mask-semantic-model", default=None, metavar="MODEL",
                   help="GLiNER checkpoint or local path (implies --mask-semantic)")
    p.add_argument("--no-mask-restore", action="store_true",
                   help="leave [[TYPE_N]] placeholders in the output instead of "
                        "restoring the original values (maximum privacy)")
    p.add_argument("--no-surrogates", action="store_true",
                   help="do NOT use same-length pseudonyms for names/passwords; "
                        "use [[TYPE_N]] placeholders for them too")
    p.add_argument("--surrogate-style", choices=["name", "syllable", "masked"],
                   default=None,
                   help="name = real-name dictionaries (default), syllable = "
                        "pronounceable filler, masked = Xxxx/0000")
    p.add_argument("--mask-email-domain", default=None, metavar="DOMAIN",
                   help="domain used for masked email/UPN addresses "
                        "(default corp.local)")
    p.add_argument("--mask-netbios-domain", default=None, metavar="DOMAIN",
                   help="domain used for masked DOMAIN\\user accounts "
                        "(default corp; FQDN forms use the email domain)")
    p.add_argument("--scan-patterns", default=None,
                   help="YAML file of {name: regex} patterns added to the built-in "
                        "set for smb_scan_share (same name replaces built-in)")
    p.add_argument("--preset", choices=["snaffler", "full", "full-domain"], default=None,
                   help="canned goal: 'snaffler' = tier/regex sweep then judgment; "
                        "'full' = smb_dump_share EVERY file (any format) then "
                        "extraction — full-content review; 'full-domain' = "
                        "per-computer fan-out (own context window per host, "
                        "merged cross-host credentials + index report)")
    p.add_argument("--computers-filter", default="",
                   help="full-domain: extra LDAP filter for host selection, e.g. "
                        "'(operatingSystem=*Server*)'")
    p.add_argument("--max-hosts", type=int, default=None,
                   help="full-domain: cap the number of computers swept")
    p.add_argument("--concurrency", type=int, default=None,
                   help="parallel file-read threads per share (default: "
                        "policy.read_threads = 10; try 3-4 on slow SMB, "
                        "mind server load)")
    p.add_argument("--skip-exts", default=None,
                   help="comma-separated extensions to SKIP during dump "
                        "(still listed in the report as 'seen but not read'). "
                        "Default: .rar,.7z,.zip,.exe,.msi,.dll — pass "
                        "'none' to read everything. Example: "
                        "--skip-exts '.rar,.iso,vhdx,.vmdk'")
    p.add_argument("--api-base-url", default=None,
                   help="Anthropic-compatible endpoint override, e.g. "
                        "https://api.deepseek.com/anthropic or the GLM /api/anthropic URL "
                        "(empty = official Anthropic API)")
    p.add_argument("--api-key", default=None,
                   help="API key for the endpoint (default: ANTHROPIC_API_KEY env)")
    p.add_argument("--thinking", choices=["adaptive", "off"], default=None,
                   help="adaptive thinking on/off. Defaults to adaptive on the official "
                        "API and OFF when --api-base-url is set (3rd-party endpoints may "
                        "reject the thinking parameter)")
    p.add_argument("--goal", default=None, help="run one goal non-interactively and exit")
    p.add_argument("--repl", action="store_true",
                   help="start the interactive REPL even with no --goal/--preset "
                        "(bare `credshrike agent` otherwise defaults to a "
                        "full-domain sweep)")
    p.add_argument("--stream", action="store_true", default=None,
                   help="stream tokens live (SSE). On by default; use this to "
                        "re-enable after a policy file disabled it")
    p.add_argument("--no-stream", action="store_true",
                   help="plain request/response (no SSE) — use if your "
                        "Anthropic-compatible endpoint rejects streaming")
    p.add_argument("--debug", action="store_true",
                   help="debug mode: echo the FULL tool results (exactly what the "
                        "model received — verify transports like adws via the "
                        "'source' field, inspect dump/scan pages); also recorded "
                        "in the report's Debug tab")
    p.add_argument("--context-limit", type=int, default=None,
                   help="your model's context window in tokens (e.g. 128000 for "
                        "GLM). When the conversation passes 75%% of it, old tool "
                        "results are compacted to placeholders; overflows also "
                        "self-heal by compacting and retrying")
    p.set_defaults(func=cmd_agent)
