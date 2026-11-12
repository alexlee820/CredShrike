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
    if getattr(args, "prompt_cache", None) is not None:
        policy.prompt_cache = bool(args.prompt_cache)
    if getattr(args, "context_limit", None):
        policy.context_token_limit = int(args.context_limit)
    if getattr(args, "analysis_mode", None):
        policy.analysis_mode = args.analysis_mode
    if getattr(args, "max_concurrent_llm", None):
        policy.max_concurrent_llm = int(args.max_concurrent_llm)
    if getattr(args, "max_shares_in_flight", None):
        policy.max_shares_in_flight = int(args.max_shares_in_flight)
    if getattr(args, "analysis_triage", None) is not None:
        policy.analysis_triage = bool(args.analysis_triage)
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
    if getattr(args, "socks_proxy", None):
        policy.socks_proxy = args.socks_proxy
    if getattr(args, "no_cache", False):
        policy.inventory_cache = False
    if getattr(args, "cache_ttl_hours", None) is not None:
        policy.cache_ttl_hours = float(args.cache_ttl_hours)
    if getattr(args, "no_content_cache", False):
        policy.cache_content = False
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


REGEX_SWEEP_PRESET = (
    "Run a credential sweep on the shares of the in-scope host(s): call "
    "smb_scan_share first (deterministic, Snaffler-structured). Hits are PAGED — while a "
    "result has next_skip set, call smb_scan_share again with skip_matches="
    "next_skip until it is null, so you see EVERY hit. Three kinds of evidence: "
    "(1) ARTIFACTS — the result's artifacts list holds files that ARE secrets "
    "(password stores like .kdbx/.ppk, NTDS.DIT/SAM/lsass dumps, .keytab, "
    ".ssh/.aws paths, passwords.*) reported without reading: every one is a "
    "finding on its own — include it with its tier (black = grab-worthy, "
    "red = high, yellow = interesting, green = name-only wide-net) and what it "
    "is; (2) content hits — JUDGE each one true/false positive (read around the "
    "hit with smb_read_file when the snippet is ambiguous); (3) data_files — "
    "read EVERY entry with smb_read_file: regex cannot see credential rows in "
    "CSV/TSV/JSON, extract username/password pairs yourself. "
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
                 artifacts=[a for s in session.scan_results
                            for a in s.get("artifacts", [])],
                 known_fps=[f for s in session.scan_results
                            for f in s.get("known_fps", [])],
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


def _resolve_latest_resume(audit_dir: str) -> str:
    """--resume latest: the newest resumable run dir (scan_run_dirs is
    newest-first)."""
    from ..runstate import scan_run_dirs
    runs = [r for r in scan_run_dirs(audit_dir) if r["resumable"]]
    if not runs:
        raise SystemExit(
            f"error: no resumable runs under {audit_dir}/ — `credshrike runs list` "
            "shows what exists (a run stays resumable until every host is done)")
    return runs[0]["run_dir"]


# canonical preset names are scope words; the old "full" names remain
# accepted as deprecated aliases (same treatment snaffler got)
PRESET_ALIASES = {"full": "host", "full-domain": "domain",
                  "snaffler": "regex-sweep"}
DOMAIN_PRESET = "domain"
HOST_PRESET = "host"


def normalize_preset(name):
    """Map any accepted spelling to its canonical preset name."""
    if not name:
        return name
    return PRESET_ALIASES.get(name, name)


def _resolve_preset(args) -> Optional[str]:
    """Effective preset: explicit wins; bare invocation (no preset, no goal,
    not REPL) defaults to the domain-wide fan-out sweep."""
    if args.preset:
        return normalize_preset(args.preset)
    if getattr(args, "goal", None) or getattr(args, "repl", False):
        return None
    return DOMAIN_PRESET


def cmd_agent(args) -> None:
    # build credential + policy once for ALL presets
    credential = build_credential(args)
    policy = _load_policy(args)
    concurrency = args.concurrency if args.concurrency is not None else policy.read_threads
    preset = _resolve_preset(args)

    # SMB/LDAP/ADWS/Kerberos through the proxy, LLM API calls stay direct
    if policy.socks_proxy:
        from ..socks_proxy import apply_socks_proxy
        apply_socks_proxy(policy.socks_proxy)

    # shared inventory cache, armed for the whole agent run (every preset
    # enumerates through SMBSession, so all of them benefit)
    from ..inventory_cache import InventoryCache
    from ..smb_session import arm_inventory_cache, disarm_inventory_cache
    _inv_cache = InventoryCache.open(args.audit_dir or "runs", policy)
    if getattr(args, "refresh", False) and _inv_cache is not None:
        _inv_cache.wipe()
    if _inv_cache is not None:
        arm_inventory_cache(_inv_cache)
    try:
        _cmd_agent_dispatch(args, credential, policy, concurrency, preset)
    finally:
        if _inv_cache is not None:
            disarm_inventory_cache()
            _inv_cache.close()


def _cmd_agent_dispatch(args, credential, policy, concurrency, preset) -> None:

    # config banner for EVERY preset (domain, host, regex-sweep, custom)
    from .orchestrator import _print_config_banner
    _print_config_banner(credential, policy, args.dc or "", args.source,
                        concurrency, lambda l: print(l))

    # domain: per-computer fan-out with orchestrator
    if getattr(args, "resume", None) and preset != DOMAIN_PRESET:
        raise SystemExit("error: --resume applies to domain-sweep runs only")

    if preset == DOMAIN_PRESET:
        import os
        if getattr(args, "resume", None):
            if args.resume == "latest":
                args.resume = _resolve_latest_resume(args.audit_dir or "runs")
            if not os.path.isfile(os.path.join(args.resume, "run.json")):
                raise SystemExit(
                    f"error: {args.resume} is not a resumable run (no run.json). "
                    "Try `credshrike runs list` or --resume latest")
        from .orchestrator import run_domain_sweep
        run_domain_sweep(credential=credential, policy=policy,
                         audit_dir=args.audit_dir, dc=args.dc or "",
                         domain_source=args.source,
                         computers_filter=args.computers_filter or "",
                         max_hosts=args.max_hosts or None,
                         concurrency=concurrency,
                         resume_dir=args.resume)
        return

    # full (single host): code-side parallel dump + config banner, same as
    # full-domain but for just the specified host(s)
    if preset == HOST_PRESET:
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

                    if policy.analysis_mode == "stream":
                        # stream mode walks + reads + analyzes on its own
                        from .stream_analysis import analyze_share_streaming
                        print(f"[share] {host}/{share_name}: streaming analysis...")
                        result = analyze_share_streaming(
                            credential=credential, policy=policy, audit=audit,
                            session=session, host=host, share_name=share_name,
                            client_factory=lambda: _make_client(policy),
                            echo=lambda l: print(l),
                            memory_block=f"({si}/{len(dumpable)}) ",
                            memory=memory)
                        memory = result["memory"]
                        all_reports.append(f"### {share_name}\n{result['report']}")
                        all_findings.extend(result["findings"])
                        session.budget.bytes_read += result["stats"].get("bytes_read", 0)
                        print(f"[share] {host}/{share_name}: "
                              f"{len(result['findings'])} finding(s)")
                        continue

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

    # everything else: regular agent loop (custom goal, regex-sweep)
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
        if not goal and args.preset in ("snaffler", "regex-sweep"):
            goal = REGEX_SWEEP_PRESET
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


# deprecated alias (renamed 2026-10-27: the preset is a canned goal driving
# the regex-triage tool; it is not Snaffler itself)
SNAFFLER_PRESET = REGEX_SWEEP_PRESET


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
    p.add_argument("--preset",
                   choices=["domain", "host", "regex-sweep", "custom",
                            "full-domain", "full", "snaffler"],
                   default=None,
                   help="scope of the sweep: 'domain' = every computer in the "
                        "domain (own context window per host, merged cross-host "
                        "credentials + index report); 'host' = full-content "
                        "review of the explicit --host(s) only; 'regex-sweep' = "
                        "regex triage then AI judgment (fast/cheap). Old names "
                        "'full-domain'/'full'/'snaffler' still work as aliases")
    p.add_argument("--computers-filter", default="",
                   help="domain: extra LDAP filter for host selection, e.g. "
                        "'(operatingSystem=*Server*)'")
    p.add_argument("--max-hosts", type=int, default=None,
                   help="domain: cap the number of computers swept")
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
    p.add_argument("--prompt-cache", dest="prompt_cache", action="store_true",
                   default=None,
                   help="Anthropic prompt caching (cache_control); on by default, "
                        "auto-disabled if the endpoint rejects it")
    p.add_argument("--no-prompt-cache", dest="prompt_cache", action="store_false",
                   help="disable prompt caching")
    p.add_argument("--debug", action="store_true",
                   help="debug mode: echo the FULL tool results (exactly what the "
                        "model received — verify transports like adws via the "
                        "'source' field, inspect dump/scan pages); also recorded "
                        "in the report's Debug tab")
    p.add_argument("--analysis-mode", choices=["batch", "stream"], default=None,
                   help="stream = walkers feed ONE LLM thread per share "
                        "(micro-batches of K files, shared session, code-side "
                        "ledger guarantees coverage); batch = dump-then-analyze "
                        "(default). CLI/policy; web UI has a dropdown")
    p.add_argument("--resume", default=None, metavar="RUN_DIR",
                   help="resume an interrupted full-domain run from its "
                        "directory (contains run.json) — done hosts/shares "
                        "are skipped, stream-mode file verdicts carry over")
    p.add_argument("--no-cache", action="store_true",
                   help="disable the shared inventory cache (runs/.cache/inventory.db)")
    p.add_argument("--refresh", action="store_true",
                   help="wipe the inventory cache before this run")
    p.add_argument("--cache-ttl-hours", type=float, default=None, metavar="H",
                   help="inventory cache freshness window (default 24)")
    p.add_argument("--no-content-cache", action="store_true",
                   help="cache listings but never file contents")
    p.add_argument("--max-concurrent-llm", type=int, default=None,
                   help="global in-flight LLM requests across shares "
                        "(stream mode; default 2)")
    p.add_argument("--max-shares-in-flight", type=int, default=None,
                   help="shares pipelined concurrently in stream mode (default 2)")
    p.add_argument("--analysis-triage", dest="analysis_triage", action="store_true",
                   default=None,
                   help="stream mode: decide which files the LLM reads using the "
                        "Snaffler 4-layer triage (junk discarded; artifacts like "
                        ".kdbx/NTDS.DIT/.ssh reported WITHOUT reading; relay "
                        "files streamed to the LLM)")
    p.add_argument("--no-analysis-triage", dest="analysis_triage", action="store_false",
                   help="read every non-skip-ext file (default)")
    p.add_argument("--context-limit", type=int, default=None,
                   help="your model's context window in tokens (e.g. 128000 for "
                        "GLM). When the conversation passes 75%% of it, old tool "
                        "results are compacted to placeholders; overflows also "
                        "self-heal by compacting and retrying")
    p.set_defaults(func=cmd_agent)
