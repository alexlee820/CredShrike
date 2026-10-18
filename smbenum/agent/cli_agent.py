"""`smbenum agent …` — REPL and one-shot entry points."""

from __future__ import annotations

import argparse
import sys

from ..cli import add_auth_args, build_credential
from ..config import Policy


def _build_session(args):
    credential = build_credential(args)
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


def _emit_html_report(loop, session, policy, audit, client, report_md: str) -> str:
    """Generate the standalone HTML report next to the audit log."""
    from pathlib import Path
    from .findings import extract_findings
    findings, extraction_error = [], ""
    try:
        findings = extract_findings(client, policy, loop.messages)
    except Exception as exc:  # noqa: BLE001 - report must still build
        extraction_error = f"{type(exc).__name__}: {exc}"
    from ..report import write_report
    red = session.credential.redacted()
    path = str(Path(audit.path).with_suffix(".report.html"))
    write_report(path,
                 context={"principal": red["principal"], "auth_type": red["auth_type"],
                          "scope": session.allowed_hosts, "model": policy.model,
                          "endpoint": policy.api_base_url or "api.anthropic.com"},
                 findings=findings, scan_results=session.scan_results,
                 flagged=session.flagged_files, report_md=report_md,
                 audit_path=audit.path, redactions=session.redactions_applied,
                 extraction_error=extraction_error,
                 domain_computers=session.domain_computers,
                 share_inventories=session.share_inventories,
                 transcript=loop.transcript)
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


def cmd_agent(args) -> None:
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
    p.add_argument("--scan-patterns", default=None,
                   help="YAML file of {name: regex} patterns added to the built-in "
                        "set for smb_scan_share (same name replaces built-in)")
    p.add_argument("--preset", choices=["snaffler"], default=None,
                   help="use a canned goal: 'snaffler' = deterministic credential "
                        "sweep first, then model-side judgment of every match")
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
    p.set_defaults(func=cmd_agent)
