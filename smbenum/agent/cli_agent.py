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
    from .audit import AuditLog
    from .session import AgentSession
    audit = AuditLog.new_run(args.audit_dir)
    hosts = [h.strip() for h in (args.host or "").split(",") if h.strip()] if args.host else []
    session = AgentSession(credential, policy, audit, hosts=hosts,
                           dc=args.dc or "", domain_source=args.source)
    return session, policy, audit


def _make_client():
    try:
        from anthropic import Anthropic
    except ImportError as exc:
        raise SystemExit("anthropic SDK not installed: pip install anthropic") from exc
    return Anthropic()  # ANTHROPIC_API_KEY (or `ant auth login` profile)


def cmd_agent(args) -> None:
    session, policy, audit = _build_session(args)
    red = session.credential.redacted()
    print(f"[agent] credential {red['principal']} ({red['auth_type']}) | "
          f"model {policy.model} | scope {session.allowed_hosts or 'unrestricted'} | "
          f"dc {session.dc or '-'}")
    print(f"[agent] audit log: {audit.path}")
    client = _make_client()

    from .loop import AgentLoop
    loop = AgentLoop(client, session, policy, audit, echo=lambda line: print(line))

    try:
        if args.goal:
            print(loop.run(args.goal))
            return
        print("[agent] ready — describe a goal, or /budget / /quit")
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
                print(session.budget.snapshot())
                continue
            try:
                print(loop.run(goal))
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
    p.add_argument("--goal", default=None, help="run one goal non-interactively and exit")
    p.set_defaults(func=cmd_agent)
