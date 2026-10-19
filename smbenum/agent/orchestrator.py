"""Per-computer fan-out orchestrator: the `full-domain` preset.

Instead of one giant conversation holding every host's results (context
pressure ∝ Σ all hosts, re-sent every turn), this sweeps the domain
computer-by-computer:

    ① domain_list_computers (code-side, deterministic) → host list
    ② reachability precheck (SMB 445) — unreachable hosts are recorded, not fatal
    ③ per host: a FRESH AgentLoop with its own context window
       (goal = FULL_PRESET pinned to that host), its own audit log and its
       own full HTML report — one monster host cannot take down the rest
    ④ global budget gate between hosts (shared tool-call/wall-clock ceiling)
    ⑤ deterministic merge: identical (username, secret) pairs across hosts
       collapse into one credential with multiple locations
    ⑥ combined index.html: coverage matrix + merged credentials + links

Context math: worst case per conversation = ONE host's share contents
(handled by the compaction machinery), never Σ(hosts).
"""

from __future__ import annotations

import os
import re
import socket
import time
from typing import Callable, Optional

from ..config import Policy
from ..credentials import Credential

_SEV_ORDER = {"high": 3, "medium": 2, "low": 1}


def _port_open(host: str, port: int = 445, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def _resolve_computers(credential: Credential, dc: str, domain_source: str,
                       computers_filter: str, source_override=None) -> list:
    """Domain computer list, code-side (deterministic — no LLM involved)."""
    if source_override is not None:
        return source_override()
    if domain_source == "adws":
        from ..domain.adws_source import AdwsSource
        source = AdwsSource(credential, dc)
    else:
        from ..domain.ldap_source import LdapSource
        source = LdapSource(credential, dc)
    return source.list_computers(computers_filter or "")


def merge_findings(all_findings: list[dict]) -> dict:
    """Deterministic cross-host merge: identical (username, secret) pairs
    collapse into one credential entry carrying every location. Severity
    takes the max; everything else is kept per-location."""
    credentials: dict[tuple, dict] = {}
    other: list[dict] = []
    for finding in all_findings:
        location = {"host": finding.get("host", ""), "share": finding.get("share", ""),
                    "path": finding.get("path", "")}
        entry = dict(finding)
        entry["locations"] = [location]
        key = (finding.get("username") or "", finding.get("secret") or "")
        if finding.get("category") == "credential" and any(key):
            if key in credentials:
                merged = credentials[key]
                merged["locations"].append(location)
                if _SEV_ORDER.get(entry["severity"], 0) > _SEV_ORDER.get(merged["severity"], 0):
                    merged["severity"] = entry["severity"]
                merged["evidence"] = f"{merged['evidence']}; {entry['evidence']}"[:400]
            else:
                credentials[key] = entry
        else:
            other.append(entry)
    return {"credentials": list(credentials.values()), "other": other}


def run_domain_sweep(*, credential: Credential, policy: Policy,
                     audit_dir: str = "runs", dc: str = "", domain_source: str = "auto",
                     computers_filter: str = "", max_hosts: Optional[int] = None,
                     client_factory: Optional[Callable] = None, echo=print,
                     source_override=None, reachable_check: Callable = _port_open) -> dict:
    from .audit import AuditLog
    from .cli_agent import FULL_PRESET, _make_client
    from .findings import extract_findings
    from .loop import AgentLoop
    from .session import AgentSession
    from ..report import write_domain_index, write_report

    if client_factory is None:
        client_factory = lambda: _make_client(policy)  # noqa: E731

    computers = _resolve_computers(credential, dc, domain_source,
                                   computers_filter, source_override)
    hosts = [c.dns_name or c.cn for c in computers]
    if max_hosts:
        hosts = hosts[:max_hosts]
    echo(f"[domain] {len(computers)} computer(s) in scope — sweeping {len(hosts)}")

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = os.path.join(audit_dir, f"domain_{stamp}")
    os.makedirs(run_dir, exist_ok=True)

    started = time.time()
    results: list[dict] = []
    total_calls = 0
    for index, host in enumerate(hosts, 1):
        entry = {"host": host, "status": "pending", "error": "", "shares": [],
                 "findings": [], "report_md": "", "audit_path": "", "html": "",
                 "tool_calls": 0, "bytes_read": 0}
        results.append(entry)

        if total_calls >= policy.max_tool_calls or \
                time.time() - started > policy.wall_clock_seconds:
            entry["status"] = "skipped-budget"
            echo(f"[domain] ({index}/{len(hosts)}) {host}: SKIPPED — global budget "
                 f"({total_calls}/{policy.max_tool_calls} calls) exhausted")
            continue
        if not reachable_check(host):
            entry["status"] = "unreachable"
            echo(f"[domain] ({index}/{len(hosts)}) {host}: SMB 445 unreachable — skipped")
            continue

        echo(f"[domain] ({index}/{len(hosts)}) {host}: sweeping")
        session = None
        try:
            audit = AuditLog.new_run(run_dir, suffix=host)
            entry["audit_path"] = os.path.basename(audit.path)
            session = AgentSession(credential, policy, audit, hosts=[host],
                                   dc=dc, domain_source=domain_source)
            loop = AgentLoop(client_factory(), session, policy, audit, echo=echo)
            report_md = loop.run(FULL_PRESET)
            entry["report_md"] = report_md
            try:
                entry["findings"] = extract_findings(client_factory(), policy, loop.messages)
            except Exception as exc:  # noqa: BLE001 - merge what we have
                entry["findings_error"] = f"{type(exc).__name__}: {exc}"

            entry["shares"] = session.share_inventories.get(host, [])
            entry["tool_calls"] = session.budget.tool_calls
            entry["bytes_read"] = session.budget.bytes_read

            red = session.credential.redacted()
            html_path = audit.path[:-len(".jsonl")] + ".report.html"
            write_report(html_path,
                         context={"principal": red["principal"],
                                  "auth_type": red["auth_type"], "scope": [host],
                                  "model": policy.model,
                                  "endpoint": policy.api_base_url or "api.anthropic.com"},
                         findings=entry["findings"], scan_results=session.scan_results,
                         flagged=session.flagged_files, report_md=report_md,
                         audit_path=audit.path,
                         domain_computers=[c.to_dict() for c in computers],
                         share_inventories=session.share_inventories,
                         transcript=loop.transcript,
                         debug_results=session.debug_results if policy.debug else [])
            entry["html"] = os.path.basename(html_path)
            entry["status"] = "done"
            echo(f"[domain] {host}: done — {len(entry['findings'])} finding(s), "
                 f"{entry['tool_calls']} calls, report {entry['html']}")
        except Exception as exc:  # noqa: BLE001 - one host must not kill the sweep
            entry["status"] = "error"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            echo(f"[domain] {host}: ERROR — {entry['error'][:200]}")
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001
                    pass
        total_calls = sum(r["tool_calls"] for r in results)

    merged = merge_findings([f for r in results for f in r["findings"]])
    context = {"principal": credential.redacted()["principal"],
               "auth_type": credential.redacted()["auth_type"],
               "scope": [r["host"] for r in results],
               "model": policy.model,
               "endpoint": policy.api_base_url or "api.anthropic.com"}
    index_path = os.path.join(run_dir, "index.html")
    write_domain_index(index_path, context=context, hosts=results,
                       merged=merged, computers=[c.to_dict() for c in computers])

    done = sum(1 for r in results if r["status"] == "done")
    n_creds = len(merged["credentials"])
    echo(f"[domain] sweep complete: {done}/{len(results)} hosts swept, "
         f"{n_creds} unique credential(s) — index: {index_path}")
    return {"hosts": results, "merged": merged, "index_html": index_path,
            "run_dir": run_dir, "computers": [c.to_dict() for c in computers]}
