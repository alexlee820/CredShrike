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

# when no context limit is configured, cap the embedded dump at ~400K chars
# (~100-130K tokens) so the analysis conversation still fits typical windows
_DEFAULT_GOAL_CHAR_BUDGET = 400_000

_HOST_ANALYSIS_PROMPT = (
    "Below is the COMPLETE deterministic content dump of every file on host "
    "{host} — gathered code-side (all formats, no filtering). Your job:\n"
    "1. Extract EVERY credential or sensitive item: usernames, passwords, keys, "
    "tokens — including plain CSV/JSON rows.\n"
    "2. Entries marked head_truncated hide content beyond the per-file head — "
    "fetch the rest with smb_read_file + offset when the head looks interesting.\n"
    "3. Assess exposure with smb_get_permissions (probe=true) for confirmed items.\n"
    "4. Produce the final report citing paths from the dump.{incomplete}\n")


def _render_dump_for_goal(session, host: str, policy: Policy, echo) -> tuple[str, list]:
    """Deterministically dump EVERY share of one host (code-side, no LLM
    decisions) and render it as text to embed in the analysis goal. Returns
    (dump_text, incomplete_notes). Special shares (IPC$/ADMIN$-style) are
    skipped. Global byte budget is respected; when the dump exceeds the char
    budget the remainder is noted for the model to page in itself."""
    from ..scanner import dump_share

    shares = session.smb(host).list_shares()
    session.share_inventories[host] = shares
    dumpable = [s for s in shares if not s.get("special")]
    echo(f"[domain] {host}: dumping {len(dumpable)}/{len(shares)} shares "
         f"({', '.join(s['name'] for s in dumpable)})")

    char_budget = int((policy.context_token_limit or 133000) * 3) \
        if policy.context_token_limit else _DEFAULT_GOAL_CHAR_BUDGET
    bytes_left = policy.max_total_read_bytes - session.budget.bytes_read
    chunks: list[str] = []
    notes: list[str] = []
    for share in dumpable:
        result = dump_share(
            session.smb(host), share["name"], "",
            depth=policy.dump_depth,
            per_file_bytes=policy.dump_per_file_bytes,
            page_chars=char_budget,           # single page: take everything
            max_files=policy.dump_max_files,
            max_total_bytes=max(0, bytes_left),
            on_event=lambda kind, data: echo(f"  ⋮ {kind} {data.get('path', '')}"
                                             if isinstance(data, dict) else ""),
        )
        session.budget.bytes_read += int(result["stats"]["bytes_read"])
        bytes_left -= int(result["stats"]["bytes_read"])
        chunks.append(f"=== SHARE {share['name']} "
                      f"({result['stats']['files_dumped']} files) ===")
        for entry in result["files"]:
            header = f"---- {entry['path']} ({entry['size']}B" \
                     f"{' head_truncated' if entry['head_truncated'] else ''}) ----"
            chunks.append(header + "\n" + entry["content"])
        if result.get("truncated"):
            notes.append(f"share {share['name']} dump was cut short "
                         f"({result.get('stop_reason')}) — continue it with "
                         f"smb_dump_share(share={share['name']!r}, skip_files="
                         f"{result['stats']['files_dumped']})")
        if sum(len(c) for c in chunks) > char_budget:
            notes.append(f"char budget reached while embedding share "
                         f"{share['name']} — the remaining shares/files were NOT "
                         f"included; page them with smb_dump_share yourself")
            break
    special = [s["name"] for s in shares if s.get("special")]
    if special:
        chunks.append(f"(special shares skipped: {', '.join(special)})")
    return "\n".join(chunks), notes


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

        total_bytes = sum(r["bytes_read"] for r in results)
        if total_calls >= policy.max_tool_calls or \
                total_bytes >= policy.max_total_read_bytes or \
                time.time() - started > policy.wall_clock_seconds:
            entry["status"] = "skipped-budget"
            echo(f"[domain] ({index}/{len(hosts)}) {host}: SKIPPED — global budget "
                 f"({total_calls} calls / {total_bytes // 1024}K read) exhausted")
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
            # deterministic phase: EVERY file dumped code-side and embedded
            # in the goal — the model never has to decide to fetch the bulk
            dump_text, incomplete = _render_dump_for_goal(session, host, policy, echo)
            incomplete_note = ("\nNOTE — dump incomplete: " + "; ".join(incomplete)
                               if incomplete else "")
            goal = _HOST_ANALYSIS_PROMPT.format(host=host,
                                                incomplete=incomplete_note) + dump_text
            entry["tool_calls"] = session.budget.tool_calls
            entry["bytes_read"] = session.budget.bytes_read
            entry["shares"] = session.share_inventories.get(host, [])

            loop = AgentLoop(client_factory(), session, policy, audit, echo=echo)
            report_md = loop.run(goal)
            entry["report_md"] = report_md
            try:
                entry["findings"] = extract_findings(client_factory(), policy, loop.messages)
            except Exception as exc:  # noqa: BLE001 - merge what we have
                entry["findings_error"] = f"{type(exc).__name__}: {exc}"

            entry["shares"] = session.share_inventories.get(host, [])
            entry["tool_calls"] = session.budget.tool_calls
            entry["bytes_read"] = session.budget.bytes_read  # includes the embedded dump

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
                 f"{entry['tool_calls']} calls, report "
                 f"{os.path.join(run_dir, entry['html'])}")
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
