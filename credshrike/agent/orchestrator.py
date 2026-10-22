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
import threading
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
    "1. Extract EVERY credential: usernames, passwords, keys, tokens — "
    "including plain CSV/JSON rows.\n"
    "2. Extract EVERY sensitive item, meaning:\n"
    "   - PII: names, emails, phone numbers, addresses, ID/passport numbers, "
    "dates of birth, salary/HR records, health data\n"
    "   - Money-related: bank accounts, credit card numbers, invoices, "
    "budgets, financial reports, payroll, payment/billing configs\n"
    "   - Internal network: IP addresses, hostnames, architecture diagrams, "
    "VPN/firewall/proxy configs, DNS zone files, internal URLs/APIs, "
    "network credentials in configs, VLAN/subnet layouts, server inventory\n"
    "3. Entries marked head_truncated hide content beyond the per-file head — "
    "fetch the rest with smb_read_file + offset when the head looks interesting.\n"
    "4. Assess exposure with smb_get_permissions (probe=true) for confirmed items.\n"
    "5. Produce the final report citing paths from the dump.{incomplete}\n")


_SHARE_ANALYSIS_PROMPT = (
    "You are analyzing ONE SMB share on host {host}. Below is the COMPLETE "
    "content of every file in share '{share}' ({n_files} files, {size_kb}K). "
    "{memory_block}"
    "Your job:\n"
    "1. Read through the file contents and extract EVERY credential "
    "(usernames, passwords, keys, tokens — including CSV/JSON plain rows).\n"
    "2. Extract EVERY sensitive item: PII (names/emails/IDs/HR/health), "
    "financial (bank cards/invoices/budgets/payroll), internal network "
    "(IPs/hostnames/diagrams/VPN/DNS/inventory).\n"
    "3. If entries are marked head_truncated and look interesting, note it.\n"
    "4. Produce a brief summary of what you found (max 200 words).\n"
    "5. List each finding as a structured entry.\n"
    "{incomplete}\n")


_SUMMARY_PROMPT = (
    "Summarize what you found in this share for the NEXT share's analysis. "
    "Keep it under 150 words. Include: usernames/passwords found (exact values), "
    "file paths with notable content, patterns you noticed (e.g. 'secrets "
    "folder contains .cred files'), and anything the next share should look "
    "for based on what you've seen. Respond with ONLY the summary text, "
    "no markdown formatting.")


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
    dump_stats = {"dirs_walked": 0, "files_seen": 0, "files_dumped": 0,
                  "bytes_read": 0, "errors": 0}
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
        for key in dump_stats:
            dump_stats[key] += int(result["stats"].get(key, 0))
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
    return "\n".join(chunks), notes, dump_stats


def _dump_single_share(session, host: str, share_name: str,
                        policy: Policy, echo) -> tuple[str, dict]:
    """Dump ONE share's contents as text (for per-share context windows).
    Returns (share_dump_text, stats)."""
    from ..scanner import dump_share

    char_budget = int((policy.context_token_limit or 133000) * 3) \
        if policy.context_token_limit else _DEFAULT_GOAL_CHAR_BUDGET
    # per-share budget: a fraction of the total (host has multiple shares)
    share_budget = char_budget // 2
    bytes_left = policy.max_total_read_bytes - session.budget.bytes_read

    result = dump_share(
        session.smb(host), share_name, "",
        depth=policy.dump_depth,
        per_file_bytes=policy.dump_per_file_bytes,
        page_chars=share_budget,
        max_files=policy.dump_max_files,
        max_total_bytes=max(0, bytes_left),
        on_event=lambda kind, data: echo(f"  ⋮ {kind} {data.get('path', '')}"
                                         if isinstance(data, dict) else ""),
    )
    session.budget.bytes_read += int(result["stats"]["bytes_read"])

    chunks = [f"=== SHARE {share_name} "
              f"({result['stats']['files_dumped']} files) ==="]
    for entry in result["files"]:
        header = f"---- {entry['path']} ({entry['size']}B" \
                 f"{' head_truncated' if entry['head_truncated'] else ''}) ----"
        chunks.append(header + "\n" + entry["content"])

    notes = ""
    if result.get("truncated"):
        notes = (f"\nNOTE: this share's dump was truncated "
                 f"({result.get('stop_reason')}). Use smb_dump_share with "
                 f"skip_files={result['stats']['files_dumped']} to see more.\n")
    return "\n".join(chunks) + notes, result["stats"]


def _generate_share_summary(client, policy, share_name: str,
                            report_md: str, echo) -> str:
    """Ask the LLM to produce a brief summary of what was found in this
    share — this becomes the 'memory' injected into the next share's
    context. Falls back to a truncated version of the report if the
    summary call fails."""
    try:
        resp = client.messages.create(
            model=policy.model,
            max_tokens=500,
            messages=[
                {"role": "user",
                 "content": f"Share: {share_name}\n\nYour findings:\n{report_md[:4000]}\n\n{_SUMMARY_PROMPT}"}
            ],
        )
        text = "".join(getattr(b, "text", "") for b in resp.content).strip()
        if text:
            echo(f"[share] {share_name}: summary generated ({len(text)} chars)")
            return text
    except Exception as exc:  # noqa: BLE001 - summary is best-effort
        echo(f"[share] {share_name}: summary failed ({type(exc).__name__}), "
             f"using truncated report")
    return report_md[:500] + "..." if len(report_md) > 500 else report_md


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


def _sweep_one_host(entry: dict, host: str, run_dir: str, credential: Credential,
                    policy: Policy, dc: str, domain_source: str, computers: list,
                    client_factory, echo, api_semaphore: Optional[threading.Semaphore] = None) -> None:
    """Sweep ONE host using PER-SHARE context windows: each share gets its
    own fresh AgentLoop (small enough for 8K-32K models). After each share
    is analyzed, the LLM generates a rolling summary that's injected into
    the NEXT share's context (cross-share memory). No regex — the LLM reads
    the actual file content and decides what's a credential."""
    from .audit import AuditLog
    from .findings import extract_findings
    from .loop import AgentLoop
    from .session import AgentSession
    from ..report import write_report

    audit = AuditLog.new_run(run_dir, suffix=host)
    entry["audit_path"] = os.path.basename(audit.path)
    session = AgentSession(credential, policy, audit, hosts=[host],
                           dc=dc, domain_source=domain_source)
    try:
        # Get share list (code-side, fast)
        shares = session.smb(host).list_shares()
        session.share_inventories[host] = shares
        entry["shares"] = shares
        dumpable = [s for s in shares if not s.get("special")]
        echo(f"[domain] {host}: {len(dumpable)} share(s) to analyze "
             f"({', '.join(s['name'] for s in dumpable)})")

        all_findings: list[dict] = []
        all_reports: list[str] = []
        memory = ""    # rolling summary from previous shares
        total_dump_stats = {"dirs_walked": 0, "files_seen": 0, "files_dumped": 0,
                            "bytes_read": 0, "errors": 0}

        for si, share_info in enumerate(dumpable, 1):
            share_name = share_info["name"]

            # Phase 1: dump THIS share only (code-side, parallel-safe)
            echo(f"[share] ({si}/{len(dumpable)}) {host}/{share_name}: dumping...")
            share_dump, share_stats = _dump_single_share(
                session, host, share_name, policy, echo)
            for key in total_dump_stats:
                total_dump_stats[key] += share_stats.get(key, 0)
            entry["bytes_read"] = session.budget.bytes_read
            entry["dump_stats"] = dict(total_dump_stats)  # keep updated even on error

            # Phase 2: fresh context window for THIS share
            memory_block = (f"\nMEMORY from previous shares on {host}:\n{memory}\n\n"
                            if memory else "")
            goal = _SHARE_ANALYSIS_PROMPT.format(
                host=host, share=share_name,
                n_files=share_stats.get("files_dumped", 0),
                size_kb=share_stats.get("bytes_read", 0) // 1024,
                memory_block=memory_block,
                incomplete="")

            if api_semaphore is not None:
                echo(f"[share] {host}/{share_name}: dump done "
                     f"({share_stats['files_dumped']} files) — waiting for API slot...")
                api_semaphore.acquire()
                try:
                    echo(f"[share] {host}/{share_name}: analyzing...")
                    share_session = AgentSession(credential, policy, audit,
                                                 hosts=[host], dc=dc,
                                                 domain_source=domain_source)
                    share_loop = AgentLoop(client_factory(), share_session,
                                           policy, audit, echo=echo)
                    share_report = share_loop.run(goal + "\n\n" + share_dump)
                finally:
                    api_semaphore.release()
            else:
                share_session = AgentSession(credential, policy, audit,
                                             hosts=[host], dc=dc,
                                             domain_source=domain_source)
                share_loop = AgentLoop(client_factory(), share_session,
                                       policy, audit, echo=echo)
                share_report = share_loop.run(goal + "\n\n" + share_dump)

            all_reports.append(f"### {share_name}\n{share_report}")

            # Extract findings from THIS share's conversation
            try:
                share_findings = extract_findings(
                    client_factory(), policy, share_loop.messages)
                for f in share_findings:
                    f["share"] = share_name
                all_findings.extend(share_findings)
                echo(f"[share] {host}/{share_name}: {len(share_findings)} finding(s)")
            except Exception as exc:  # noqa: BLE001
                echo(f"[share] {host}/{share_name}: extraction failed — {exc}")

            # Phase 3: generate rolling summary for the next share
            memory = _generate_share_summary(
                client_factory(), policy, share_name, share_report, echo)

            entry["tool_calls"] = session.budget.tool_calls

        # Combine all share findings + reports into host-level output
        entry["dump_stats"] = total_dump_stats
        entry["findings"] = all_findings
        entry["report_md"] = "\n\n".join(all_reports)

        red = session.credential.redacted()
        html_path = audit.path[:-len(".jsonl")] + ".report.html"
        write_report(html_path,
                     context={"principal": red["principal"],
                              "auth_type": red["auth_type"], "scope": [host],
                              "model": policy.model,
                              "endpoint": policy.api_base_url or "api.anthropic.com"},
                     findings=all_findings, scan_results=session.scan_results,
                     flagged=session.flagged_files,
                     report_md=entry["report_md"],
                     audit_path=audit.path,
                     domain_computers=[c.to_dict() for c in computers],
                     share_inventories=session.share_inventories,
                     transcript=[],
                     debug_results=session.debug_results if policy.debug else [],
                     dump_stats=total_dump_stats)
        entry["html"] = os.path.basename(html_path)
        entry["status"] = "done"
        echo(f"[domain] {host}: done — {len(all_findings)} finding(s) across "
             f"{len(dumpable)} share(s), report {entry['html']}")
        echo(f"[domain] {host}: done — {len(entry['findings'])} finding(s), "
             f"{entry['tool_calls']} calls, report "
             f"{os.path.join(run_dir, entry['html'])}")
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def _sweep_host_with_retry(entry, host, run_dir, credential, policy, dc,
                           domain_source, computers, client_factory, echo,
                           api_semaphore=None):
    """Sweep one host with transient-error retry (shared by sequential and
    parallel paths). Fills entry fields on success; records errors."""
    echo(f"[domain] {host}: START sweep")
    transient_markers = ("no answer", "connection reset", "broken pipe",
                         "unpack requires", "timed out", "timeout")
    for attempt in (1, 2):
        if attempt == 2:
            echo(f"[domain] {host}: transient error — retrying once")
            time.sleep(3)
            entry.update(status="pending", error="", findings=[], report_md="",
                         html="", tool_calls=0, bytes_read=0, shares=[])
        try:
            _sweep_one_host(entry, host, run_dir, credential, policy, dc,
                            domain_source, computers, client_factory, echo,
                            api_semaphore=api_semaphore)
            return
        except Exception as exc:  # noqa: BLE001
            message = str(exc).lower()
            if attempt == 1 and any(m in message for m in transient_markers):
                entry["error"] = f"{type(exc).__name__}: {exc}"
                continue
            entry["status"] = "error"
            entry["error"] = f"{type(exc).__name__}: {exc}"
            echo(f"[domain] {host}: ERROR — {entry['error'][:200]}")
            return


def run_domain_sweep(*, credential: Credential, policy: Policy,
                     audit_dir: str = "runs", dc: str = "", domain_source: str = "auto",
                     computers_filter: str = "", max_hosts: Optional[int] = None,
                     client_factory: Optional[Callable] = None, echo=print,
                     source_override=None, reachable_check: Optional[Callable] = None,
                     concurrency: int = 1) -> dict:
    """Sweep a domain. concurrency=1 (default) is sequential; concurrency>1
    uses a ThreadPoolExecutor — each host still gets its own context window,
    its own audit log, its own LLM client; only the host-level orchestration
    runs in parallel."""
    # resolve at CALL time so monkeypatching module attributes works (a
    # default-arg binding would freeze the original function and make tests
    # environment-dependent)
    if reachable_check is None:
        reachable_check = _port_open
    from .audit import AuditLog
    from .cli_agent import _make_client

    if client_factory is None:
        client_factory = lambda: _make_client(policy)  # noqa: E731

    computers = _resolve_computers(credential, dc, domain_source,
                                   computers_filter, source_override)
    hosts = [c.dns_name or c.cn for c in computers]
    # explicit transport announcement in the log
    transport = "adws (net.tcp 9389)" if domain_source == "adws" else \
               f"ldap (389) [{domain_source}]" if domain_source == "ldap" else \
               f"auto → ldap (389) [requested: {domain_source}]"
    echo(f"[domain] TRANSPORT: {transport} — querying domain computers")
    if max_hosts:
        hosts = hosts[:max_hosts]
    echo(f"[domain] {len(computers)} computer(s) in scope — sweeping {len(hosts)}"
         + (f" (concurrency={concurrency})" if concurrency > 1 else ""))
    if concurrency > 1:
        echo(f"[domain] PARALLEL: hosts will interleave in the log below — "
             f"SMB dumps run concurrently; LLM analysis queues on an API semaphore")

    # API semaphore: limits concurrent LLM calls. GLM plans typically allow
    # 1; the semaphore prevents 429 storms that make parallel look sequential
    api_concurrency = 1  # safe default for GLM; increase for Anthropic
    if policy.api_base_url and "anthropic.com" not in policy.api_base_url:
        api_concurrency = 1  # third-party endpoints: assume strict limits
    else:
        api_concurrency = min(concurrency, 3)  # official API: allow some parallel
    api_semaphore = threading.Semaphore(api_concurrency) if concurrency > 1 else None
    if api_semaphore:
        echo(f"[domain] API semaphore: {api_concurrency} concurrent LLM call(s) max "
             f"(prevents rate-limit storms; SMB dumps still fully parallel)")

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = os.path.join(audit_dir, f"domain_{stamp}")
    os.makedirs(run_dir, exist_ok=True)

    started = time.time()
    results: list[dict] = []

    def _work(index_host):
        index, host = index_host
        entry = {"host": host, "status": "pending", "error": "", "shares": [],
                 "findings": [], "report_md": "", "audit_path": "", "html": "",
                 "tool_calls": 0, "bytes_read": 0}
        # pre-checks (budget gate + reachability)
        total_bytes = sum(r["bytes_read"] for r in results if r.get("bytes_read"))
        total_calls = sum(r["tool_calls"] for r in results if r.get("tool_calls"))
        if total_calls >= policy.max_tool_calls or \
                total_bytes >= policy.max_total_read_bytes or \
                time.time() - started > policy.wall_clock_seconds:
            entry["status"] = "skipped-budget"
            echo(f"[domain] {host}: SKIPPED — global budget exhausted")
            return entry
        if not reachable_check(host):
            entry["status"] = "unreachable"
            echo(f"[domain] {host}: SMB 445 unreachable — skipped")
            return entry
        echo(f"[domain] ({index}/{len(hosts)}) {host}: sweeping")
        _sweep_host_with_retry(entry, host, run_dir, credential, policy, dc,
                               domain_source, computers, client_factory, echo,
                               api_semaphore=api_semaphore)
        return entry

    if concurrency <= 1:
        for pair in enumerate(hosts, 1):
            results.append(_work(pair))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(_work, pair): pair[1] for pair in enumerate(hosts, 1)}
            future_to_host = {f: h for f, h in futures.items()}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001 - host-level crash
                    host = future_to_host[future]
                    results.append({"host": host, "status": "error",
                                    "error": f"{type(exc).__name__}: {exc}",
                                    "shares": [], "findings": [], "report_md": "",
                                    "audit_path": "", "html": "",
                                    "tool_calls": 0, "bytes_read": 0})
                    echo(f"[domain] {host}: CRASH — {type(exc).__name__}: {exc}")
        # restore host order (as_completed returns in completion order)
        order = {h: i for i, h in enumerate(hosts)}
        results.sort(key=lambda r: order.get(r["host"], len(hosts)))

    merged = merge_findings([f for r in results for f in r["findings"]])
    context = {"principal": credential.redacted()["principal"],
               "auth_type": credential.redacted()["auth_type"],
               "scope": [r["host"] for r in results],
               "model": policy.model,
               "endpoint": policy.api_base_url or "api.anthropic.com"}
    index_path = os.path.join(run_dir, "index.html")
    from ..report import write_domain_index
    write_domain_index(index_path, context=context, hosts=results,
                       merged=merged, computers=[c.to_dict() for c in computers])

    done = sum(1 for r in results if r["status"] == "done")
    n_creds = len(merged["credentials"])
    elapsed = int(time.time() - started)
    echo(f"[domain] sweep complete: {done}/{len(results)} hosts swept, "
         f"{n_creds} unique credential(s), {elapsed}s — index: {index_path}")
    return {"hosts": results, "merged": merged, "index_html": index_path,
            "run_dir": run_dir, "computers": [c.to_dict() for c in computers]}
