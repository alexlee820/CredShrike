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
    "MANDATORY FORMAT — follow exactly:\n\n"
    "PART 1: FILE CHECKLIST (one line per file, in order):\n"
    "FILE: <path> | VERDICT: FOUND | <category> | <one-line detail>\n"
    "FILE: <path> | VERDICT: CLEAN\n"
    "FILE: <path> | VERDICT: SKIPPED | <reason>\n"
    "You MUST account for EVERY file. Do not skip any file without stating why.\n\n"
    "PART 2: DETAILED FINDINGS (only for files marked FOUND):\n"
    "For each FOUND file, list the exact credentials/sensitive items with\n"
    "verbatim values (usernames, passwords, keys, tokens, PII, financial,\n"
    "network info — including plain CSV/JSON rows).\n\n"
    "PART 3: SUMMARY (max 150 words)\n"
    "What you found, patterns noticed, and anything the next share should look for.\n"
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


DEFAULT_SKIP_EXTENSIONS = {
    ".rar", ".7z", ".zip", ".exe", ".msi", ".dll",
    ".iso", ".vhd", ".vhdx", ".vmdk", ".img", ".wim",
    ".mp3", ".mp4", ".avi", ".mkv", ".wav",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
    ".doc", ".xls", ".ppt",              # legacy OLE2 (binary, no zip)
    ".pst", ".ost",
    ".ttf", ".otf", ".woff", ".fon",
    ".cab", ".msu", ".appx",
    ".jar", ".war",
    ".db", ".sqlite", ".mdf", ".ndf",
    ".psd", ".ai",
}

# Office formats we CAN extract text from (OOXML = ZIP containing XML)
_OFFICE_EXTRACTABLE = {".docx", ".xlsx", ".pptx"}


def _extract_office_text(raw_bytes: bytes, ext: str) -> str:
    """Extract readable text from Office files (.docx/.xlsx/.pptx) by
    unzipping the OOXML container and pulling text from the XML inside."""
    import io
    import re
    import zipfile

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes))
    except Exception:  # noqa: BLE001 — not a valid zip
        return ""

    parts: list[str] = []
    if ext == ".docx":
        for name in ("word/document.xml", "word/footnotes.xml"):
            if name in zf.namelist():
                xml = zf.read(name).decode("utf-8", errors="replace")
                parts.extend(re.findall(r"<w:t[^>]*>([^<]+)</w:t>", xml))
    elif ext == ".xlsx":
        for name in zf.namelist():
            if name == "xl/sharedStrings.xml" or name.startswith("xl/comments"):
                xml = zf.read(name).decode("utf-8", errors="replace")
                parts.extend(re.findall(r"<t[^>]*>([^<]+)</t>", xml))
    elif ext == ".pptx":
        for name in sorted(zf.namelist()):
            if (name.startswith("ppt/slides/slide") or
                    name.startswith("ppt/notesSlides/")) and name.endswith(".xml"):
                xml = zf.read(name).decode("utf-8", errors="replace")
                parts.extend(re.findall(r"<a:t>([^<]+)</a:t>", xml))
    return "\n".join(parts)


def _walk_share_files(smb_session, share_name: str, depth: int,
                       max_files: int, echo,
                       skip_exts: Optional[set] = None,
                       conn_pool=None, walk_threads: int = 1,
                       on_file: Optional[Callable] = None) -> tuple[list[dict], int, list[dict]]:
    """Phase 1: walk directory tree using PARALLEL BFS. All directories at the
    same level are listed concurrently. Each listing borrows its own
    connection from the pool (SMB is not thread-safe).

    ``on_file``: streaming hook — called with each discovered (filtered) file
    dict as soon as it is seen (must be thread-safe, e.g. queue.put). Used by
    analysis_mode=stream so the LLM worker starts while the walk runs."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    skip = skip_exts if skip_exts is not None else DEFAULT_SKIP_EXTENSIONS
    files: list[dict] = []
    skipped: list[dict] = []
    seen_dirs: set[str] = set()
    dirs_walked = 0

    def _list_one_dir(dir_path: str):
        """List one directory. Returns (path, listing_or_None, error_or_None)."""
        conn = conn_pool.get(timeout=30) if conn_pool else smb_session
        try:
            listing = conn.list_dir(share_name, dir_path, max_entries=1000)
            return dir_path, listing, None
        except Exception as exc:  # noqa: BLE001
            return dir_path, None, str(exc)[:80]
        finally:
            if conn_pool:
                conn_pool.put(conn)

    # BFS level by level: all dirs at the same level listed in parallel
    current_level: list[tuple[str, int]] = [("", 0)]
    while current_level and len(files) < max_files:
        next_level: list[tuple[str, int]] = []
        use_pool = walk_threads > 1 and len(current_level) > 1 and conn_pool

        if use_pool:
            with ThreadPoolExecutor(max_workers=min(walk_threads, len(current_level))) as pool:
                futures = {pool.submit(_list_one_dir, d): (d, lvl) for d, lvl in current_level}
                results = {futures[f]: f.result() for f in as_completed(futures)}
        else:
            results = {(d, l): _list_one_dir(d) for d, l in current_level}

        for (dir_path, level), (res_path, listing, err) in results.items():
            if res_path in seen_dirs:
                continue
            seen_dirs.add(res_path)
            dirs_walked += 1
            if err:
                echo(f"  ! walk_error: {res_path or '/'} — {err}")
                continue
            echo(f"  ⋮ walk {res_path or '/'}")
            for entry in listing.get("entries", []):
                if len(files) >= max_files:
                    break
                name = entry.get("name", "")
                if name in (".", ".."):
                    continue
                child = f"{res_path}/{name}" if res_path else name
                if entry.get("is_dir") and level < depth:
                    next_level.append((child, level + 1))
                elif not entry.get("is_dir"):
                    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                    if ext in skip:
                        skipped.append({"path": child, "size": entry.get("size", 0), "ext": ext})
                    else:
                        entry_dict = {"path": child, "size": entry.get("size", 0)}
                        files.append(entry_dict)
                        if on_file is not None:
                            on_file(entry_dict)
        current_level = next_level

    echo(f"  ⋮ walk done: {dirs_walked} dirs, {len(files)} to read, "
         f"{len(skipped)} skipped (ext)")
    return files, dirs_walked, skipped


def _close_pool(pool, original_session):
    """Close pool connections (but not the original session's connection)."""
    from queue import Empty as QueueEmpty
    while True:
        try:
            reader = pool.get_nowait()
        except QueueEmpty:
            break
        if reader is not original_session:
            try:
                reader.close()
            except Exception:  # noqa: BLE001
                pass


def _dump_single_share(session, host: str, share_name: str,
                        policy: Policy, echo,
                        read_threads: int = 10) -> tuple[list[dict], dict, list[str]]:
    """Dump ONE share: Phase 1 walks directory tree (parallel BFS), Phase 2
    reads all files concurrently (ThreadPool). Both phases share a connection
    pool (one SMB connection per thread — SMB is not thread-safe).

    Returns (file_entries, stats, skipped_files) where each entry carries its
    own content — the CALLER decides how to render/split them across context
    windows (see _analyze_share_batches)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import base64 as _b64
    from queue import Queue
    from ..smb_session import create_smb_session

    # Create connection pool FIRST — shared by walk + read phases
    n_threads = max(1, read_threads)
    smb_pool: Queue = Queue()
    for i in range(n_threads):
        try:
            reader = create_smb_session(session.credential, host, timeout=30)
            reader.connect()
            smb_pool.put(reader)
        except Exception:  # noqa: BLE001 — pool creation failed (mock/no network)
            pass
    if smb_pool.qsize() == 0:
        smb_pool.put(session.smb(host))  # fall back to original session (mocks)
        echo(f"  ⋮ using shared connection (pool unavailable)")
    else:
        echo(f"  ⋮ {smb_pool.qsize()} SMB connection(s) in pool")

    # Phase 1: walk directory tree (parallel BFS — dirs at same level listed concurrently)
    echo(f"[share] {host}/{share_name}: walking directory tree...")
    file_list, dirs_walked, skipped_files = _walk_share_files(
        session.smb(host), share_name,
        policy.dump_depth, policy.dump_max_files, echo,
        skip_exts=set(policy.dump_skip_exts),
        conn_pool=smb_pool, walk_threads=n_threads)
    if not file_list:
        stats = {"dirs_walked": dirs_walked, "files_seen": 0, "files_dumped": 0,
                 "bytes_read": 0, "errors": 0, "files_skipped_ext": len(skipped_files)}
        _close_pool(smb_pool, session)
        return [], stats, skipped_files

    bytes_left = policy.max_total_read_bytes - session.budget.bytes_read
    per_file = policy.dump_per_file_bytes

    # Phase 2: read all files in parallel (uses the shared pool from above)
    echo(f"[share] {host}/{share_name}: reading {len(file_list)} files "
         f"({n_threads} threads)...")
    results: dict[str, dict] = {}
    total_bytes = 0
    errors = 0

    def _read_one(file_info):
        path = file_info["path"]
        thread_name = threading.current_thread().name
        short_thread = thread_name.rsplit("_", 1)[-1] if "_" in thread_name else thread_name
        ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
        reader = smb_pool.get()   # borrow a connection
        try:
            echo(f"  ⟐ [T{short_thread}] {path}")
            read = reader.read_file(share_name, path, max_bytes=per_file)
            data = _b64.b64decode(read.get("content_b64", ""))
            echo(f"  ✓ [T{short_thread}] {path} ({len(data)}B)")

            if ext in _OFFICE_EXTRACTABLE and data:
                text = _extract_office_text(data, ext)
                if text:
                    echo(f"  ✓ [T{short_thread}] extracted {len(text)} chars from {path}")
                return path, {"content": text if text else f"(empty {ext})",
                             "size": file_info["size"],
                             "head_truncated": len(data) >= per_file}
            return path, {"content": data.decode("utf-8", errors="replace"),
                         "size": file_info["size"],
                         "head_truncated": len(data) >= per_file}
        except Exception as exc:  # noqa: BLE001
            echo(f"  ! [T{short_thread}] {path} FAILED — {str(exc)[:60]}")
            return path, None
        finally:
            smb_pool.put(reader)   # return the connection

    with ThreadPoolExecutor(max_workers=read_threads) as pool:
        # each file is submitted exactly once → no duplicates possible
        # ThreadPoolExecutor's internal queue guarantees all tasks complete
        futures = {pool.submit(_read_one, f): f["path"] for f in file_list}
        for future in as_completed(futures):
            path, result = future.result()
            if result is not None:
                results[path] = result
                total_bytes += len(result["content"].encode("utf-8", errors="replace"))
            else:
                errors += 1

    _close_pool(smb_pool, session)
    echo(f"  ⋮ pool closed. {n_threads} thread(s) read "
         f"{len(results)}/{len(file_list)} files, {total_bytes // 1024}K, {errors} error(s)")

    session.budget.bytes_read += total_bytes

    # Phase 3: build file entries (in original walk order, not completion
    # order). Rendering/splitting across context windows is the CALLER's job.
    file_entries = []
    for f in file_list:
        path = f["path"]
        if path in results:
            r = results[path]
            file_entries.append({"path": path, "content": r["content"],
                                 "size": r["size"],
                                 "head_truncated": r["head_truncated"]})

    stats = {"dirs_walked": dirs_walked, "files_seen": len(file_list),
             "files_dumped": len(results), "bytes_read": total_bytes, "errors": errors,
             "files_skipped_ext": len(skipped_files)}
    echo(f"[share] {host}/{share_name}: dump done — {len(results)} files, "
         f"{total_bytes // 1024}K read, {errors} error(s)")

    return file_entries, stats, skipped_files


def _max_dump_chars(policy: Policy) -> int:
    """Char budget for ONE context window's worth of dump: ~60% of the
    model's window (instruction ~1000 tokens + response ~16000 tokens take
    the rest), ~3 chars per token. Falls back to 400K when no limit is set."""
    if policy.context_token_limit:
        return int(policy.context_token_limit * 3 * 0.6)
    return _DEFAULT_GOAL_CHAR_BUDGET


def _render_entry_text(entry: dict) -> str:
    header = (f"---- {entry['path']} ({entry['size']}B"
              f"{' head_truncated' if entry.get('head_truncated') else ''}) ----")
    return header + "\n" + entry["content"]


def _render_dump_text(file_entries: list[dict], share_name: str,
                      notes: str = "") -> str:
    chunks = [f"=== SHARE {share_name} ({len(file_entries)} files) ==="]
    chunks.extend(_render_entry_text(e) for e in file_entries)
    return "\n".join(chunks) + notes


def _split_file_entries(file_entries: list[dict],
                        max_chars: int) -> list[list[dict]]:
    """Group file entries into context-safe batches. Files are never split
    mid-content; a single file larger than a whole batch budget gets its own
    batch with its content hard-truncated to fit (marked so the model knows
    to page the rest with smb_read_file)."""
    batches: list[list[dict]] = []
    current: list[dict] = []
    used = 0
    for entry in file_entries:
        entry_len = len(_render_entry_text(entry))
        if current and used + entry_len > max_chars:
            batches.append(current)
            current, used = [], 0
        if entry_len > max_chars and not current:
            # single file exceeds a whole batch — hard-truncate to fit
            truncated = dict(entry)
            keep = max(0, max_chars - 600)  # header + truncation marker room
            truncated["content"] = entry["content"][:keep] + (
                f"\n[SINGLE FILE EXCEEDS CONTEXT BATCH — truncated at {keep} "
                f"chars; page the rest with smb_read_file + offset]")
            batches.append([truncated])
            continue
        current.append(entry)
        used += entry_len
    if current:
        batches.append(current)
    return batches


def _analyze_share_batches(credential: Credential, policy: Policy, audit,
                           host: str, share_name: str,
                           file_entries: list[dict], client_factory,
                           echo, dc: str = "", domain_source: str = "auto",
                           memory: str = "") -> dict:
    """Analyze one share's dump, auto-splitting into multiple requests when
    the content exceeds the model's context window (instead of truncating).
    Each batch runs in a FRESH context window; a rolling summary carries
    findings forward between batches (same machinery as share-per-context,
    one level down). Per-batch checklist verification + findings extraction.

    Returns {"report", "findings", "memory"} — findings already tagged with
    host/share, memory is the rolling summary for the next share."""
    from .findings import extract_findings
    from .loop import AgentLoop
    from .session import AgentSession

    findings: list[dict] = []
    reports: list[str] = []
    batch_memory = ""

    total_chars = sum(len(_render_entry_text(e)) for e in file_entries)
    max_chars = _max_dump_chars(policy)
    if total_chars <= max_chars or not file_entries:
        batches = [file_entries]
    else:
        batches = _split_file_entries(file_entries, max_chars)
        echo(f"[share] {host}/{share_name}: dump {total_chars // 1000}K chars > "
             f"context budget {max_chars // 1000}K — auto-split into "
             f"{len(batches)} request(s) ({[len(b) for b in batches]} files)")

    masked_total = 0
    masked_entities: dict[str, int] = {}
    for i, batch in enumerate(batches, 1):
        # one fresh session per batch = one placeholder namespace per request
        share_session = AgentSession(credential, policy, audit, hosts=[host],
                                     dc=dc, domain_source=domain_source)
        masker = share_session.masker

        batch_note = (f"\nBATCH {i} OF {len(batches)}: this request contains "
                      f"{len(batch)} of the share's {len(file_entries)} files. "
                      f"Other batches are analyzed in separate requests — your "
                      f"checklist covers ONLY the files below."
                      if len(batches) > 1 else "")
        memory_parts = []
        if memory:
            memory_parts.append(f"MEMORY from previous shares on {host}:\n{memory}")
        if batch_memory:
            memory_parts.append(f"MEMORY from previous batches of THIS share:\n{batch_memory}")
        injected_memory = "\n\n".join(memory_parts)
        if masker is not None and injected_memory:
            # raw memory (restored cross-context values) is re-masked with
            # THIS context's placeholders before it leaves for the model
            injected_memory, hits = masker.mask_text(injected_memory)
            masked_total += hits
        memory_block = (f"\n{batch_note}\n" + injected_memory + "\n\n"
                        if injected_memory or batch_note else "")
        batch_chars = sum(len(_render_entry_text(e)) for e in batch)

        goal = _SHARE_ANALYSIS_PROMPT.format(
            host=host, share=share_name,
            n_files=len(batch), size_kb=batch_chars // 1024,
            memory_block=memory_block, incomplete="")
        dump_text = _render_dump_text(batch, share_name)
        if masker is not None:
            dump_text, hits = masker.mask_text(dump_text)
            masked_total += hits

        loop = AgentLoop(client_factory(), share_session, policy, audit, echo=echo)
        echo(f"[share] {host}/{share_name}: analyzing batch {i}/{len(batches)} "
             f"({len(batch)} file(s), {batch_chars // 1000}K"
             + (f", {masked_total} value(s) masked)" if masker is not None else ")"))
        # restore=False: the LLM-facing report stays masked for the corrective
        # round + rolling summary; the operator's copy is restored at the end
        try:
            raw_report = loop.run(goal + "\n\n" + dump_text, restore=False)
        finally:
            share_session.close_smb()   # release this batch's SMB connections

        # checklist verification for THIS batch (it saw only these files)
        batch_paths = [e["path"] for e in batch]
        if batch_paths:
            missing = _verify_file_checklist(raw_report, batch_paths)
            if missing:
                echo(f"[checklist] {host}/{share_name} batch {i}/{len(batches)}: "
                     f"{len(missing)}/{len(batch_paths)} file(s) not accounted "
                     f"for — sending corrective round")
                corrective = _corrective_checklist_round(
                    client_factory(), policy, share_name, missing, raw_report, echo)
                if corrective:
                    raw_report += "\n" + corrective
            else:
                echo(f"[checklist] {host}/{share_name} batch {i}/{len(batches)}: "
                     f"all {len(batch_paths)} file(s) accounted for ✓")

        # findings extraction per batch (double-pass union happens inside);
        # extracted from the MASKED conversation, then restored in code
        try:
            batch_findings = extract_findings(client_factory(), policy,
                                              loop.messages)
            if masker is not None:
                from ..masking import restore_findings
                restore_findings(batch_findings, masker,
                                 restore_values=policy.mask_restore)
            for f in batch_findings:
                f["host"] = host
                f["share"] = share_name
            findings.extend(batch_findings)
            echo(f"[share] {host}/{share_name} batch {i}/{len(batches)}: "
                 f"{len(batch_findings)} finding(s)")
        except Exception as exc:  # noqa: BLE001
            echo(f"[share] {host}/{share_name} batch {i}/{len(batches)}: "
                 f"extraction failed — {exc}")

        # operator-facing report: originals back in place
        report = masker.restore(raw_report) if (masker is not None
                                                and policy.mask_restore) else raw_report
        if len(batches) > 1:
            report = f"#### Batch {i}/{len(batches)}\n{report}"
        reports.append(report)

        if masker is not None:
            for entity, count in masker.summary().items():
                masked_entities[entity] = masked_entities.get(entity, 0) + count

        # rolling summary: carries THIS batch's findings to the next batch.
        # Generated from the MASKED report (what the model actually saw),
        # then restored — the next context re-masks it with its own namespace.
        if len(batches) > 1:
            batch_memory = _generate_share_summary(
                client_factory(), policy, share_name, raw_report, echo)
            if masker is not None and policy.mask_restore:
                batch_memory = masker.restore(batch_memory)

    return {"report": "\n\n".join(reports), "findings": findings,
            "memory": batch_memory or memory, "masked": masked_total,
            "masked_entities": masked_entities}


def _parse_checklist_paths(report_md: str) -> set[str]:
    """Extract file paths from 'FILE: <path> | VERDICT: ...' checklist lines.
    Robust to case/separator differences (AI might use \\ instead of /)."""
    mentioned = set()
    for line in report_md.split("\n"):
        stripped = line.strip()
        if stripped.upper().startswith("FILE:"):
            # path is between "FILE:" and the first "|"
            path_part = stripped[5:].split("|")[0].strip().strip("`\"'")
            if path_part:
                mentioned.add(path_part.lower().replace("\\", "/").strip("/"))
    return mentioned


def _verify_file_checklist(report_md: str, dumped_paths: list[str]) -> list[str]:
    """Return files from the dump that were NOT accounted for in the AI's
    checklist. This catches both format non-compliance and skipped files."""
    mentioned = _parse_checklist_paths(report_md)
    missing = []
    for path in dumped_paths:
        normalized = path.lower().replace("\\", "/").strip("/")
        if normalized not in mentioned:
            missing.append(path)
    return missing


def _corrective_checklist_round(client, policy, share_name: str,
                                 missing_files: list[str], share_report: str,
                                 echo) -> str:
    """Send a corrective round asking the AI to output checklist lines for
    files it missed. Returns the additional report text."""
    file_list = "\n".join(f"  {f}" for f in missing_files)
    prompt = (
        f"Your file checklist for share '{share_name}' was INCOMPLETE. "
        f"You did not account for these {len(missing_files)} file(s):\n"
        f"{file_list}\n\n"
        f"For EACH file listed above, output its checklist line in the "
        f"MANDATORY FORMAT:\n"
        f"FILE: <path> | VERDICT: FOUND/CLEAN/SKIPPED | <detail>\n\n"
        f"Do not repeat your previous analysis. Only output the missing "
        f"checklist lines.")
    try:
        resp = client.messages.create(
            model=policy.model,
            max_tokens=min(policy.max_tokens, 4096),
            messages=[{"role": "user", "content": prompt}])
        text = "".join(getattr(b, "text", "") for b in resp.content).strip()
        if text:
            echo(f"[checklist] corrective round: {len(missing_files)} missing "
                 f"file(s) → AI provided {text.count('FILE:')} checklist line(s)")
            return text
    except Exception as exc:  # noqa: BLE001 - best effort
        echo(f"[checklist] corrective round failed: {exc}")
    return ""


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
    """Domain computer list, code-side (deterministic — no LLM involved).
    Consults the armed inventory cache first when one is active."""
    if source_override is not None:
        return source_override()
    from ..smb_session import active_inventory_cache
    cache = active_inventory_cache()
    if cache is not None:
        cached = cache.get_computers(dc, domain_source, computers_filter or "")
        if cached is not None:
            from ..domain.base import ComputerRecord
            return [ComputerRecord(**d) for d in cached]
    if domain_source == "adws":
        from ..domain.adws_source import AdwsSource
        source = AdwsSource(credential, dc)
    else:
        from ..domain.ldap_source import LdapSource
        source = LdapSource(credential, dc)
    computers = source.list_computers(computers_filter or "")
    if cache is not None:
        cache.put_computers(dc, domain_source, computers_filter or "",
                            [c.to_dict() for c in computers])
    return computers


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
                if entry.get("masked"):
                    merged["masked"] = True
                merged["mask_entities"] = sorted(
                    set(merged.get("mask_entities") or [])
                    | set(entry.get("mask_entities") or []))
            else:
                credentials[key] = entry
        else:
            other.append(entry)
    return {"credentials": list(credentials.values()), "other": other}


def _sweep_one_host(entry: dict, host: str, run_dir: str, credential: Credential,
                    policy: Policy, dc: str, domain_source: str, computers: list,
                    client_factory, echo, read_threads: int = 10,
                    emit=None, state_store=None) -> None:
    """Sweep ONE host using PER-SHARE context windows. File reads within each
    share use ThreadPoolExecutor (SMB I/O parallelism). LLM analysis is
    sequential (one share at a time — avoids rate-limit storms) in batch
    mode; in stream mode shares are pipelined (max_shares_in_flight) with a
    global request semaphore."""
    from .audit import AuditLog
    from .session import AgentSession
    from ..report import write_report

    audit = AuditLog.new_run(run_dir, suffix=host)
    entry["audit_path"] = os.path.basename(audit.path)
    session = AgentSession(credential, policy, audit, hosts=[host],
                           dc=dc, domain_source=domain_source)
    try:
        shares = session.smb(host).list_shares()
        session.share_inventories[host] = shares
        entry["shares"] = shares
        dumpable = [s for s in shares if not s.get("special")]
        echo(f"[domain] {host}: {len(dumpable)} share(s) to analyze "
             f"({', '.join(s['name'] for s in dumpable)})")

        if getattr(policy, "analysis_mode", "batch") == "stream":
            _sweep_one_host_stream(entry, host, credential, policy, dc,
                                   domain_source, dumpable, session, audit,
                                   client_factory, echo, emit,
                                   computers=[c.to_dict() for c in computers],
                                   state_store=state_store)
            return

        all_findings: list[dict] = []
        all_reports: list[str] = []
        all_skipped: list[dict] = []    # files seen but not read (ext filter)
        memory = ""    # rolling summary from previous shares
        masked_total = 0
        masked_entities: dict[str, int] = {}
        total_dump_stats = {"dirs_walked": 0, "files_seen": 0, "files_dumped": 0,
                            "bytes_read": 0, "errors": 0}

        prior = state_store.load_host(host) if state_store else {}
        entry.setdefault("shares_done", [])
        for si, share_info in enumerate(dumpable, 1):
            share_name = share_info["name"]
            done_state = prior.get(share_name) or {}
            if done_state.get("status") == "done":
                all_reports.append(done_state.get("report") or f"### {share_name}")
                all_findings.extend(done_state.get("findings") or [])
                all_skipped.extend(done_state.get("skipped_ext") or [])
                for entity, count in (done_state.get("masked_entities") or {}).items():
                    masked_entities[entity] = masked_entities.get(entity, 0) + count
                memory = done_state.get("memory") or memory
                masked_total += int(done_state.get("masked") or 0)
                entry["shares_done"].append(share_name)
                echo(f"[share] ({si}/{len(dumpable)}) {host}/{share_name}: done in "
                     f"previous session — reusing")
                continue

            # Phase 1: dump THIS share — parallel file reads (SMB I/O)
            echo(f"[share] ({si}/{len(dumpable)}) {host}/{share_name}: dumping...")
            file_entries, share_stats, skipped_ext = _dump_single_share(
                session, host, share_name, policy, echo,
                read_threads=read_threads)
            for key in total_dump_stats:
                total_dump_stats[key] += share_stats.get(key, 0)
            entry["bytes_read"] = session.budget.bytes_read
            entry["dump_stats"] = dict(total_dump_stats)

            # Phase 2: analyze THIS share — fresh context window per share,
            # AUTO-SPLIT into multiple requests when the dump exceeds the
            # context window (per-batch windows + rolling summary)
            echo(f"[share] {host}/{share_name}: dump done "
                 f"({share_stats['files_dumped']} files) — analyzing...")
            result = _analyze_share_batches(
                credential, policy, audit, host, share_name, file_entries,
                client_factory, echo, dc=dc, domain_source=domain_source,
                memory=memory)
            share_report = result["report"]
            memory = result["memory"]
            masked_total += int(result.get("masked", 0))
            for entity, count in result.get("masked_entities", {}).items():
                masked_entities[entity] = masked_entities.get(entity, 0) + count

            all_reports.append(f"### {share_name}\n{share_report}")
            all_skipped.extend(skipped_ext)
            all_findings.extend(result["findings"])
            if state_store is not None:
                state_store.save(host, share_name, {
                    "status": "done",
                    "report": f"### {share_name}\n{share_report}",
                    "findings": result["findings"],
                    "skipped_ext": skipped_ext,
                    "masked": int(result.get("masked", 0)),
                    "masked_entities": result.get("masked_entities", {}),
                    "memory": memory,
                    "bytes_read": session.budget.bytes_read})
                entry["shares_done"].append(share_name)
            echo(f"[share] {host}/{share_name}: {len(result['findings'])} "
                 f"finding(s) total")

            entry["tool_calls"] = session.budget.tool_calls

        # Combine all share findings + reports into host-level output
        _finish_host_report(entry, host, session, audit, policy,
                            all_findings=all_findings, all_reports=all_reports,
                            all_skipped=all_skipped,
                            masked_entities=masked_entities,
                            total_dump_stats=total_dump_stats, echo=echo,
                            domain_computers=[c.to_dict() for c in computers])
        if masked_total:
            echo(f"[mask] {host}: {masked_total} sensitive value(s) replaced with "
                 f"placeholders before leaving for the LLM (restored in the report)")
        echo(f"[domain] {host}: done — {len(all_findings)} finding(s) across "
             f"{len(dumpable)} share(s), report {entry['html']}")
    finally:
        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass


def _sweep_one_host_stream(entry, host, credential, policy, dc, domain_source,
                           dumpable, session, audit, client_factory, echo, emit,
                           computers=None, state_store=None):
    """stream mode: shares pipelined (each = walkers + one LLM thread),
    bounded by max_shares_in_flight and a global LLM request semaphore."""
    from concurrent.futures import ThreadPoolExecutor
    from .stream_analysis import analyze_share_streaming, api_semaphore

    in_flight = max(1, int(getattr(policy, "max_shares_in_flight", 2)))
    sem = api_semaphore(getattr(policy, "max_concurrent_llm", 2))
    budget_lock = threading.Lock()
    echo(f"[domain] {host}: STREAM analysis — shares pipelined "
         f"(max {in_flight} in flight, {getattr(policy, 'max_concurrent_llm', 2)} "
         f"concurrent LLM requests)")

    all_findings: list[dict] = []
    all_reports: list[str] = []
    all_skipped: list[dict] = []
    masked_entities: dict[str, int] = {}
    total_dump_stats = {"dirs_walked": 0, "files_seen": 0, "files_dumped": 0,
                        "bytes_read": 0, "errors": 0}
    results: dict[str, dict] = {}
    all_artifacts: list[dict] = []
    all_known_fps: list[dict] = []
    lock = threading.Lock()

    def _run_share(si_share):
        si, share_info = si_share
        share_name = share_info["name"]
        # resume an interrupted share file-level: seed the ledger from the
        # last in-progress checkpoint (if any) and checkpoint every batch
        partial = (state_store.load(host, share_name) or {}) if state_store else {}
        resume_ledger = partial.get("ledger") if partial.get("status") == "in-progress" else None
        if resume_ledger:
            echo(f"[share] {host}/{share_name}: resuming from checkpoint "
                 f"({len(resume_ledger.get('verdicts') or {})} file(s) already verdicted)")
        # shares run concurrently: no cross-share memory chain in stream mode
        result = analyze_share_streaming(
            credential=credential, policy=policy, audit=audit, session=session,
            host=host, share_name=share_name, client_factory=client_factory,
            echo=echo, emit=emit, dc=dc, domain_source=domain_source,
            sem=sem, budget_lock=budget_lock,
            memory_block=f"({si}/{len(dumpable)}) ",
            use_triage=bool(getattr(policy, "analysis_triage", False)),
            resume=resume_ledger,
            state_sink=(lambda snap: state_store.save(host, share_name, snap))
            if state_store is not None else None)
        with lock:
            results[share_name] = result
            if state_store is not None and result.get("status") != "reused":
                state_store.save(host, share_name, dict(result, status="done"))
                entry.setdefault("shares_done", []).append(share_name)

    # shares already completed in a previous session are reused verbatim
    prior_states = state_store.load_host(host) if state_store else {}
    entry.setdefault("shares_done", [])
    todo = []
    for si, share_info in enumerate(dumpable, 1):
        share_name = share_info["name"]
        done_state = prior_states.get(share_name) or {}
        if done_state.get("status") == "done" and "stats" in done_state:
            results[share_name] = done_state
            entry["shares_done"].append(share_name)
            echo(f"[share] {host}/{share_name}: done in previous session — reusing")
        else:
            todo.append((si, share_info))

    if todo:
        with ThreadPoolExecutor(max_workers=min(in_flight, max(1, len(todo)))) as pool:
            list(pool.map(_run_share, todo))

    for share_info in dumpable:               # deterministic report order
        share_name = share_info["name"]
        result = results.get(share_name)
        if result is None:
            all_reports.append(f"### {share_name}\n(analysis failed)")
            continue
        for key in total_dump_stats:
            total_dump_stats[key] += result["stats"].get(key, 0)
        for entity, count in result.get("masked_entities", {}).items():
            masked_entities[entity] = masked_entities.get(entity, 0) + count
        all_reports.append(f"### {share_name}\n{result['report']}")
        all_findings.extend(result["findings"])
        all_skipped.extend(result["stats"].get("skipped_list", []))
        all_artifacts.extend(result.get("artifacts", []))
        all_known_fps.extend(result.get("known_fps", []))

    _finish_host_report(entry, host, session, audit, policy,
                        all_findings=all_findings, all_reports=all_reports,
                        all_skipped=all_skipped, masked_entities=masked_entities,
                        total_dump_stats=total_dump_stats, echo=echo,
                        domain_computers=computers,
                        artifacts=all_artifacts, known_fps=all_known_fps)


def _finish_host_report(entry, host, session, audit, policy,
                        all_findings, all_reports, all_skipped,
                        masked_entities, total_dump_stats, echo,
                        domain_computers, artifacts=None, known_fps=None):
    """Assemble the per-host report (shared by batch and stream paths)."""
    from ..report import write_report

    entry["dump_stats"] = total_dump_stats
    entry["findings"] = all_findings
    entry["report_md"] = "\n\n".join(all_reports)
    entry["skipped_files"] = all_skipped
    entry["bytes_read"] = session.budget.bytes_read
    entry["tool_calls"] = session.budget.tool_calls

    red = session.credential.redacted()
    html_path = audit.path[:-len(".jsonl")] + ".report.html"
    masking = ({"entities": masked_entities, "restored": policy.mask_restore}
               if (policy.mask_pii or policy.mask_secrets or policy.mask_semantic)
               else None)
    write_report(html_path,
                 context={"principal": red["principal"],
                          "auth_type": red["auth_type"], "scope": [host],
                          "model": policy.model,
                          "endpoint": policy.api_base_url or "api.anthropic.com"},
                 masking=masking,
                 findings=all_findings, scan_results=session.scan_results,
                 flagged=session.flagged_files,
                 report_md=entry["report_md"],
                 audit_path=audit.path,
                 domain_computers=domain_computers or [],
                 share_inventories=session.share_inventories,
                 transcript=[],
                 debug_results=session.debug_results if policy.debug else [],
                 dump_stats=total_dump_stats,
                 skipped_files=all_skipped,
                 artifacts=artifacts or [], known_fps=known_fps or [])
    entry["html"] = os.path.basename(html_path)
    entry["masked"] = sum(masked_entities.values())
    entry["masked_entities"] = masked_entities
    entry["status"] = "done"
    echo(f"[domain] {host}: done — {len(all_findings)} finding(s), "
         f"report {os.path.basename(html_path)}")


def _sweep_host_with_retry(entry, host, run_dir, credential, policy, dc,
                           domain_source, computers, client_factory, echo,
                           read_threads=10, emit=None, state_store=None):
    """Sweep one host with transient-error retry. Fills entry fields on
    success; records errors."""
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
                            read_threads=read_threads, emit=emit,
                            state_store=state_store)
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


def _print_config_banner(credential: Credential, policy: Policy, dc: str,
                         domain_source: str, concurrency: int, echo) -> None:
    """Print a settings banner + equivalent CLI command at the start of a run."""
    red = credential.redacted()
    sep = "═" * 60

    # equivalent CLI command (password masked)
    auth_flag = {"password": f"--password ***",
                 "ntlm": f"--hashes ***:{'*' * 32}",
                 "aes": "--aes-key ***",
                 "ticket": f"--ticket {credential.ticket_path or '***'}"}.get(
        credential.auth_type.value, "")

    cmd_parts = [
        "credshrike agent",
        f"--dc {dc}" if dc else "",
        f"--user {credential.username}",
        f"--domain {credential.domain}",
        auth_flag,
        f"--kdc {credential.kdc_host}" if credential.kdc_host else "",
        f"--model {policy.model}",
        f"--api-base-url {policy.api_base_url}" if policy.api_base_url else "",
        f"--concurrency {concurrency}" if concurrency > 1 else "",
        f"--context-limit {policy.context_token_limit}" if policy.context_token_limit else "",
        f"--read-gate {policy.read_gate}" if policy.read_gate != "none" else "",
        f"--redact '{','.join(policy.redact_literals)}'" if policy.redact_literals else "",
        "--mask-pii" if policy.mask_pii else "",
        "--mask-secrets" if policy.mask_secrets else "",
        "--mask-semantic" if policy.mask_semantic else "",
        f"--skip-exts '{','.join(policy.dump_skip_exts[:6])}...'" if policy.dump_skip_exts else "",
        f"--analysis-mode {policy.analysis_mode}" if getattr(policy, "analysis_mode", "batch") != "batch" else "",
        f"--max-concurrent-llm {policy.max_concurrent_llm}" if getattr(policy, "max_concurrent_llm", 2) != 2 else "",
        f"--socks-proxy {policy.socks_proxy}" if getattr(policy, "socks_proxy", "") else "",
        "--debug" if policy.debug else "",
    ]
    cli_cmd = " \\\n  ".join(p for p in cmd_parts if p)

    echo(sep)
    echo(" CredShrike — Configuration")
    echo(sep)
    echo(f" Credential : {red['principal']} ({red['auth_type']})")
    echo(f" DC         : {dc or '(not set)'}")
    echo(f" Transport  : {'adws (net.tcp 9389)' if domain_source == 'adws' else 'ldap (389)' if domain_source == 'ldap' else 'auto → ldap'}")
    echo(f" Model      : {policy.model} @ {policy.api_base_url or 'api.anthropic.com'}")
    if getattr(policy, "socks_proxy", ""):
        echo(f" SOCKS      : {policy.socks_proxy} (SMB/LDAP/ADWS only — LLM direct)")
    if getattr(policy, "inventory_cache", True):
        echo(f" Cache      : <audit_dir>/.cache/inventory.db "
             f"(ttl {getattr(policy, 'cache_ttl_hours', 24)}h, "
             f"content {'on' if getattr(policy, 'cache_content', True) else 'off'})")
    else:
        echo(" Cache      : off (--no-cache)")
    echo(f" Concurrency: {concurrency} thread(s) (parallel file reads)")
    echo(f" Skip exts  : {len(policy.dump_skip_exts)} types" +
         (f" ({', '.join(policy.dump_skip_exts[:5])}...)" if policy.dump_skip_exts else " (none)"))
    echo(f" Read gate  : {policy.read_gate}")
    mask_types = [t for t, on in (("PII", policy.mask_pii),
                                  ("semantic PII (GLiNER)", policy.mask_semantic),
                                  ("secrets", policy.mask_secrets)) if on]
    if mask_types:
        same = ", ".join(policy.mask_same_length or [])
        style = (f"same-length surrogates for {same}" if same else "[[TYPE_N]] placeholders")
        if same and "EMAIL_ADDRESS" in {s.upper() for s in policy.mask_same_length}:
            style += f" (email domain → {policy.mask_email_domain})"
        echo(f" Masking    : {', '.join(mask_types)} → {style}"
             f"{' + [[TYPE_N]] for the rest' if same else ''}, "
             f"{'restored' if policy.mask_restore else 'NOT restored'} in output")
    else:
        echo(" Masking    : off")
    echo(f" Context    : {policy.context_token_limit or 'off'}" +
         (f" (compact at {int(policy.compact_at_ratio * 100)}%)" if policy.context_token_limit else ""))
    echo(f" Budget     : {policy.max_tool_calls} calls / {policy.max_total_read_bytes // 1048576} MiB / {policy.wall_clock_seconds}s")
    echo(f" Streaming  : {'SSE (live output, auto-fallback)' if policy.stream else 'off'}")
    echo(f" Prompt cache: {'on (auto-fallback)' if policy.prompt_cache else 'off'}")
    if getattr(policy, "analysis_mode", "batch") == "stream":
        echo(f" Analysis   : stream (group={policy.analysis_group_files} files/request, "
             f"reset@{int(policy.analysis_reset_ratio * 100)}%, "
             f"≤{policy.max_concurrent_llm} concurrent LLM, "
             f"{policy.max_shares_in_flight} share(s) in flight"
             + (", Snaffler triage" if getattr(policy, "analysis_triage", False)
                else "") + ")")
    else:
        echo(" Analysis   : batch (dump-then-analyze, auto-split)")
    echo(f" Debug      : {'ON' if policy.debug else 'off'}")
    echo(sep)
    echo(" Equivalent CLI command:")
    echo(f"  {cli_cmd}")
    echo(sep)


def run_domain_sweep(*, credential: Credential, policy: Policy,
                     audit_dir: str = "runs", dc: str = "", domain_source: str = "auto",
                     computers_filter: str = "", max_hosts: Optional[int] = None,
                     client_factory: Optional[Callable] = None, echo=print,
                     source_override=None, reachable_check: Optional[Callable] = None,
                     concurrency: int = 0, emit=None,
                     resume_dir: Optional[str] = None) -> dict:
    """Sweep a domain. Hosts are SEQUENTIAL (one at a time — LLM analysis is
    the bottleneck, not host discovery). Within each share, files are read
    in PARALLEL via ThreadPoolExecutor (SMB I/O parallelism). The
    `concurrency` parameter controls file-read threads per share, not
    parallel hosts."""
    if not concurrency or concurrency < 1:
        concurrency = int(getattr(policy, "read_threads", 10))
    if reachable_check is None:
        reachable_check = _port_open
    from .audit import AuditLog
    from .cli_agent import _make_client

    if client_factory is None:
        client_factory = lambda: _make_client(policy)  # noqa: E731

    # ---- resume vs fresh: establish run_dir + manifest -------------------- #
    from ..runstate import (RunManifest, ShareStateStore,
                           fingerprint_components, fingerprint_diff,
                           load_host_result)

    resumed = resume_dir is not None
    if resumed:
        manifest = RunManifest.load(resume_dir)
        changed = fingerprint_diff(
            manifest.data.get("fingerprint_components") or {},
            dc, domain_source, computers_filter, max_hosts, policy)
        if changed:
            raise ValueError(
                "cannot resume — parameters changed since the run started: "
                + ", ".join(changed))
        from ..domain.base import ComputerRecord
        computers = [ComputerRecord(**d)
                     for d in manifest.data.get("computers") or []]
        run_dir = resume_dir
    else:
        computers = _resolve_computers(credential, dc, domain_source,
                                       computers_filter, source_override)
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        run_dir = os.path.join(audit_dir, f"domain_{stamp}")
        os.makedirs(run_dir, exist_ok=True)
        manifest = RunManifest.create(
            run_dir, hosts=[],
            components=fingerprint_components(dc, domain_source,
                                              computers_filter, max_hosts, policy),
            computers=[c.to_dict() for c in computers])
    state_store = ShareStateStore(run_dir)
    hosts = [c.dns_name or c.cn for c in computers]
    if max_hosts:
        hosts = hosts[:max_hosts]
    manifest.data["hosts_order"] = list(hosts)
    for h in hosts:
        manifest.data["hosts"].setdefault(
            h, {"status": "pending", "error": "", "shares": [],
                "shares_done": [], "html": "", "audit_path": "",
                "findings_count": 0, "tool_calls": 0, "bytes_read": 0})
    if resumed:
        done_before = sum(1 for h in hosts
                          if manifest.host_status(h) == "done")
        echo(f"[domain] RESUMING {run_dir}: {done_before}/{len(hosts)} host(s) "
             f"done, {sum(len(manifest.data['hosts'][h].get('shares_done', [])) for h in hosts)} "
             f"share(s) checkpointed")
    transport = "adws (net.tcp 9389)" if domain_source == "adws" else \
               f"ldap (389) [{domain_source}]" if domain_source == "ldap" else \
               f"auto → ldap (389) [requested: {domain_source}]"
    _print_config_banner(credential, policy, dc, domain_source, concurrency, echo)
    echo(f"[domain] TRANSPORT: {transport} — querying domain computers")
    if max_hosts:
        hosts = hosts[:max_hosts]
    echo(f"[domain] {len(computers)} computer(s) in scope — sweeping {len(hosts)}"
         + (f" (read_threads={concurrency})" if concurrency > 1 else ""))
    if concurrency > 1:
        echo(f"[domain] PARALLEL FILE READS: {concurrency} threads per share — "
             f"SMB I/O runs concurrently; hosts are sequential")

    started = time.time()
    if resumed:
        # wall-clock gate must account for the time already spent
        started -= float(manifest.budget_spend().get("elapsed_s") or 0.0)
    results: list[dict] = []

    # seed the results list: DONE hosts recover their findings/reports for
    # the final merge; partially-swept hosts keep their spent counters so
    # the global budget gate stays honest
    for host in hosts:
        if manifest.host_status(host) == "done":
            results.append(load_host_result(run_dir, host))
            continue
        prior = manifest.data["hosts"].get(host, {})
        results.append({"host": host, "status": "pending", "error": "",
                        "shares": prior.get("shares", []), "findings": [],
                        "report_md": "", "audit_path": "",
                        "html": prior.get("html", ""),
                        "tool_calls": int(prior.get("tool_calls") or 0),
                        "bytes_read": int(prior.get("bytes_read") or 0),
                        "shares_done": prior.get("shares_done", [])})
    if resumed:
        # spend recorded in the manifest but not attributable to any host
        # entry (crash mid-sweep) still counts against the global gate —
        # attribute the deficit to the first host that still has to run
        deficit = int(manifest.budget_spend().get("bytes_read") or 0) - \
            sum(r["bytes_read"] for r in results)
        if deficit > 0:
            for r in results:
                if r["status"] != "done":
                    r["bytes_read"] += deficit
                    break

    for index, host in enumerate(hosts, 1):
        entry = results[index - 1]
        if entry.get("status") == "done":
            echo(f"[domain] ({index}/{len(hosts)}) {host}: done in previous "
                 f"session — skipping")
            continue
        # budget gate
        total_bytes = sum(r["bytes_read"] for r in results)
        total_calls = sum(r["tool_calls"] for r in results)
        if total_calls >= policy.max_tool_calls or \
                total_bytes >= policy.max_total_read_bytes or \
                time.time() - started > policy.wall_clock_seconds:
            entry["status"] = "skipped-budget"
            _update_manifest_host(manifest, entry, started,
                                  total_bytes=total_bytes, total_calls=total_calls)
            echo(f"[domain] {host}: SKIPPED — global budget exhausted")
            continue
        if not reachable_check(host):
            entry["status"] = "unreachable"
            _update_manifest_host(manifest, entry, started,
                                  total_bytes=total_bytes, total_calls=total_calls)
            echo(f"[domain] {host}: SMB 445 unreachable — skipped")
            continue
        manifest.mark_host(host, status="in-progress")
        manifest.save()
        echo(f"[domain] ({index}/{len(hosts)}) {host}: sweeping")
        _sweep_host_with_retry(entry, host, run_dir, credential, policy, dc,
                               domain_source, computers, client_factory, echo,
                               read_threads=concurrency, emit=emit,
                               state_store=state_store)
        _update_manifest_host(manifest, entry, started,
                              total_bytes=sum(r["bytes_read"] for r in results),
                              total_calls=sum(r["tool_calls"] for r in results))

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

    manifest.mark_complete()
    done = sum(1 for r in results if r["status"] == "done")
    n_creds = len(merged["credentials"])
    elapsed = int(time.time() - started)
    echo(f"[domain] sweep complete: {done}/{len(results)} hosts swept, "
         f"{n_creds} unique credential(s), {elapsed}s — index: {index_path}")
    from ..smb_session import active_inventory_cache
    cache = active_inventory_cache()
    cache_stats = cache.stats() if cache is not None else None
    if cache_stats and (cache_stats["hits"] or cache_stats["misses"]):
        echo(f"[cache] {cache_stats['hits']} hit(s) / {cache_stats['misses']} "
             f"miss(es), {cache_stats['bytes_served'] // 1024} KiB served "
             f"from {cache_stats['db_path']}")
    return {"hosts": results, "merged": merged, "index_html": index_path,
            "run_dir": run_dir, "computers": [c.to_dict() for c in computers],
            "resumed": resumed, "cache": cache_stats}


def _update_manifest_host(manifest, entry: dict, started: float,
                          total_bytes: int = 0, total_calls: int = 0) -> None:
    """Persist one host's outcome + the global budget spend (atomic)."""
    manifest.mark_host(
        entry["host"],
        status=entry.get("status", "pending"),
        error=entry.get("error", ""),
        shares=entry.get("shares", []),
        shares_done=entry.get("shares_done", []),
        html=entry.get("html", ""),
        audit_path=entry.get("audit_path", ""),
        findings_count=len(entry.get("findings") or []),
        tool_calls=int(entry.get("tool_calls") or 0),
        bytes_read=int(entry.get("bytes_read") or 0))
    manifest.record_budget(bytes_read=total_bytes, tool_calls=total_calls,
                           elapsed_s=max(0.0, time.time() - started))
    manifest.save()
