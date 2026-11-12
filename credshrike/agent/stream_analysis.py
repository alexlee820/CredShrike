"""Streaming share analysis (``analysis_mode: stream``).

Pipeline per share (producer–consumer):

    walkers (list_dir BFS)  ──path queue──▶  LLM worker thread
    (paths only — tiny RAM)                  (reads files itself, one
                                             dedicated SMB connection)

The LLM worker sends one request per GROUP of K files (micro-batch), keeps a
single shared conversation per share (append-only → prompt-cache friendly),
and every file must produce a checklist verdict line. Coverage is enforced by
a code-side ledger — the reduce report's Part 1 checklist is GENERATED from
the ledger, so the AI can never "forget" a file.

End of stream: walk sentinel → drain → (verify) → REDUCE → finalize.
"""

from __future__ import annotations

import json
import re
import threading
import time
from queue import Empty, Queue
from typing import Callable, Optional

from ..config import Policy
from ..credentials import Credential

_FILE_LINE_RE = re.compile(
    r"FILE:\s*(?P<path>.+?)\s*\|\s*VERDICT:\s*(?P<verdict>[A-Za-z]+)", re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?\s*(?P<body>.*?)```", re.DOTALL)
VALID_VERDICTS = {"FOUND", "CLEAN", "SKIPPED", "UNREADABLE", "UNRESOLVED"}

_STREAM_SYSTEM = (
    "You are a read-only data-exposure analyst embedded in an authorized SMB "
    "assessment. Analyze ONLY the file contents given in each message. Follow "
    "the requested output format EXACTLY. Some values are privacy pseudonyms "
    "(realistic-looking names/accounts) or [[TYPE_N]] placeholders — they ARE "
    "the real values for your purposes: copy them VERBATIM, never alter, "
    "shorten or 'fix' them. Do not call tools.")

_BATCH_PROMPT = (
    "Analyze the {n} file(s) below from SMB share '{share}' on host {host}.{digest}"
    "For EVERY file output EXACTLY ONE line:\n"
    "FILE: <path> | VERDICT: FOUND | <category> | <one-line detail>\n"
    "FILE: <path> | VERDICT: CLEAN\n"
    "FILE: <path> | VERDICT: SKIPPED | <reason>\n"
    "FOUND means credentials / PII / financial / internal-network data (state "
    "category: credential|pii|financial|network_info|sensitive_file|other and "
    "what exactly). CLEAN means nothing sensitive.\n"
    "After the FILE lines, output your findings as ONE fenced ```json array:\n"
    '[{{"path": "...", "category": "...", "username": null, "secret": null, '
    '"note": "...", "severity": "high|medium|low"}}]\n'
    "One object per finding; include username/secret values verbatim when "
    "present (they may be pseudonyms/placeholders).\n")

_REDUCE_PROMPT = (
    "Analysis of share '{share}' on host {host} is complete. Below is the "
    "code-verified per-file ledger and the entity index (pseudonyms are "
    "consistent across files). Write the share report — ONLY these parts:\n"
    "PART 2: DETAILED FINDINGS — for every FOUND file, the exact items with "
    "verbatim values. Ledger entries marked 'artifact <tier>' are files that "
    "ARE secrets themselves (password stores, credential/hive dumps, key "
    "files); call each one out with its tier even though its content was "
    "never read.\n"
    "PART 3: SUMMARY (max 150 words) — what was found, patterns, cross-file "
    "correlations visible in the entity index.\n")

_DIGEST_PROMPT = (
    "Context from earlier in this share (a previous analysis session):\n")


def _norm(path: str) -> str:
    return (path or "").lower().replace("\\", "/").strip("/")


def parse_batch_response(text: str):
    """→ (verdicts {norm_path: VERDICT}, findings [dict])."""
    verdicts: dict[str, str] = {}
    for match in _FILE_LINE_RE.finditer(text or ""):
        verdict = match.group("verdict").upper()
        if verdict in VALID_VERDICTS:
            verdicts[_norm(match.group("path"))] = verdict
    findings: list[dict] = []
    fence = _FENCE_RE.search(text or "")
    if fence:
        try:
            data = json.loads(fence.group("body"))
            if isinstance(data, list):
                findings = [f for f in data if isinstance(f, dict)]
        except Exception:  # noqa: BLE001 - malformed fence is survivable
            pass
    return verdicts, findings


# --------------------------------------------------------------------------- #
# ledger: code-side source of truth for coverage
# --------------------------------------------------------------------------- #
class ShareLedger:
    def __init__(self, share: str):
        self.share = share
        self.verdicts: dict[str, dict] = {}   # norm path -> {verdict, detail}
        self.findings: list[dict] = []        # masked findings (restore later)
        self.token_hits: dict[str, list[str]] = {}  # masked token -> [paths]
        self.token_entities: dict[str, str] = {}
        self.unreadable: dict[str, str] = {}  # path -> error
        self.budget_skipped: list[str] = []
        self.skipped_ext: list[dict] = []
        self.bytes_read = 0

    def note_file(self, path: str) -> None:
        self.verdicts.setdefault(_norm(path), {"verdict": "UNRESOLVED", "detail": ""})

    def record(self, path: str, verdict: str, detail: str = "") -> None:
        self.verdicts[_norm(path)] = {"verdict": verdict.upper(), "detail": detail}

    def record_tokens(self, masked_text: str, masker, path: str) -> None:
        if masker is None:
            return
        for token, entity in masker.tokens_in(masked_text).items():
            hits = self.token_hits.setdefault(token, [])
            if path not in hits:
                hits.append(path)
            self.token_entities[token] = entity

    def unresolved(self) -> list[str]:
        return [p for p, v in self.verdicts.items() if v["verdict"] == "UNRESOLVED"]

    def digest(self, max_found: int = 200) -> str:
        counts: dict[str, int] = {}
        for entry in self.verdicts.values():
            counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
        lines = [f"Progress: {len(self.verdicts)} files processed "
                 + ", ".join(f"{k}×{v}" for k, v in sorted(counts.items())) + "."]
        found = [(p, v) for p, v in self.verdicts.items() if v["verdict"] == "FOUND"]
        for path, entry in found[:max_found]:
            lines.append(f"- {path}: {entry['detail'][:120]}")
        if len(found) > max_found:
            lines.append(f"… and {len(found) - max_found} more FOUND files")
        if self.token_hits:
            lines.append("Entities seen (pseudonyms, consistent):")
            for token, paths in list(self.token_hits.items())[:80]:
                entity = self.token_entities.get(token, "?")
                lines.append(f"- {token} [{entity}] in {', '.join(paths[:6])}"
                             + (f" (+{len(paths) - 6})" if len(paths) > 6 else ""))
        return "\n".join(lines)

    def checklist_md(self, real_paths: list[str]) -> str:
        """Part 1 of the report, GENERATED from the ledger (coverage by
        construction — every walked file gets exactly one line)."""
        lines = []
        lookup = {_norm(p): p for p in real_paths}
        for norm, entry in sorted(self.verdicts.items()):
            shown = lookup.get(norm, norm)
            detail = entry["detail"]
            line = f"FILE: {shown} | VERDICT: {entry['verdict']}"
            if detail:
                line += f" | {detail}"
            lines.append(line)
        for path in self.unreadable:
            lines.append(f"FILE: {path} | VERDICT: UNREADABLE | read failed")
        for path in self.budget_skipped:
            lines.append(f"FILE: {path} | VERDICT: SKIPPED | byte budget exhausted")
        for entry in self.skipped_ext:
            lines.append(f"FILE: {entry.get('path')} | VERDICT: SKIPPED "
                         f"| extension filter ({entry.get('ext')})")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# LLM plumbing: streaming + cache + rate-limit retry under a global semaphore
# --------------------------------------------------------------------------- #
_SEMAPHORES: dict[int, threading.Semaphore] = {}
_SEM_LOCK = threading.Lock()


def api_semaphore(max_concurrent: int) -> threading.Semaphore:
    max_concurrent = max(1, int(max_concurrent or 1))
    with _SEM_LOCK:
        if max_concurrent not in _SEMAPHORES:
            _SEMAPHORES[max_concurrent] = threading.Semaphore(max_concurrent)
        return _SEMAPHORES[max_concurrent]


def llm_request(client, policy: Policy, messages: list[dict], echo,
                sem: threading.Semaphore) -> str:
    """One non-tool request with streaming echo, prompt-cache breakpoints and
    rate-limit retry. Returns the assistant text."""
    from .prompt_cache import cacheable_messages, cacheable_system, is_cache_unsupported
    cache_ok = bool(getattr(policy, "prompt_cache", False))
    for attempt in range(4):
        kwargs = dict(
            model=policy.model,
            max_tokens=min(policy.max_tokens, 8192),
            system=cacheable_system(_STREAM_SYSTEM, cache_ok),
            messages=cacheable_messages(messages, cache_ok))
        try:
            with sem:
                stream_factory = getattr(client.messages, "stream", None)
                if getattr(policy, "stream", False) and stream_factory:
                    with stream_factory(**kwargs) as stream:
                        buf = ""
                        for delta in stream.text_stream:
                            if not delta:
                                continue
                            buf += delta
                            if "\n" in buf:
                                echo(f"  ✎ {buf.strip()}")
                                buf = ""
                        if buf:
                            echo(f"  ✎ {buf.strip()}")
                        resp = stream.get_final_message()
                else:
                    resp = client.messages.create(**kwargs)
            return "".join(getattr(b, "text", "") for b in resp.content)
        except Exception as exc:  # noqa: BLE001
            if cache_ok and is_cache_unsupported(exc):
                cache_ok = False
                echo("  ! prompt caching rejected — retrying without it")
                continue
            low = str(exc).lower()
            if "rate" in low or "429" in low or "limit" in low or "overloaded" in low:
                wait = 2 * (2 ** attempt)
                echo(f"  ⏳ rate limited, retrying in {wait}s "
                     f"(attempt {attempt + 1}/4)")
                time.sleep(wait)
                continue
            raise
    raise RuntimeError("llm request failed after retries")


# --------------------------------------------------------------------------- #
# the share pipeline
# --------------------------------------------------------------------------- #
def _drain(q: Queue, limit: int, wait_s: float, done: threading.Event) -> list:
    """Collect up to ``limit`` paths, waiting at most ``wait_s`` for the
    first. The walk's None sentinel sets ``done`` (never re-queued)."""
    batch: list = []
    try:
        first = q.get(timeout=wait_s)
    except Empty:
        return batch
    if first is None:
        done.set()
        return batch
    batch.append(first)
    while len(batch) < limit:
        try:
            item = q.get_nowait()
        except Empty:
            break
        if item is None:
            done.set()
            break
        batch.append(item)
    return batch


def analyze_share_streaming(*, credential: Credential, policy: Policy, audit,
                            session, host: str, share_name: str,
                            client_factory, echo, emit: Optional[Callable] = None,
                            dc: str = "", domain_source: str = "auto",
                            memory: str = "", sem: Optional[threading.Semaphore] = None,
                            budget_lock: Optional[threading.Lock] = None,
                            memory_block: str = "",
                            use_triage: Optional[bool] = None,
                            focus: str = "",
                            resume: Optional[dict] = None,
                            state_sink: Optional[Callable] = None) -> dict:
    """Same result contract as _analyze_share_batches:
    {"report", "findings", "memory", "masked", "masked_entities", "stats",
     "artifacts" (use_triage only)}.

    use_triage=True = the snaffler preset: the 4-layer Snaffler triage runs
    in the walker (discard at walk time; artifacts reported WITHOUT reading;
    relay files streamed to the LLM). Detection is 100% LLM — the only
    regexes involved are PasteGuard masking. use_triage=False = full mode:
    every non-skip-ext file is streamed to the LLM."""
    from ..masking import Masker, restore_findings
    from ..smb_session import create_smb_session
    from .orchestrator import (_OFFICE_EXTRACTABLE, _extract_office_text,
                               _generate_share_summary, _walk_share_files)

    if use_triage is None:      # not passed -> follow the policy
        use_triage = bool(getattr(policy, "analysis_triage", False))
    emit = emit or (lambda ch, line, share=None: echo(line))
    sem = sem or api_semaphore(getattr(policy, "max_concurrent_llm", 2))
    budget_lock = budget_lock or threading.Lock()
    k = max(1, int(getattr(policy, "analysis_group_files", 10)))
    wait_s = max(0.05, int(getattr(policy, "analysis_group_wait_ms", 2000)) / 1000)
    per_file = policy.dump_per_file_bytes
    masker = Masker.from_policy(policy)
    ledger = ShareLedger(share_name)
    if resume:
        # continue an interrupted share: restore coverage state (NOT the
        # token maps or findings — masker namespaces are per-context and
        # persisted findings are merged by the orchestrator instead)
        ledger.verdicts.update({k: dict(v)
                                for k, v in (resume.get("verdicts") or {}).items()})
        ledger.unreadable.update(resume.get("unreadable") or {})
        ledger.budget_skipped.extend(resume.get("budget_skipped") or [])

    def say(channel, line):
        emit(channel, line, share_name)

    def _checkpoint():
        """Persist the in-progress ledger after each LLM batch so an
        interrupted share resumes file-level (never kills analysis)."""
        if state_sink is None:
            return
        try:
            state_sink({"status": "in-progress",
                        "ledger": {"verdicts": {k: dict(v) for k, v in ledger.verdicts.items()},
                                   "unreadable": dict(ledger.unreadable),
                                   "budget_skipped": list(ledger.budget_skipped)}})
        except Exception:  # noqa: BLE001
            pass

    # ---- phase 1: walkers (producers — paths only) ---------------------- #
    say("walk", f"[share] {host}/{share_name}: walking…")
    q: Queue = Queue()
    walk_done = threading.Event()
    pool = session.get_read_pool(host)
    walk_result: dict = {}

    artifacts_found: list[dict] = []     # triage layer 2/4 (never read)
    triage_none: list[str] = []         # no rule matched -> skipped, not read
    known_fps: list[dict] = []          # discarded by the known-FP name rules

    def _on_file(f):
        prior = ledger.verdicts.get(_norm(f["path"]))
        if prior and prior.get("verdict") not in (None, "UNRESOLVED"):
            return          # analyzed before the interruption — keep its verdict
        if not use_triage:
            q.put(f)
            return
        from ..patterns import triage as snaffler_triage
        verdict = snaffler_triage(f["path"])
        kind = verdict["kind"]
        if kind == "relay" or (kind == "artifact" and verdict.get("read")):
            q.put(f)                     # relay content -> LLM
        elif kind in ("artifact", "green"):
            artifacts_found.append(
                {"path": f["path"], "size": f.get("size", 0),
                 "tier": verdict.get("tier", "green"),
                 "reason": verdict.get("reason", "")})
        elif kind == "discard":
            known_fps.append({"path": f["path"], "host": host,
                              "share": share_name,
                              "reason": verdict.get("reason", "")})
        elif kind is None:
            triage_none.append(f["path"])

    def _walk():
        from ..patterns import DISCARD_EXTS
        try:
            files, dirs, skipped = _walk_share_files(
                session.smb(host), share_name,
                policy.dump_depth, policy.dump_max_files,
                lambda line: say("walk", line),
                skip_exts=DISCARD_EXTS if use_triage else set(policy.dump_skip_exts),
                conn_pool=pool, walk_threads=session.read_threads,
                on_file=_on_file)
            walk_result.update(files=files, dirs=dirs, skipped=skipped)
        except Exception as exc:  # noqa: BLE001 — surfaced via result
            walk_result.update(error=str(exc), files=[], dirs=0, skipped=[])
        finally:
            walk_done.set()
            q.put(None)

    threading.Thread(target=_walk, daemon=True,
                     name=f"walk-{host}-{share_name}").start()

    # ---- phase 2: LLM worker (single consumer) -------------------------- #
    client = client_factory()
    try:
        read_conn = create_smb_session(credential, host, timeout=30)
        read_conn.connect()
        own_conn = True
    except Exception:  # noqa: BLE001 — mocks / no network: shared session
        read_conn = session.smb(host)
        own_conn = False
    say("ai", f"[ai] {share_name}: analysis thread ready "
              f"(group={k}, own SMB conn={own_conn})")

    messages: list[dict] = []
    session_chars = 0
    reset_chars = _reset_budget(policy)
    total_seen = 0

    def _new_session(opening: str):
        nonlocal messages, session_chars
        messages = [{"role": "user", "content": opening}]
        session_chars = len(opening)

    opening = (f"Share: {share_name} on {host}. {memory_block}" +
               (_DIGEST_PROMPT + memory + "\n" if memory else "") +
               "Reply 'ready'.")
    if ledger.verdicts:
        # fresh LLM session, carried coverage: mirror the context-reset digest
        opening += ("\n" + _DIGEST_PROMPT + ledger.digest() +
                    "\n(This continues an interrupted analysis of the same "
                    "share; checklist items above were already covered.)")
    _new_session(opening)
    llm_request(client, policy, messages, lambda l: say("ai", l), sem)

    try:
        while True:
            batch = _drain(q, k, wait_s, walk_done)
            if not batch:
                if walk_done.is_set() and q.empty():
                    break
                continue
            # ---- read this group's files (serial, on this thread) ------ #
            entries = []
            for f in batch:
                path = f["path"]
                with budget_lock:
                    left = policy.max_total_read_bytes - session.budget.bytes_read
                if left <= 0:
                    ledger.budget_skipped.append(path)
                    continue
                try:
                    read = read_conn.read_file(share_name, path, max_bytes=per_file)
                    import base64 as _b64
                    data = _b64.b64decode(read.get("content_b64", ""))
                except Exception as exc:  # noqa: BLE001
                    ledger.unreadable[path] = str(exc)[:80]
                    say("ai", f"  ! read failed: {path} — {str(exc)[:60]}")
                    continue
                ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
                content = data.decode("utf-8", errors="replace")
                if ext in _OFFICE_EXTRACTABLE and data:
                    text = _extract_office_text(data, ext)
                    if text:
                        content = text
                with budget_lock:
                    session.budget.bytes_read += len(data)
                ledger.bytes_read += len(data)
                masked = content
                if masker is not None:
                    masked, _hits = masker.mask_text(content)
                ledger.note_file(path)
                ledger.record_tokens(masked, masker, path)
                entries.append({"path": path, "masked": masked,
                                "size": f.get("size", len(data)),
                                "head_truncated": len(data) >= per_file})
            if not entries:
                continue
            total_seen += len(entries)

            if session_chars > reset_chars:
                say("ai", f"[ai] {share_name}: context near limit — "
                          f"resetting session (ledger carried over)")
                _new_session(opening + "\n" + _DIGEST_PROMPT + ledger.digest())
                llm_request(client, policy, messages,
                            lambda l: say("ai", l), sem)

            chunk = [f"---- {e['path']} ({e['size']}B"
                     f"{' head_truncated' if e['head_truncated'] else ''}) ----\n"
                     f"{e['masked']}" for e in entries]
            digest = (_DIGEST_PROMPT + ledger.digest() + "\n"
                      if ledger.findings or total_seen > k else "")
            prompt = _BATCH_PROMPT.format(
                n=len(entries), share=share_name, host=host, digest=digest) \
                + (f"OPERATOR FOCUS — the scope is fixed, but pay special "
                   f"attention to: {focus}\n\n" if focus else "") \
                + "\n".join(chunk)
            say("ai", f"[ai] {share_name}: request ({len(entries)} files, "
                      f"{len(prompt) // 1000}K chars)")
            messages.append({"role": "user", "content": prompt})
            session_chars += len(prompt)
            try:
                text = llm_request(client, policy, messages,
                                   lambda l: say("ai", l), sem)
            except Exception as exc:  # noqa: BLE001 — mark group unresolved
                for e in entries:
                    ledger.record(e["path"], "UNRESOLVED", f"request failed: {exc}"[:80])
                _checkpoint()
                say("ai", f"  ! batch failed — {len(entries)} file(s) UNRESOLVED")
                continue
            messages.append({"role": "assistant", "content": text})
            session_chars += len(text)
            verdicts, findings = parse_batch_response(text)
            for e in entries:
                verdict = verdicts.get(_norm(e["path"]))
                if verdict:
                    ledger.record(e["path"], verdict, "")
                # entries without a verdict line stay UNRESOLVED
            for finding in findings:
                finding.setdefault("path", entries[0]["path"])
                ledger.findings.append(finding)
            say("ai", f"[ai] {share_name}: {len(verdicts)}/{len(entries)} "
                      f"verdict(s), {len(findings)} finding(s) "
                      f"(total {total_seen} files)")
            _checkpoint()
    finally:
        if own_conn:
            try:
                read_conn.close()
            except Exception:  # noqa: BLE001
                pass

    # ---- drain remaining + coverage ------------------------------------- #
    while not q.empty():
        try:
            item = q.get_nowait()
        except Empty:
            break
        if item is not None:
            ledger.record(item["path"], "UNRESOLVED", "walk finished during analysis")
    walk_files = walk_result.get("files", [])
    ledger.skipped_ext = walk_result.get("skipped", [])
    for f in walk_files:
        ledger.note_file(f["path"])

    # triage layers 2/4: artifacts get code-generated verdicts (never read)
    for path in triage_none:
        ledger.record(path, "SKIPPED", "no snaffler rule matched (not read)")
    for fp in known_fps:
        ledger.record(fp["path"], "SKIPPED",
                      "known false positive — discarded (not read)")
    artifact_findings: list[dict] = []
    for entry in artifacts_found:
        entry.setdefault("host", host)
        entry.setdefault("share", share_name)
        tier = entry["tier"]
        ledger.record(entry["path"], "SKIPPED",
                      f"artifact {tier} — {entry['reason']} (reported without reading)")
        if tier in ("black", "red"):
            artifact_findings.append({
                "path": entry["path"], "category": "credential",
                "username": None, "secret": None,
                "note": f"artifact {tier}: {entry['reason']} — the file itself "
                        f"is a secret store; not read",
                "severity": "high" if tier == "black" else "medium"})
    unresolved = ledger.unresolved()
    if unresolved:
        say("ai", f"[ai] {share_name}: {len(unresolved)} file(s) UNRESOLVED — "
                  f"one corrective round")
        try:
            from .orchestrator import _corrective_checklist_round
            client2 = client_factory()
            listed = "\n".join(f"  {f}" for f in unresolved[:200])
            text = llm_request(
                client2, policy,
                messages + [{"role": "user", "content":
                             f"These files were never analyzed:\n{listed}\n"
                             "Output one FILE: line each."}],
                lambda l: say("ai", l), sem)
            verdicts, _ = parse_batch_response(text)
            for path in unresolved:
                verdict = verdicts.get(_norm(path))
                if verdict and verdict != "UNRESOLVED":
                    ledger.record(path, verdict, "(corrective round)")
        except Exception:  # noqa: BLE001 — ledger already marks UNRESOLVED
            say("ai", f"  ! corrective round failed — files stay UNRESOLVED")

    # ---- reduce ---------------------------------------------------------- #
    say("ai", f"[ai] {share_name}: reduce — writing share report")
    reduce_prompt = (_REDUCE_PROMPT.format(share=share_name, host=host)
                     + "\nLedger:\n" + ledger.checklist_md(
                         [f["path"] for f in walk_files])
                     + "\n\nEntity index:\n" + ledger.digest()
                     + "\n\nFindings so far (JSON):\n"
                     + json.dumps(ledger.findings, ensure_ascii=False)[:8000])
    try:
        reduce_text = llm_request(client_factory(), policy,
                                  [{"role": "user", "content": reduce_prompt}],
                                  lambda l: say("ai", l), sem)
    except Exception as exc:  # noqa: BLE001
        reduce_text = f"(reduce failed: {exc} — see ledger above)"

    report = (f"#### File checklist (code-verified, {len(ledger.verdicts)} "
              f"+ {len(ledger.unreadable)} unreadable + "
              f"{len(ledger.budget_skipped)} budget-skipped + "
              f"{len(ledger.skipped_ext)} ext-skipped)\n"
              + ledger.checklist_md([f["path"] for f in walk_files])
              + "\n\n#### Findings & summary (AI)\n" + reduce_text)

    # ---- finalize: restore + tag findings ------------------------------- #
    findings = [dict(f) for f in ledger.findings] + artifact_findings
    if masker is not None and policy.mask_restore:
        restore_findings(findings, masker)
    elif masker is not None:
        restore_findings(findings, masker, restore_values=False)
    for f in findings:
        f.setdefault("host", host)
        f["share"] = share_name
        f.setdefault("severity", "low")
        f.setdefault("category", "other")

    summary = ""
    try:
        summary = _generate_share_summary(client_factory(), policy, share_name,
                                          report, echo)
    except Exception:  # noqa: BLE001 — memory is best-effort
        summary = ledger.digest()

    stats = {"dirs_walked": walk_result.get("dirs", 0),
             "files_seen": len(walk_files) + len(ledger.skipped_ext),
             "files_dumped": len(ledger.verdicts),
             "files_artifacts": len(artifacts_found),
             "bytes_read": ledger.bytes_read, "errors": len(ledger.unreadable),
             "files_skipped_ext": len(ledger.skipped_ext)}
    say("system", f"[share] {host}/{share_name}: stream analysis done — "
                  f"{stats['files_dumped']} files "
                  f"({len(artifacts_found)} artifact(s) reported unread), "
                  f"{len(findings)} finding(s)")
    return {"report": report, "findings": findings, "memory": summary,
            "masked": sum(masker.summary().values()) if masker else 0,
            "masked_entities": masker.summary() if masker else {},
            "stats": stats, "artifacts": artifacts_found,
            "known_fps": known_fps}


def _reset_budget(policy: Policy) -> int:
    limit = policy.context_token_limit
    if limit:
        return int(limit * 3 * float(getattr(policy, "analysis_reset_ratio", 0.7)))
    return 300_000
