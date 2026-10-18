"""Snaffler-style deterministic share sweep: walk, triage, read, regex.

This is the coverage half of the hybrid scan mode — every decision here is
deterministic (tier rules + regex), so the sweep's coverage is claimable.
The LLM's job (via the smb_scan_share tool) is the judgment half: classify
each hit true/false positive and assess impact.

Everything flows through the same SMBSession read-only surface, respects the
byte budget, and emits progress events for the UI/echo (session.emit).
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

from .patterns import classify_file, compile_patterns

LOG = logging.getLogger(__name__)

# paging: a page of hits must fit inside the executor's result_char_cap
# (~50 masked snippets ≈ 7K chars); the sweep itself may collect far more
MAX_MATCHES_RETURNED = 50     # hits per result page
MAX_MATCHES_COLLECTED = 1000  # hard collection ceiling per sweep


def mask_line(line: str, group_start: int, group_end: int, mask: str = "***") -> str:
    """Replace [group_start:group_end] (offsets into the ORIGINAL line) with
    the mask, keeping surrounding context visible."""
    if group_start < 0 or group_end <= group_start:
        return line
    return line[:group_start] + mask + line[group_end:]


def scan_share(session, share: str, path: str = "", *, depth: int = 3,
               max_files: int = 200, max_file_bytes: int = 65536,
               max_total_bytes: int = 5 * 1024 * 1024,
               tiers=("red", "yellow"), patterns: Optional[list] = None,
               on_event: Optional[Callable] = None,
               skip_matches: int = 0, max_matches_returned: int = MAX_MATCHES_RETURNED) -> dict:
    """Sweep one share (rooted at ``path``) for credential patterns.

    ``session`` is an SMBSession (read-only). ``patterns`` comes from
    :func:`patterns.compile_patterns`. Returns a result dict with matches
    (secret values masked) + coverage stats; ``skip_matches`` pages through
    the hit list when there are more than MAX_MATCHES_RETURNED (the result
    carries ``next_skip`` while more remain). Raises nothing for SMB errors
    on individual files — they are recorded as scan_errors.
    """
    emit = on_event or (lambda kind, data: None)
    compiled = patterns if patterns is not None else compile_patterns()
    stats = {"dirs_walked": 0, "files_seen": 0, "files_scanned": 0,
             "files_skipped_notier": 0, "bytes_scanned": 0, "scan_errors": 0}
    matches: list[dict] = []
    truncated = False
    stop_reason = None

    queue: list[tuple[str, int]] = [((path or "").strip("/"), 0)]
    seen_dirs: set[str] = set()

    while queue:
        current, level = queue.pop(0)
        if current in seen_dirs:
            continue
        seen_dirs.add(current)
        stats["dirs_walked"] += 1
        emit("walk", {"path": current or "/", "depth": level})
        try:
            listing = session.list_dir(share, current, max_entries=1000)
        except Exception as exc:  # noqa: BLE001 — one bad dir must not stop the sweep
            stats["scan_errors"] += 1
            emit("walk_error", {"path": current, "error": str(exc)[:120]})
            continue

        for entry in listing.get("entries", []):
            name = entry.get("name", "")
            if name in (".", ".."):
                continue  # pseudo-entries — descending into them produces
                # paths like 'a/./../..' which the server rejects
            stats["files_seen"] += 1
            child = f"{current}/{name}" if current else name
            if entry.get("is_dir"):
                if level < depth:
                    queue.append((child, level + 1))
                continue
            if stats["files_scanned"] >= max_files:
                truncated, stop_reason = True, f"max_files={max_files} reached"
                queue.clear()
                break
            tier = classify_file(name, tiers)
            if tier is None:
                stats["files_skipped_notier"] += 1
                continue
            if stats["bytes_scanned"] >= max_total_bytes:
                truncated, stop_reason = True, f"max_total_bytes={max_total_bytes} reached"
                queue.clear()
                break
            if len(matches) >= MAX_MATCHES_COLLECTED:  # hard cap on collected hits
                truncated, stop_reason = True, "match cap reached"
                queue.clear()
                break

            try:
                read = session.read_file(share, child, max_bytes=max_file_bytes)
            except Exception as exc:  # noqa: BLE001
                stats["scan_errors"] += 1
                emit("read_error", {"path": child, "error": str(exc)[:120]})
                continue
            import base64
            data = base64.b64decode(read.get("content_b64", ""))
            stats["files_scanned"] += 1
            stats["bytes_scanned"] += len(data)
            emit("scan", {"path": child, "tier": tier, "size": len(data)})

            text = data.decode("utf-8", errors="replace")
            hits = _find_matches(text, compiled)
            for line_no, line_text, pattern_name, g_start, g_end in hits:
                snippet = mask_line(line_text.strip(), g_start, g_end)
                matches.append({"path": child, "tier": tier, "line": line_no,
                                "pattern": pattern_name, "snippet": snippet[:300]})
                emit("hit", {"path": child, "pattern": pattern_name})
            if hits:
                emit("file_hit", {"path": child, "hits": len(hits), "tier": tier})

    total = len(matches)
    page = matches[skip_matches: skip_matches + max_matches_returned]
    result = {
        "share": share, "root": path or "", "tiers": list(tiers),
        "matches": page,
        "matches_skip": skip_matches,
        "matches_total": total,
        # paging handle for the model: while set, more hits remain — call
        # again with skip_matches = next_skip to get the next page
        "next_skip": (skip_matches + len(page)) if skip_matches + len(page) < total else None,
        "truncated": truncated, "stop_reason": stop_reason,
        "stats": stats,
        "patterns_used": [p["name"] for p in compiled],
    }
    emit("done", {k: result[k] for k in ("matches_total", "truncated", "stop_reason", "stats")})
    return result


def _find_matches(text: str, compiled: list[dict]) -> list[tuple]:
    """Yield (line_no, line_text, pattern_name, group_start, group_end) for
    every regex hit. Group offsets are translated to be relative to the
    containing LINE so masking stays aligned."""
    out = []
    for entry in compiled:
        for m in entry["compiled"].finditer(text):
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            line_no = text.count("\n", 0, m.start()) + 1
            line_text = text[line_start:line_end]
            g_start = g_end = -1
            if m.groups() and m.group(1) is not None:
                gs, ge = m.span(1)
                g_start = gs - line_start
                g_end = ge - line_start
                if g_start < 0 or g_end > len(line_text):  # secret spans lines: mask all
                    g_start, g_end = 0, len(line_text)
            out.append((line_no, line_text, entry["name"], g_start, g_end))
    out.sort(key=lambda t: t[0])
    return out
