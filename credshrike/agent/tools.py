"""Read-only tool registry exposed to the LLM.

This file is the complete capability surface of the agent. There is no
write/delete/rename/execute handler anywhere — that is the enforcement
mechanism, not a prompt instruction. Adding a tool here is a code-review
event, not a config change.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .session import AgentSession


@dataclass
class Tool:
    name: str
    description: str
    schema: dict
    handler: Callable[[AgentSession, dict], Any]
    # optional per-tool override of the executor's result_char_cap — used by
    # smb_dump_share whose pages are intentionally larger than the default
    char_cap: int | None = None

    def anthropic_spec(self) -> dict:
        return {"name": self.name, "description": self.description,
                "input_schema": self.schema, "strict": True}


def _obj(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


# --------------------------------------------------------------------------- #
# handlers (thin wrappers over the core library; caps applied by the executor)
# --------------------------------------------------------------------------- #
def _domain_list_computers(ctx: AgentSession, args: dict) -> Any:
    # model's per-call choice wins; otherwise the session-level config
    # (CLI --source / web UI dropdown) is the default
    chosen = args.get("source") or ctx.domain_source or "auto"
    source = ctx.directory(chosen)
    ctx.emit("transport", {"query": "domain computers",
                           "using": source.name,
                           "requested": chosen})
    computers = [c.to_dict() for c in source.list_computers(args.get("filter", "") or "")]
    # harness-side inventory for the HTML report (dedupe by sam/dns/cn)
    seen = {c.get("sam_account") or c.get("dns_name") or c.get("cn")
            for c in ctx.domain_computers}
    for c in computers:
        key = c.get("sam_account") or c.get("dns_name") or c.get("cn")
        if key not in seen:
            ctx.domain_computers.append(c)
            seen.add(key)
    return {"source": source.name, "computers": computers}


def _smb_list_shares(ctx: AgentSession, args: dict) -> Any:
    shares = ctx.smb(args["host"]).list_shares()
    ctx.share_inventories[args["host"]] = shares   # harness-side for the report
    return {"host": args["host"], "shares": shares}


def _smb_list_dir(ctx: AgentSession, args: dict) -> Any:
    return ctx.smb(args["host"]).list_dir(args["share"], args.get("path", ""),
                                          max_entries=args.get("max_entries", 200))


def _smb_read_file(ctx: AgentSession, args: dict) -> Any:
    return ctx.smb(args["host"]).read_file(
        args["share"], args["path"], offset=args.get("offset", 0),
        max_bytes=args.get("max_bytes", 65536))


def _smb_stat(ctx: AgentSession, args: dict) -> Any:
    return ctx.smb(args["host"]).stat(args["share"], args["path"])


def _smb_get_permissions(ctx: AgentSession, args: dict) -> Any:
    session = ctx.smb(args["host"])
    result: dict = {"host": args["host"], "share": args["share"]}
    path = args.get("path", "")
    if path:
        result["path"] = path
        result["sd"] = session.get_security(args["share"], path)
        if args.get("probe", False):
            result["effective_probes"] = session.effective_access(args["share"], path)
    else:
        result["share_acl"] = session.get_share_security(args["share"])
    return result


def _sid_lookup(ctx: AgentSession, args: dict) -> Any:
    sids = args.get("sids", [])
    resolver = ctx.any_smb_resolver()  # LSA-capable if a session exists
    return {"names": resolver.resolve_many(sids)}


def _smb_scan_share(ctx: AgentSession, args: dict) -> Any:
    """Snaffler-style sweep with PARALLEL walk + PARALLEL reads.
    Uses the session's connection pool for concurrent SMB I/O."""
    from ..patterns import compile_patterns, classify_file
    from .orchestrator import _walk_share_files, DEFAULT_SKIP_EXTENSIONS
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from .scanner import _find_matches, mask_line

    host = args["host"]
    share = args["share"]
    session = ctx.smb(host)
    patterns = compile_patterns(extra=ctx.policy.scan_extra_patterns,
                                use_defaults=ctx.policy.scan_use_default_patterns)
    skip_exts = set(ctx.policy.dump_skip_exts)

    # Phase 1: parallel walk (same infra as orchestrator)
    pool = ctx.get_read_pool(host)
    file_list, dirs_walked, skipped_ext = _walk_share_files(
        session, share, int(args.get("depth", ctx.policy.scan_depth)),
        int(args.get("max_files", ctx.policy.scan_max_files)),
        ctx.emit, skip_exts=skip_exts,
        conn_pool=pool, walk_threads=ctx.read_threads)

    # Phase 2: filter by tier (red/yellow) then parallel-read + regex
    tiers = tuple(args.get("tiers", ctx.policy.scan_tiers))
    candidates = []
    stats = {"dirs_walked": dirs_walked, "files_seen": len(file_list),
             "files_scanned": 0, "files_skipped_notier": 0,
             "bytes_scanned": 0, "scan_errors": 0, "files_skipped_ext": len(skipped_ext)}

    for f in file_list:
        tier = classify_file(f["path"].rsplit("/", 1)[-1], tiers)
        if tier is None:
            stats["files_skipped_notier"] += 1
        else:
            candidates.append({"path": f["path"], "size": f["size"], "tier": tier})

    matches = []
    per_file = int(ctx.policy.scan_max_file_bytes)

    def _scan_one(f):
        reader = pool.get(timeout=30)
        try:
            read = reader.read_file(share, f["path"], max_bytes=per_file)
            import base64 as _b64
            data = _b64.b64decode(read.get("content_b64", ""))
            return f["path"], f["tier"], data, None
        except Exception as exc:
            return f["path"], f["tier"], None, str(exc)[:60]
        finally:
            pool.put(reader)

    with ThreadPoolExecutor(max_workers=max(1, ctx.read_threads)) as executor:
        futures = {executor.submit(_scan_one, f): f for f in candidates}
        for future in as_completed(futures):
            path, tier, data, err = future.result()
            if err:
                stats["scan_errors"] += 1
                continue
            stats["files_scanned"] += 1
            stats["bytes_scanned"] += len(data)
            ctx.budget.bytes_read += len(data)
            text = data.decode("utf-8", errors="replace")
            for line_no, line_text, pattern_name, g_start, g_end in _find_matches(text, patterns):
                matches.append({"path": path, "tier": tier, "line": line_no,
                                "pattern": pattern_name,
                                "snippet": mask_line(line_text.strip(), g_start, g_end)[:300]})

    # page the results
    skip = int(args.get("skip_matches", 0))
    page = matches[skip: skip + 50]
    result = {
        "share": share, "root": args.get("path", ""),
        "matches": page, "matches_skip": skip, "matches_total": len(matches),
        "next_skip": (skip + len(page)) if skip + len(page) < len(matches) else None,
        "stats": stats,
        "patterns_used": [p["name"] for p in patterns],
    }
    ctx.scan_results.append(result)
    return result


def _smb_dump_share(ctx: AgentSession, args: dict) -> Any:
    """Full-content dump with parallel reads + skip extensions (same infra as orchestrator)."""
    from .orchestrator import _dump_single_share

    host = args["host"]
    ctx.share_inventories[host] = ctx.smb(host).list_shares()
    dump_text, stats, file_paths, skipped = _dump_single_share(
        ctx, host, args["share"], ctx.policy,
        ctx.emit, read_threads=ctx.read_threads)
    ctx.budget.bytes_read += int(stats.get("bytes_read", 0))

    return {"share": args["share"], "files": file_paths,
            "files_total": len(file_paths), "skipped_ext": len(skipped),
            "stats": stats, "dump_text": dump_text[:8000],
            "next_skip": None}


# --------------------------------------------------------------------------- #
REGISTRY: dict[str, Tool] = {t.name: t for t in [
    Tool(
        name="domain_list_computers",
        description=("List Active Directory computer objects. Use this first when the task "
                     "involves finding hosts (e.g. file servers) before touching SMB."),
        schema=_obj({
            "source": {"type": "string", "enum": ["auto", "ldap", "adws"],
                       "description": "transport; omit to use the session default "
                                      "(auto/ldap = LDAP 389, adws = WCF net.tcp 9389)"},
            "filter": {"type": "string",
                       "description": "extra LDAP filter ANDed with (objectClass=computer), "
                                      "e.g. '(operatingSystem=*Server*)'"},
        }, []),
        handler=_domain_list_computers,
    ),
    Tool(
        name="smb_list_shares",
        description="List the SMB shares on a host, with share types and remarks.",
        schema=_obj({"host": {"type": "string"}}, ["host"]),
        handler=_smb_list_shares,
    ),
    Tool(
        name="smb_list_dir",
        description=("List a directory inside an SMB share. Path is relative to the share root "
                     "('' or '.' = root). Results are capped; if 'truncated' is true, narrow "
                     "the path or page by subdirectory."),
        schema=_obj({
            "host": {"type": "string"},
            "share": {"type": "string"},
            "path": {"type": "string", "description": "e.g. 'IT/Reports'; empty = share root"},
            "max_entries": {"type": "integer", "minimum": 1},
        }, ["host", "share", "path"]),
        handler=_smb_list_dir,
    ),
    Tool(
        name="smb_read_file",
        description=("Read bytes from a file over SMB. Content is base64. Reads are size-capped; "
                     "use offset/max_bytes to page through larger files. Only read files that "
                     "plausibly help the task (configs, scripts, notes) — not bulk binary data."),
        schema=_obj({
            "host": {"type": "string"},
            "share": {"type": "string"},
            "path": {"type": "string"},
            "offset": {"type": "integer", "minimum": 0},
            "max_bytes": {"type": "integer", "minimum": 1},
        }, ["host", "share", "path"]),
        handler=_smb_read_file,
    ),
    Tool(
        name="smb_stat",
        description="Metadata (size, timestamps, attributes) for one file or directory.",
        schema=_obj({
            "host": {"type": "string"},
            "share": {"type": "string"},
            "path": {"type": "string"},
        }, ["host", "share", "path"]),
        handler=_smb_stat,
    ),
    Tool(
        name="smb_get_permissions",
        description=("Permissions for a path or a whole share: parsed owner/group/DACL ACEs "
                     "(trustee names, allow/deny, rights) and, with probe=true, effective-access "
                     "probes showing what the current credential can actually do."),
        schema=_obj({
            "host": {"type": "string"},
            "share": {"type": "string"},
            "path": {"type": "string", "description": "omit for share-level ACL"},
            "probe": {"type": "boolean", "description": "run effective-access open probes"},
        }, ["host", "share"]),
        handler=_smb_get_permissions,
    ),
    Tool(
        name="sid_lookup",
        description="Resolve SIDs to principal names (well-known + directory).",
        schema=_obj({"sids": {"type": "array", "items": {"type": "string"}}}, ["sids"]),
        handler=_sid_lookup,
    ),
    Tool(
        name="smb_scan_share",
        description=("Deterministic credential sweep of one share (snaffler-style). Walks "
                     "directories, triages files into red/yellow tiers, reads candidates "
                     "and regex-scans content; returns matches with the SECRET MASKED plus "
                     "coverage stats. Use this FIRST for 'find passwords/credentials' tasks. "
                     "HITS ARE PAGED: while 'next_skip' is set, call again with "
                     "skip_matches=next_skip until null so you see EVERY hit. "
                     "data_files lists every CSV/TSV/JSON opened — regex CANNOT judge "
                     "structured data (a 'user,pass' row has no keyword), so READ each "
                     "data_files entry with smb_read_file and extract any credential "
                     "pairs yourself. Judge every hit too (true/false positive via "
                     "smb_read_file around it, exposure via smb_get_permissions). "
                     "'truncated' means the sweep was cut short (max_files/bytes)."),
        schema=_obj({
            "host": {"type": "string"},
            "share": {"type": "string"},
            "path": {"type": "string", "description": "start directory (default: share root)"},
            "depth": {"type": "integer", "minimum": 1, "maximum": 6},
            "max_files": {"type": "integer", "minimum": 1},
            "tiers": {"type": "array", "items": {"enum": ["red", "yellow"]},
                      "description": "which triage tiers to open (default: both)"},
            "skip_matches": {"type": "integer", "minimum": 0,
                             "description": "paging: fetch hits after this index "
                                            "(use next_skip from the previous result)"},
        }, ["host", "share"]),
        handler=_smb_scan_share,
    ),
    Tool(
        name="smb_dump_share",
        description=("FULL-CONTENT review: dumps EVERY file in a share — any "
                     "extension, no filtering — as decoded text (each file's "
                     "first ~16KB). This is the tool for 'review/read everything' "
                     "tasks where nothing should be pre-filtered. Results are "
                     "PAGED by size: while 'next_skip' is set, call again with "
                     "skip_files=next_skip until null so you see EVERY file. "
                     "'head_truncated' on an entry means the file is longer than "
                     "the per-file head — page into it with smb_read_file+offset "
                     "if its content looks interesting."),
        schema=_obj({
            "host": {"type": "string"},
            "share": {"type": "string"},
            "path": {"type": "string", "description": "start directory (default: share root)"},
            "depth": {"type": "integer", "minimum": 1, "maximum": 8},
            "max_files": {"type": "integer", "minimum": 1},
            "skip_files": {"type": "integer", "minimum": 0,
                           "description": "paging: skip this many dumped files "
                                          "(use next_skip from the previous result)"},
        }, ["host", "share"]),
        handler=_smb_dump_share,
        # dump pages are intentionally larger than the default 8K result cap
        char_cap=40000,
    ),
]}


def anthropic_tools() -> list[dict]:
    return [t.anthropic_spec() for t in REGISTRY.values()]
