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
    source = ctx.directory(args.get("source", "auto"))
    return {"source": source.name,
            "computers": [c.to_dict() for c in
                          source.list_computers(args.get("filter", "") or "")]}


def _smb_list_shares(ctx: AgentSession, args: dict) -> Any:
    return {"host": args["host"], "shares": ctx.smb(args["host"]).list_shares()}


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


# --------------------------------------------------------------------------- #
REGISTRY: dict[str, Tool] = {t.name: t for t in [
    Tool(
        name="domain_list_computers",
        description=("List Active Directory computer objects. Use this first when the task "
                     "involves finding hosts (e.g. file servers) before touching SMB."),
        schema=_obj({
            "source": {"type": "string", "enum": ["auto", "ldap", "adws"],
                       "description": "transport; auto=LDAP (default), adws=SOAP port 9389"},
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
]}


def anthropic_tools() -> list[dict]:
    return [t.anthropic_spec() for t in REGISTRY.values()]
