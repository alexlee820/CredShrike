"""Tool executor: the safety layer between the LLM and the network.

Every tool_use block from the model passes through :meth:`ToolExecutor.execute`
which, in order:

1. allowlist check — the tool name must exist in the registry (read-only by
   construction; unknown tools are refused and logged, never guessed);
2. scope check — host arguments must be within the session's allowed hosts;
3. path normalization — backslash/UTF tricks collapsed, `..` segments rejected;
4. cap clamping — max_bytes/max_entries forced to the policy ceiling;
5. budget check — per-run tool-call / byte / wall-clock budgets;
6. execution — the handler runs, exceptions become is_error tool results
   (they must never crash the loop);
7. result truncation to the policy char cap with an explicit paging marker;
8. audit record — verdict allowed|refused|capped|error, redacted args.

The executor is deliberately boring: no dynamic dispatch by string beyond the
registry lookup, no eval, no shell.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..config import Policy
from .audit import AuditLog, CallTimer
from .session import AgentSession
from .tools import REGISTRY

_TRAVERSAL = re.compile(r"(^|[\\/])\.\.?([\\/]|$)")


class Refused(Exception):
    """Raised internally for guard violations; converted to tool_result."""


def normalize_path(path: str) -> str:
    """Accept '/' or '\\' separated paths, reject traversal segments."""
    p = (path or "").replace("\\", "/").strip()
    p = re.sub(r"/+", "/", p).strip("/")
    if not p or p == ".":
        return ""
    if _TRAVERSAL.search("/" + p + "/"):
        raise Refused(f"path traversal rejected: {path!r}")
    return p


class ToolExecutor:
    def __init__(self, session: AgentSession, policy: Policy, audit: AuditLog):
        self.session = session
        self.policy = policy
        self.audit = audit

    # ------------------------------------------------------------------ #
    def execute(self, tool_name: str, raw_args: dict) -> dict:
        """Run one tool call; returns an Anthropic tool_result content block
        body: {"content": str, "is_error": bool}."""
        with CallTimer() as timer:
            try:
                result, verdict = self._guarded(tool_name, raw_args)
            except Refused as exc:
                self.audit.record(tool_name, raw_args, "refused", error=str(exc),
                                  duration_ms=timer.ms)
                return {"content": f"REFUSED: {exc}", "is_error": True}
            except Exception as exc:  # noqa: BLE001 - handler errors must not kill the loop
                self.audit.record(tool_name, raw_args, "error", error=f"{type(exc).__name__}: {exc}",
                                  duration_ms=timer.ms)
                return {"content": f"ERROR: {type(exc).__name__}: {exc}", "is_error": True}
        content, capped = self._render(result)
        self.audit.record(tool_name, raw_args, verdict if not capped else "capped",
                          result_chars=len(content), duration_ms=timer.ms)
        return {"content": content, "is_error": False}

    # ------------------------------------------------------------------ #
    def _guarded(self, tool_name: str, raw_args: dict):
        """Guards 1–5; returns (result, verdict)."""
        tool = REGISTRY.get(tool_name)
        if tool is None:
            raise Refused(f"'{tool_name}' is not in the read-only tool registry")

        args = dict(raw_args or {})
        # strict schema validation is done API-side; we still coerce defensively
        if not isinstance(args, dict):
            raise Refused("arguments must be an object")

        # budget
        if self.session.budget.exhausted:
            raise Refused(f"budget exhausted: {self.session.budget.why()}")

        # scope + normalization
        if "host" in args:
            host = str(args["host"])
            if not self.session.host_allowed(host):
                raise Refused(f"host '{host}' outside session scope")
        if "share" in args:
            args["share"] = str(args["share"]).strip("\\/ ").replace("\\", "")
        if "path" in args:
            args["path"] = normalize_path(str(args["path"]))

        # caps
        capped = False
        if "max_bytes" in args:
            want = int(args["max_bytes"])
            if want > self.policy.max_file_bytes:
                want, capped = self.policy.max_file_bytes, True
            args["max_bytes"] = max(1, want)
        if "max_entries" in args:
            want = int(args["max_entries"])
            if want > self.policy.max_entries:
                want, capped = self.policy.max_entries, True
            args["max_entries"] = max(1, want)

        self.session.budget.tool_calls += 1
        result = tool.handler(self.session, args)

        # count bytes toward the budget for reads
        if tool_name == "smb_read_file" and isinstance(result, dict):
            self.session.budget.bytes_read += int(result.get("size", 0))

        return result, "capped" if capped else "allowed"

    # ------------------------------------------------------------------ #
    def _render(self, result: Any) -> tuple[str, bool]:
        """Serialize + truncate to the policy char cap with a paging marker."""
        try:
            text = json.dumps(result, default=str)
        except Exception:  # noqa: BLE001
            text = str(result)
        cap = self.policy.result_char_cap
        if len(text) <= cap:
            return text, False
        marker = (f"…[TRUNCATED at {cap} chars of {len(text)} — page through with "
                  f"offset/max_entries/max_bytes or narrow the query]")
        return text[:cap] + marker, True
