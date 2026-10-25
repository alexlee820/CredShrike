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

import base64
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
        self._regex_cache: list | None = None

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
        result, redactions, masked = self._sanitize_result(result)
        if redactions:
            self.session.redactions_applied += redactions
        if masked:
            self.session.masked_values += masked
        tool = REGISTRY.get(tool_name)
        char_cap = getattr(tool, "char_cap", None) if tool else None
        content, capped = self._render(result, cap=char_cap)
        if redactions:
            # appended AFTER truncation so the note always survives
            content += f"\n[+{redactions} redaction(s) applied per session policy]"
        if masked:
            content += (f"\n[+{masked} value(s) replaced with privacy placeholders "
                        f"per masking policy — they are restored in your output]")
        if self.policy.debug:
            # keep the exact rendered result the model received
            if len(self.session.debug_results) < 300:
                self.session.debug_results.append(
                    {"tool": tool_name, "args": raw_args, "chars": len(content),
                     "content": content})
        self.audit.record(tool_name, raw_args, verdict if not capped else "capped",
                          result_chars=len(content), duration_ms=timer.ms,
                          redactions=redactions or None)
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

        # read gate: flag-but-don't-read for smb_read_file
        if tool_name == "smb_read_file":
            gate = self._read_gate(args)
            if gate is not None:
                return gate, "flagged"

        result = tool.handler(self.session, args)

        # count bytes toward the budget for reads
        if tool_name == "smb_read_file" and isinstance(result, dict):
            self.session.budget.bytes_read += int(result.get("size", 0))

        return result, "capped" if capped else "allowed"

    # ------------------------------------------------------------------ #
    def _read_gate(self, args: dict):
        """Read-gate check for smb_read_file (policy.read_gate).

        Returns a flagged tool-result dict when the read must NOT execute,
        or None to proceed with the read. Two modes:

        - ``ai``: the model picked the file; the gate only fires when the
          REQUESTED byte range's estimated token count exceeds
          ``max_read_tokens`` (estimate = bytes / chars_per_token).
        - ``size``: the file's actual size (via smb_stat) is compared to
          ``flag_oversize_bytes``; oversized files are never read.
        """
        gate = self.policy.read_gate
        if gate not in ("ai", "size"):
            return None
        host, share, path = str(args["host"]), str(args["share"]), str(args["path"])

        if gate == "ai":
            requested = int(args.get("max_bytes", 65536))
            estimated = int(requested / max(self.policy.chars_per_token, 0.1))
            if estimated <= self.policy.max_read_tokens:
                return None
            entry = self.session.flag_file(
                host, share, path,
                reason=(f"token gate: ~{estimated} estimated tokens for "
                        f"{requested} requested bytes exceeds max_read_tokens="
                        f"{self.policy.max_read_tokens}"))
            entry["requested_bytes"] = requested
            entry["estimated_tokens"] = estimated
        else:  # size
            stat = self.session.smb(host).stat(share, path)
            size = int(stat.get("size", 0))
            if size <= self.policy.flag_oversize_bytes:
                return None
            entry = self.session.flag_file(
                host, share, path, size_bytes=size,
                reason=(f"size gate: {size} bytes exceeds flag_oversize_bytes="
                        f"{self.policy.flag_oversize_bytes}"))

        # the tool result the model sees instead of content
        entry["flagged"] = True
        entry["instruction"] = ("This file was NOT read (gate policy). Do not retry "
                                "the read. Record it in your final report as a "
                                "flagged-not-read file, including size if known.")
        return entry

    # ------------------------------------------------------------------ #
    # redaction: scrub tool results BEFORE they reach the LLM
    # ------------------------------------------------------------------ #
    def _compiled_patterns(self) -> list:
        if self._regex_cache is None:
            self._regex_cache = [re.compile(p) for p in self.policy.redact_patterns]
        return self._regex_cache

    def _redact_text(self, text: str) -> tuple[str, int]:
        """Apply literal + regex redaction rules; returns (text, hits)."""
        count = 0
        replacement = self.policy.redact_replacement
        for literal in self.policy.redact_literals:
            if literal and literal in text:
                count += text.count(literal)
                text = text.replace(literal, replacement)
        for rx in self._compiled_patterns():
            def _sub(match, _rep=replacement):
                nonlocal count
                count += 1
                if match.groups():
                    # group-aware: keep context (e.g. 'password='), mask the value
                    return match.group(0).replace(match.group(1), _rep)
                return _rep
            text = rx.sub(_sub, text)
        return text, count

    def _sanitize_text(self, text: str) -> tuple[str, int, int]:
        """Redaction first (operator rules win), then privacy masking.
        Returns (text, redactions, masked)."""
        text, redactions = self._redact_text(text)
        masked = 0
        if self.session.masker is not None:
            text, masked = self.session.masker.mask_text(text)
        return text, redactions, masked

    def _sanitize_result(self, obj: Any) -> tuple[Any, int, int]:
        """Recursively scrub every string in a tool result. File contents
        travel base64-encoded, so ``content_b64`` fields are decoded,
        scrubbed, and re-encoded — plaintext rules still apply to them."""
        if isinstance(obj, dict):
            out, redactions, masked = {}, 0, 0
            for key, value in obj.items():
                if key == "content_b64" and isinstance(value, str):
                    try:
                        decoded = base64.b64decode(value).decode("utf-8", errors="replace")
                        scrubbed, hits, masked_hits = self._sanitize_text(decoded)
                        if hits or masked_hits:
                            out[key] = base64.b64encode(
                                scrubbed.encode("utf-8")).decode("ascii")
                            redactions += hits
                            masked += masked_hits
                            continue
                    except Exception:  # noqa: BLE001 - not b64/text: leave as-is
                        pass
                new_value, hits, masked_hits = self._sanitize_result(value)
                out[key] = new_value
                redactions += hits
                masked += masked_hits
            return out, redactions, masked
        if isinstance(obj, list):
            out, redactions, masked = [], 0, 0
            for value in obj:
                new_value, hits, masked_hits = self._sanitize_result(value)
                out.append(new_value)
                redactions += hits
                masked += masked_hits
            return out, redactions, masked
        if isinstance(obj, str):
            return self._sanitize_text(obj)
        return obj, 0, 0

    # ------------------------------------------------------------------ #
    def _render(self, result: Any, cap: int | None = None) -> tuple[str, bool]:
        """Serialize + truncate (per-tool override > policy cap) with a
        paging marker."""
        try:
            text = json.dumps(result, default=str)
        except Exception:  # noqa: BLE001
            text = str(result)
        limit = cap or self.policy.result_char_cap
        if len(text) <= limit:
            return text, False
        marker = (f"…[TRUNCATED at {limit} chars of {len(text)} — page through with "
                  f"offset/max_entries/max_bytes/skip or narrow the query]")
        return text[:limit] + marker, True
