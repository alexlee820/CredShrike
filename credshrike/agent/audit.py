"""JSONL audit log: every agent tool call, redacted args, verdicts.

The audit trail is the evidence record for what the LLM actually did —
required reading after any agent run, and the artifact a reviewer uses to
reconstruct the run without re-executing it.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional

# keys whose values are scrubbed no matter what (defense in depth — tool args
# should never contain secrets, but redaction must not depend on that)
SENSITIVE_KEYS = {"password", "nthash", "lmhash", "aes_key", "ticket", "token",
                  "authorization", "cookie"}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<redacted>" if k.lower() in SENSITIVE_KEYS else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    @classmethod
    def new_run(cls, directory: str = "runs", suffix: str = "") -> "AuditLog":
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe = "".join(c if c.isalnum() or c in "-." else "_" for c in suffix)[:48]
        name = f"{stamp}_{safe}.jsonl" if safe else f"{stamp}.jsonl"
        return cls(os.path.join(directory, name))

    def record(self, tool: str, args: dict, verdict: str, *, result_chars: int = 0,
               duration_ms: int = 0, error: Optional[str] = None,
               redactions: Optional[int] = None) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool": tool,
            "args": redact(args),
            "verdict": verdict,       # allowed | refused | capped | flagged | error
            "result_chars": result_chars,
            "duration_ms": duration_ms,
        }
        if error:
            entry["error"] = error[:500]
        if redactions:
            entry["redactions"] = redactions
        self._fh.write(json.dumps(entry, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class CallTimer:
    """Context manager measuring a tool call; `.ms` is live (readable inside
    the with-block, e.g. when an exception path logs the duration)."""

    def __enter__(self):
        self.start = time.monotonic()
        return self

    @property
    def ms(self) -> int:
        return int((time.monotonic() - self.start) * 1000)

    def __exit__(self, *exc):
        return False
