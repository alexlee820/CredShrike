"""Structured findings extraction: turn the finished conversation into
machine-readable findings (credentials, weak ACLs, sensitive files).

Provider-portable by design: a plain messages call that asks for JSON
(fence-tolerant parsing, one retry with error feedback) instead of
Anthropic-only structured-output betas — so it works the same on the
official API and on GLM/DeepSeek Anthropic-compatible endpoints.
"""

from __future__ import annotations

import json
import re
from typing import Optional

FINDINGS_SCHEMA_HINT = """{
  "findings": [
    {"severity": "high|medium|low",
     "category": "credential|weak_acl|sensitive_file|other",
     "host": "string", "share": "string", "path": "string",
     "username": "string or null",
     "secret": "string or null",
     "evidence": "which tool call(s) showed this",
     "note": "one-line context"}
  ]
}"""

EXTRACTION_PROMPT = (
    "From the investigation above, extract EVERY finding into JSON.\n"
    "Rules:\n"
    "- Only findings backed by a tool result you saw; cite the tool call in evidence.\n"
    "- For credentials include BOTH username and secret (password/key) when present "
    "in what was read; copy values verbatim.\n"
    "- severity: high = exploitable credential/world-writable secret, "
    "medium = weak ACL on sensitive data, low = informational.\n"
    "- If nothing was found, return {\"findings\": []}.\n"
    "Respond with ONLY the JSON object matching exactly this shape, no prose, "
    "no markdown fence:\n" + FINDINGS_SCHEMA_HINT)

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)
VALID_SEVERITIES = {"high", "medium", "low"}
VALID_CATEGORIES = {"credential", "weak_acl", "sensitive_file", "other"}


def _parse_findings_json(text: str) -> dict:
    """Lenient parse: fenced block > first {...} blob; returns {"findings": [...]}"""
    candidate = None
    fence = _FENCE_RE.search(text or "")
    if fence:
        candidate = fence.group(1).strip()
    else:
        blob = _JSON_OBJ_RE.search(text or "")
        if blob:
            candidate = blob.group(0)
    if not candidate:
        raise ValueError("no JSON object found in model output")
    data = json.loads(candidate)
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError("JSON missing 'findings' key")
    if not isinstance(data["findings"], list):
        raise ValueError("'findings' is not a list")
    return data


def _sanitize(data: dict) -> list[dict]:
    out = []
    for raw in data.get("findings", []):
        if not isinstance(raw, dict):
            continue
        finding = {
            "severity": str(raw.get("severity", "low")).lower() if
                        str(raw.get("severity", "low")).lower() in VALID_SEVERITIES else "low",
            "category": str(raw.get("category", "other")).lower() if
                        str(raw.get("category", "other")).lower() in VALID_CATEGORIES else "other",
            "host": str(raw.get("host", "") or ""),
            "share": str(raw.get("share", "") or ""),
            "path": str(raw.get("path", "") or ""),
            "username": raw.get("username") or None,
            "secret": raw.get("secret") or None,
            "evidence": str(raw.get("evidence", "") or ""),
            "note": str(raw.get("note", "") or ""),
        }
        out.append(finding)
    return out


def extract_findings(client, policy, messages: list[dict]) -> list[dict]:
    """One follow-up call over the finished conversation → sanitized findings.
    Raises nothing fatal: on total failure returns [] (report still builds)."""
    prompt_messages = list(messages) + [{"role": "user", "content": EXTRACTION_PROMPT}]
    last_error: Optional[str] = None
    for attempt in range(2):
        try:
            resp = client.messages.create(
                model=policy.model,
                max_tokens=min(policy.max_tokens, 8192),
                messages=prompt_messages,
            )
            text = "".join(getattr(b, "text", "") for b in resp.content)
            return _sanitize(_parse_findings_json(text))
        except Exception as exc:  # noqa: BLE001 - parse or API error
            last_error = f"{type(exc).__name__}: {exc}"
            prompt_messages = prompt_messages + [
                {"role": "assistant", "content": "(invalid response)"},
                {"role": "user", "content": f"Your previous output failed to parse "
                                            f"({last_error[:200]}). Respond with ONLY "
                                            f"the raw JSON object, no prose, no fence."},
            ]
    raise RuntimeError(f"findings extraction failed after retry: {last_error}")
