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
     "category": "credential|pii|financial|network_info|weak_acl|sensitive_file|other",
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
    "- COUNT the findings in the final report FIRST; the JSON must contain "
    "exactly that many entries — one per credential, NEVER fewer.\n"
    "- Include command-line credentials too (e.g. 'net use \\\\srv\\share "
    "/user:DOMAIN\\\\user password') — each user/secret pair is its own entry.\n"
    "- Only findings backed by a tool result you saw; cite the tool call in evidence.\n"
    "- For credentials include BOTH username and secret (password/key) when present "
    "in what was read; copy values verbatim.\n"
    "- Categories: credential (user/pass/key/token), pii (names/emails/IDs/"
    "HR/health), financial (bank cards/invoices/budgets/payroll), "
    "network_info (IPs/hostnames/diagrams/VPN/DNS/inventory), "
    "sensitive_file, other.\n"
    "- severity: high = exploitable credential, "
    "medium = PII/financial/internal-network exposure, low = informational.\n"
    "- If nothing was found, return {\"findings\": []}.\n"
    "Respond with ONLY the JSON object matching exactly this shape, no prose, "
    "no markdown fence:\n" + FINDINGS_SCHEMA_HINT)

# DOMAIN\user tokens in the final report = what the extraction MUST cover
_DOMAIN_USER_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_.-]{1,30})\\([A-Za-z][A-Za-z0-9_.$-]{1,30})\b")
_PLACEHOLDER_USERNAMES = {"", "—", "-", "none", "null", "n/a", "user", "username"}
_SEV_ORDER = {"high": 3, "medium": 2, "low": 1}

_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)
_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)
VALID_SEVERITIES = {"high", "medium", "low"}
VALID_CATEGORIES = {"credential", "pii", "financial", "network_info",
                     "weak_acl", "sensitive_file", "other"}


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
        username = str(raw.get("username") or "").strip()
        if username.lower() in _PLACEHOLDER_USERNAMES or "�" in username:
            username = None
        finding = {
            "severity": str(raw.get("severity", "low")).lower() if
                        str(raw.get("severity", "low")).lower() in VALID_SEVERITIES else "low",
            "category": str(raw.get("category", "other")).lower() if
                        str(raw.get("category", "other")).lower() in VALID_CATEGORIES else "other",
            "host": str(raw.get("host", "") or ""),
            "share": str(raw.get("share", "") or ""),
            "path": str(raw.get("path", "") or ""),
            "username": username,
            "secret": raw.get("secret") or None,
            "evidence": str(raw.get("evidence", "") or ""),
            "note": str(raw.get("note", "") or ""),
        }
        out.append(finding)
    return out


def _expected_usernames(messages: list[dict]) -> set[str]:
    """DOMAIN\\user tokens from the FINAL assistant report — the extraction
    must account for every one of these (completeness cross-check)."""
    expected: set[str] = set()
    for message in reversed(messages):
        if message.get("role") != "assistant":
            break
        content = message.get("content")
        text = ""
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = " ".join(getattr(b, "text", "") for b in content)
        for _domain, user in _DOMAIN_USER_RE.findall(text):
            if user.lower() not in _PLACEHOLDER_USERNAMES:
                expected.add(user.lower())
        break   # only the final report
    return expected


def _extraction_call(client, policy, messages: list[dict]) -> tuple[list[dict], str]:
    """One extraction pass with a parse-retry. Returns (findings, raw_text)."""
    prompt_messages = list(messages) + [{"role": "user", "content": EXTRACTION_PROMPT}]
    last_error: Optional[str] = None
    for attempt in range(2):
        try:
            resp = client.messages.create(
                model=policy.model,
                max_tokens=min(policy.max_tokens, 16384),
                messages=prompt_messages,
            )
            text = "".join(getattr(b, "text", "") for b in resp.content)
            return _sanitize(_parse_findings_json(text)), text
        except Exception as exc:  # noqa: BLE001 - parse or API error
            last_error = f"{type(exc).__name__}: {exc}"
            prompt_messages = prompt_messages + [
                {"role": "assistant", "content": "(invalid response)"},
                {"role": "user", "content": f"Your previous output failed to parse "
                                            f"({last_error[:200]}). Respond with ONLY "
                                            f"the raw JSON object, no prose, no fence."},
            ]
    raise RuntimeError(f"extraction call failed: {last_error}")


def _merge_passes(passes: list[list[dict]]) -> list[dict]:
    """Union of two independent extraction passes, deduplicated:
    credentials by (username, secret) — severity takes the max, evidence
    joined; everything else by (category, host, share, path)."""
    out: dict[tuple, dict] = {}
    for findings in passes:
        for f in findings:
            if f["category"] == "credential" and (f.get("username") or f.get("secret")):
                key = ("cred", (f.get("username") or "").lower(), f.get("secret") or "")
            else:
                key = ("other", f["category"], f.get("host"), f.get("share"), f.get("path"))
            if key in out:
                merged = out[key]
                if _SEV_ORDER.get(f["severity"], 0) > _SEV_ORDER.get(merged["severity"], 0):
                    merged["severity"] = f["severity"]
                if f.get("evidence") and f["evidence"] not in merged.get("evidence", ""):
                    merged["evidence"] = (merged.get("evidence", "") + "; " + f["evidence"])[:400]
                for field in ("note", "share", "path"):
                    if not merged.get(field) and f.get(field):
                        merged[field] = f[field]
            else:
                out[key] = dict(f)
    return list(out.values())


def extract_findings(client, policy, messages: list[dict]) -> list[dict]:
    """Robust extraction: TWO independent LLM passes unioned (each pass can
    randomly omit items — the union catches what either missed), then the
    regex cross-check against the final report's DOMAIN\\user tokens; any
    account still missing after the union triggers ONE corrective round."""
    passes: list[list[dict]] = []
    texts: list[str] = []
    errors: list[str] = []
    for _ in range(2):
        try:
            findings, text = _extraction_call(client, policy, messages)
            passes.append(findings)
            texts.append(text)
        except Exception as exc:  # noqa: BLE001 - one pass failing is survivable
            errors.append(str(exc))
    if not passes:
        raise RuntimeError(f"both extraction passes failed: {' | '.join(errors)}")
    findings = _merge_passes(passes)

    missing = _expected_usernames(messages) - {
        (f.get("username") or "").split("\\")[-1].lower() for f in findings}
    if not missing:
        return findings

    # corrective round over the union: name exactly who is still absent
    corrective_prompt = list(messages) + [
        {"role": "user", "content": EXTRACTION_PROMPT},
        {"role": "assistant", "content": (texts[0] if texts else "")[:4000]},
        {"role": "user", "content":
            f"The extraction omitted credentials for: {', '.join(sorted(missing))}. "
            f"They ARE in the final report. Re-emit the COMPLETE findings JSON "
            f"(all previous entries PLUS the missing ones), same schema, raw JSON only."},
    ]
    try:
        resp = client.messages.create(
            model=policy.model,
            max_tokens=min(policy.max_tokens, 16384),
            messages=corrective_prompt,
        )
        text = "".join(getattr(b, "text", "") for b in resp.content)
        return _merge_passes([findings, _sanitize(_parse_findings_json(text))])
    except Exception:  # noqa: BLE001 - union result is still the best we have
        return findings
