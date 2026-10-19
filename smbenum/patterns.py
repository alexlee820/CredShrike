"""Credential-detection patterns for the snaffler-style scan mode.

Two kinds of knowledge, distilled from Snaffler's default rule set:

- PATTERN list: content regexes. Each entry carries a name and a compiled
  pattern; when the pattern has a capture group, group(1) is THE SECRET and
  gets masked in snippets (context stays, value goes).
- Extension tiers: which files are worth opening, in priority order.
  "red"  = almost certainly credential-bearing, scan first
  "yellow" = plausibly interesting, scan second
  anything else = skipped by the scan (the model can still read files
  individually — this only orders/bounds the deterministic sweep).

Users extend/override via policy (scan_extra_patterns) or a YAML file
(--scan-patterns): mapping of {name: regex-with-optional-group}.
"""

from __future__ import annotations

import re

DEFAULT_PATTERNS: list[dict] = [
    {"name": "password_assignment", "pattern": r"(?i)\bpass(?:word|wd)\b\s*[:=]\s*[\"']?([^\s\"';]{4,})"},
    {"name": "pwd_assignment", "pattern": r"(?i)\bpwd\b\s*[:=]\s*[\"']?([^\s\"';]{4,})"},
    {"name": "secret_assignment", "pattern": r"(?i)\bsecret\b\s*[:=]\s*[\"']?([^\s\"';]{4,})"},
    {"name": "connection_string_password", "pattern": r"(?i)\bpassword\s*=\s*([^;\s\"']{4,})"},
    {"name": "private_key_block", "pattern": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
    {"name": "aws_access_key", "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"},
    {"name": "github_token", "pattern": r"\bghp_[A-Za-z0-9]{36}\b"},
    {"name": "slack_token", "pattern": r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"},
    {"name": "azure_storage_key", "pattern": r"\bAccountKey=[A-Za-z0-9+/=]{60,}"},
    # command-line credential: net use \\srv\share /user:DOMAIN\user password
    # (group = the SECRET so masking hides the password, username stays visible)
    {"name": "net_use_credential", "pattern": r"(?i)/user:[A-Za-z0-9_.\\$-]+\s+([^\s\"\x27]{4,})"},
]

# --- file triage tiers ------------------------------------------------------ #
RED_EXTS = {".kdbx", ".key", ".pem", ".ppk", ".pfx", ".p12", ".rdp", ".vnc", ".env"}
RED_NAME_SUBSTRINGS = ("password", "passwort", "passw", "secret", "credential",
                       "unattend", "sysprep", "web.config", "app.config",
                       "connectionstring", "id_rsa", "keytab")
YELLOW_EXTS = {".config", ".xml", ".ini", ".cfg", ".conf", ".ps1", ".psm1", ".bat",
               ".cmd", ".vbs", ".sql", ".txt", ".yaml", ".yml", ".json", ".csv",
               ".py", ".sh", ".hta", ".asp", ".aspx", ".php", ".jsp", ".reg",
               ".log"}

# structured-data files: regex can't see their secrets (a 'user,pass' CSV row
# has no keyword to match), so the sweep surfaces them for the AI to READ
DATA_EXTS = {".csv", ".tsv", ".json"}

TIERS = {"red": (RED_EXTS, RED_NAME_SUBSTRINGS), "yellow": (YELLOW_EXTS, ())}


def is_data_file(name: str) -> bool:
    return name.lower().endswith(tuple(DATA_EXTS))


def classify_file(name: str, tiers=("red", "yellow")) -> str | None:
    """Return the tier of a file name ('red' > 'yellow') or None (skip)."""
    lowered = name.lower()
    for tier in tiers:
        exts, subs = TIERS[tier]
        if lowered.endswith(tuple(exts)) or any(s in lowered for s in subs):
            return tier
    return None


def compile_patterns(extra: dict | None = None, use_defaults: bool = True) -> list[dict]:
    """Merge default + user patterns into compiled entries
    [{name, regex, compiled}]. User entries with the same name replace
    the built-in one (order preserved: defaults first, extras after)."""
    entries: list[dict] = []
    if use_defaults:
        for entry in DEFAULT_PATTERNS:
            entries.append({"name": entry["name"], "regex": entry["pattern"],
                            "compiled": re.compile(entry["pattern"])})
    for name, pattern in (extra or {}).items():
        entries.append({"name": name, "regex": pattern, "compiled": re.compile(pattern)})
    return entries
