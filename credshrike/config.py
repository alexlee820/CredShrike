"""Configuration: credential profiles (YAML) and the agent policy.

The policy object is the single source of truth for every cap the agent
executor enforces. CLI/manual use is unaffected by it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from .credentials import Credential

DEFAULT_POLICY_DICT: dict[str, Any] = {
    "max_file_bytes": 256 * 1024,       # per smb_read_file call
    "max_entries": 500,                 # per smb_list_dir call
    "result_char_cap": 8192,            # per tool_result fed to the LLM
    "max_tool_calls": 100,              # per run
    "max_total_read_bytes": 10 * 1024 * 1024,
    "wall_clock_seconds": 1800,
    "allowed_hosts": [],                # empty = whatever the CLI passes explicitly
    "model": "claude-opus-5",
    "max_tokens": 16000,
    # --- read gate: flag-but-don't-read modes for smb_read_file -----------
    # "none": read whatever the model asks (within max_file_bytes)  [current]
    # "ai":   model chooses freely, but a request whose ESTIMATED token count
    #         exceeds max_read_tokens is not executed — returned as flagged
    # "size": files larger than flag_oversize_bytes are never read; the
    #         request returns flagged with the real size (from smb_stat)
    "read_gate": "none",
    "max_read_tokens": 8192,            # ai mode: estimated-token ceiling per read
    "chars_per_token": 4.0,             # ai mode: estimation ratio (bytes/4 ≈ tokens)
    "flag_oversize_bytes": 5 * 1024 * 1024,   # size mode: 5 MiB default
    # --- redaction: scrub tool results BEFORE they reach the LLM -----------
    "redact_literals": [],              # exact strings to mask (e.g. codenames, hostnames)
    "redact_patterns": [],              # regexes; with a capture group only the group
                                        # is masked: 'password\s*=\s*(\S+)' keeps the key
    "redact_replacement": "[REDACTED]",
    # --- PasteGuard-style privacy masking (see credshrike/masking.py) ------
    # Detected PII/secrets become [[TYPE_N]] placeholders on the way to the
    # LLM and are restored in its output (mask_restore) — a compromised or
    # third-party model never receives the real values.
    "mask_pii": False,                  # emails, IPs, cards, IBANs, VAT, phones
    "mask_secrets": False,              # API keys, JWTs, private keys, passwords, DSNs
    "mask_restore": True,               # put originals back in the model's output
    "mask_show_markers": False,         # prefix restored values with mask_marker_text
    "mask_marker_text": "[protected]",
    "mask_max_scan_chars": 200_000,     # per-pass chunk size (the WHOLE text is scanned)
    "mask_allowlist": [],               # strings/regexes never masked:
                                        # [{"pattern": "Company Inc.", "regex": false}]
    "mask_denylist": [],                # always masked, custom type:
                                        # [{"pattern": "CUST-\\d{6}", "type": "CUSTOMER_ID", "regex": true}]
    # --- optional GLiNER semantic PII layer (PERSON / LOCATION) -----------
    # needs `pip install "gliner>=0.2.27,<0.3"`; the model downloads on first
    # use. Deterministic detectors still win on overlap.
    "mask_semantic": False,
    "mask_semantic_model": "urchade/gliner_multi_pii-v1",
    "mask_semantic_threshold": 0.7,     # call-level floor (can only RAISE
                                        # the per-label floors: person .99,
                                        # location/address .80)
    "mask_semantic_labels": ["person", "location", "address"],
    "mask_semantic_floors": {},         # per-label overrides, e.g. {person: 0.9}
    "mask_semantic_max_tokens": 384,    # window size (64-token overlap)
    "mask_semantic_overlap": 64,
    # --- same-length surrogates instead of [[TYPE_N]] for names/passwords --
    # Alice Smith -> Amber Scott, Winter2024! -> Xkqmbn7314# (restored later;
    # lengths and password character classes are preserved). Values that are
    # too short or cannot be made collision-safe use [[TYPE_N]] instead.
    "mask_same_length": ["PERSON", "ENV_PASSWORD"],
    "mask_surrogate_style": "name",        # name | syllable | masked
    "mask_surrogate_keep_initials": True,  # Alice -> Amber (A kept)
    "mask_surrogate_min_len": 4,           # shorter values -> [[TYPE_N]]
    # --- snaffler-style scan tool (smb_scan_share) --------------------------
    "scan_depth": 3,
    "scan_max_files": 200,              # candidates opened per sweep
    "scan_max_file_bytes": 65536,       # per file
    "scan_tiers": ["red", "yellow"],
    "scan_use_default_patterns": True,
    "scan_extra_patterns": {},          # {name: regex}; same name replaces the built-in
    # --- full-content dump tool (smb_dump_share — custom-goal mode) ---------
    "dump_depth": 6,
    "dump_per_file_bytes": 16384,       # head sent per file
    "dump_page_chars": 24000,           # page target (tool char_cap is 40000)
    "dump_max_files": 500,
    # extensions to SKIP during dump (still listed in the report as "seen but not read")
    "read_threads": 4,                  # parallel SMB reads (all presets)
    "dump_skip_exts": [
        ".rar", ".7z", ".zip", ".exe", ".msi", ".dll",           # archives + binaries
        ".iso", ".vhd", ".vhdx", ".vmdk", ".img", ".wim",       # disk/vm images
        ".mp3", ".mp4", ".avi", ".mkv", ".wav",                  # media
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", # images
        ".doc", ".xls", ".ppt",                                   # legacy OLE2 (binary)
        ".pst", ".ost",                                           # outlook (huge)
        ".ttf", ".otf", ".woff", ".fon",                          # fonts
        ".cab", ".msu", ".appx",                                  # windows packages
        ".jar", ".war",                                           # java archives
        ".db", ".sqlite", ".mdf", ".ndf",                        # databases
        ".psd", ".ai",                                            # design files
    ],  # NOTE: .docx/.xlsx/.pptx are NOT skipped — text is extracted from the OOXML zip
    # --- debug mode: echo + record FULL tool results (what the model saw) --
    "debug": False,
    # --- streaming (SSE) ----------------------------------------------------
    # Same model/prompt/cost — only the transport differs. Tokens are echoed
    # live, long requests are less likely to hit proxy idle timeouts, and the
    # final message is identical to a non-streaming call. Falls back to a
    # plain request automatically when an endpoint rejects streaming.
    "stream": True,
    # --- context-window management ------------------------------------------
    "context_token_limit": 0,       # 0 = auto-manage off (set your model's
                                    # window, e.g. 128000 for GLM, 1000000 for
                                    # claude-opus; CLI --context-limit)
    "compact_at_ratio": 0.75,       # compact old tool results at 75% of limit
    "compact_keep_recent": 4,       # newest N messages stay untouched
    # --- LLM endpoint (Anthropic-compatible providers: GLM, DeepSeek, ...) ---
    "api_base_url": "",                 # empty = official Anthropic API
    "api_key": "",                      # empty = ANTHROPIC_API_KEY env / auth profile
    "thinking_mode": "adaptive",        # adaptive | off — off is safer on 3rd-party
                                        # endpoints; auto-set when api_base_url is given
}


@dataclass
class Policy:
    max_file_bytes: int = DEFAULT_POLICY_DICT["max_file_bytes"]
    max_entries: int = DEFAULT_POLICY_DICT["max_entries"]
    result_char_cap: int = DEFAULT_POLICY_DICT["result_char_cap"]
    max_tool_calls: int = DEFAULT_POLICY_DICT["max_tool_calls"]
    max_total_read_bytes: int = DEFAULT_POLICY_DICT["max_total_read_bytes"]
    wall_clock_seconds: int = DEFAULT_POLICY_DICT["wall_clock_seconds"]
    allowed_hosts: list[str] = field(default_factory=list)
    model: str = DEFAULT_POLICY_DICT["model"]
    max_tokens: int = DEFAULT_POLICY_DICT["max_tokens"]
    read_gate: str = DEFAULT_POLICY_DICT["read_gate"]          # none | ai | size
    max_read_tokens: int = DEFAULT_POLICY_DICT["max_read_tokens"]
    chars_per_token: float = DEFAULT_POLICY_DICT["chars_per_token"]
    flag_oversize_bytes: int = DEFAULT_POLICY_DICT["flag_oversize_bytes"]
    redact_literals: list[str] = field(default_factory=list)
    redact_patterns: list[str] = field(default_factory=list)
    redact_replacement: str = DEFAULT_POLICY_DICT["redact_replacement"]
    mask_pii: bool = DEFAULT_POLICY_DICT["mask_pii"]
    mask_secrets: bool = DEFAULT_POLICY_DICT["mask_secrets"]
    mask_restore: bool = DEFAULT_POLICY_DICT["mask_restore"]
    mask_show_markers: bool = DEFAULT_POLICY_DICT["mask_show_markers"]
    mask_marker_text: str = DEFAULT_POLICY_DICT["mask_marker_text"]
    mask_max_scan_chars: int = DEFAULT_POLICY_DICT["mask_max_scan_chars"]
    mask_allowlist: list = field(default_factory=list)
    mask_denylist: list = field(default_factory=list)
    mask_semantic: bool = DEFAULT_POLICY_DICT["mask_semantic"]
    mask_semantic_model: str = DEFAULT_POLICY_DICT["mask_semantic_model"]
    mask_semantic_threshold: float = DEFAULT_POLICY_DICT["mask_semantic_threshold"]
    mask_semantic_labels: list = field(
        default_factory=lambda: list(DEFAULT_POLICY_DICT["mask_semantic_labels"]))
    mask_semantic_floors: dict = field(default_factory=dict)
    mask_semantic_max_tokens: int = DEFAULT_POLICY_DICT["mask_semantic_max_tokens"]
    mask_semantic_overlap: int = DEFAULT_POLICY_DICT["mask_semantic_overlap"]
    mask_same_length: list = field(
        default_factory=lambda: list(DEFAULT_POLICY_DICT["mask_same_length"]))
    mask_surrogate_style: str = DEFAULT_POLICY_DICT["mask_surrogate_style"]
    mask_surrogate_keep_initials: bool = DEFAULT_POLICY_DICT["mask_surrogate_keep_initials"]
    mask_surrogate_min_len: int = DEFAULT_POLICY_DICT["mask_surrogate_min_len"]
    scan_depth: int = DEFAULT_POLICY_DICT["scan_depth"]
    scan_max_files: int = DEFAULT_POLICY_DICT["scan_max_files"]
    scan_max_file_bytes: int = DEFAULT_POLICY_DICT["scan_max_file_bytes"]
    scan_tiers: list[str] = field(default_factory=lambda: list(DEFAULT_POLICY_DICT["scan_tiers"]))
    scan_use_default_patterns: bool = DEFAULT_POLICY_DICT["scan_use_default_patterns"]
    scan_extra_patterns: dict[str, str] = field(default_factory=dict)
    dump_depth: int = DEFAULT_POLICY_DICT["dump_depth"]
    dump_per_file_bytes: int = DEFAULT_POLICY_DICT["dump_per_file_bytes"]
    dump_page_chars: int = DEFAULT_POLICY_DICT["dump_page_chars"]
    dump_max_files: int = DEFAULT_POLICY_DICT["dump_max_files"]
    read_threads: int = DEFAULT_POLICY_DICT["read_threads"]
    dump_skip_exts: list[str] = field(default_factory=lambda: list(DEFAULT_POLICY_DICT["dump_skip_exts"]))
    debug: bool = DEFAULT_POLICY_DICT["debug"]
    stream: bool = DEFAULT_POLICY_DICT["stream"]
    context_token_limit: int = DEFAULT_POLICY_DICT["context_token_limit"]
    compact_at_ratio: float = DEFAULT_POLICY_DICT["compact_at_ratio"]
    compact_keep_recent: int = DEFAULT_POLICY_DICT["compact_keep_recent"]
    api_base_url: str = DEFAULT_POLICY_DICT["api_base_url"]
    api_key: str = DEFAULT_POLICY_DICT["api_key"]
    thinking_mode: str = DEFAULT_POLICY_DICT["thinking_mode"]

    @classmethod
    def load(cls, path: Optional[str] = None, overrides: Optional[dict] = None) -> "Policy":
        data: dict[str, Any] = {}
        if path:
            with open(path, "r", encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        merged = {**DEFAULT_POLICY_DICT, **data.get("policy", {}), **(overrides or {})}
        # env escape hatch for the model, since it changes most often
        merged["model"] = os.environ.get("SMBENUM_MODEL", merged["model"])
        return cls(**{k: merged[k] for k in cls.__dataclass_fields__ if k in merged})


@dataclass
class Profile:
    """A named credential + optional domain/target hints from YAML."""

    name: str
    credential: Credential
    kdc: str = ""
    targets: list[str] = field(default_factory=list)
    domain_source: str = "ldap"        # ldap | adws | auto

    @classmethod
    def load(cls, path: str, name: Optional[str] = None) -> "Profile":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        profiles = data.get("profiles") or {}
        if not profiles:
            # allow a flat single-profile file
            profiles = {"default": data}
        if name is None:
            name = next(iter(profiles))
        if name not in profiles:
            raise KeyError(f"profile '{name}' not found; have: {sorted(profiles)}")
        entry = profiles[name]
        credential = Credential.from_profile(entry)
        credential.validate()
        return cls(name=name, credential=credential, kdc=entry.get("kdc", ""),
                   targets=entry.get("targets", []) or [],
                   domain_source=entry.get("domain_source", "ldap"))
