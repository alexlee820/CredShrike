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
