"""Per-run resume state: the run manifest and per-share checkpoint files.

An interrupted sweep loses everything in RAM — host progress, per-share
results, ShareLedger verdicts, budget spend, findings. This module pins the
progress to disk inside the run directory so a restarted run (CLI
``--resume`` / web UI) can skip completed hosts and shares, continue a
half-analyzed share from its persisted ledger, and restore budget spend:

::

    runs/domain_<stamp>/run.json                  # RunManifest (main thread)
    runs/domain_<stamp>/state/<host>/<share>.json # ShareState (per share)

Everything here contains ONLY run progress and results — credentials are
never persisted, and the whole tree lives under the git-ignored ``runs/``
(plus explicit .gitignore patterns as belt-and-suspenders).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Optional

from .inventory_cache import sanitize_name

MANIFEST_NAME = "run.json"
STATE_DIR = "state"

# coverage-shaping policy keys — a resume whose fingerprint differs on any of
# these would silently cover a different file set, so mismatch refuses
FINGERPRINT_POLICY_KEYS = (
    "analysis_mode", "analysis_triage", "analysis_group_files",
    "dump_depth", "dump_per_file_bytes", "dump_max_files", "dump_skip_exts",
    "model",
)


def _policy_snapshot(policy) -> dict:
    return {k: list(getattr(policy, k)) if isinstance(getattr(policy, k), list)
            else getattr(policy, k)
            for k in FINGERPRINT_POLICY_KEYS if hasattr(policy, k)}


def fingerprint_components(dc: str, domain_source: str, computers_filter: str,
                           max_hosts, policy) -> dict:
    """Everything a resume must agree on — the manifest stores exactly this
    dict, and run_fingerprint hashes it."""
    return {
        "dc": dc or "", "domain_source": domain_source or "",
        "computers_filter": computers_filter or "",
        "max_hosts": max_hosts or 0,
        "policy": _policy_snapshot(policy),
    }


def run_fingerprint(dc: str, domain_source: str, computers_filter: str,
                    max_hosts, policy) -> str:
    payload = json.dumps(
        fingerprint_components(dc, domain_source, computers_filter, max_hosts,
                               policy), sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_diff(manifest_fp_components: dict, dc, domain_source,
                     computers_filter, max_hosts, policy) -> list:
    """Which fingerprint components changed vs the manifest's run."""
    current = fingerprint_components(dc, domain_source, computers_filter,
                                     max_hosts, policy)
    changed = []
    for key, value in current.items():
        if manifest_fp_components.get(key) != value:
            if key == "policy":
                old = manifest_fp_components.get(key, {}) or {}
                for sub in sorted(set(value) | set(old)):
                    if value.get(sub) != old.get(sub):
                        changed.append(f"policy.{sub}")
            else:
                changed.append(key)
    return changed


def _atomic_write_json(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)   # atomic on the same volume, NTFS included


def _read_json(path: str) -> Optional[dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


class RunManifest:
    """run.json — run identity, host statuses, budget spend. Written only by
    the main orchestrator thread, always atomically."""

    def __init__(self, run_dir: str, data: dict):
        self.run_dir = run_dir
        self.data = data

    # -- lifecycle ---------------------------------------------------------- #
    @classmethod
    def create(cls, run_dir: str, hosts: list, components: dict,
               computers: list) -> "RunManifest":
        fingerprint = hashlib.sha256(json.dumps(
            components, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        data = {
            "version": 1,
            "run_dir": run_dir,
            "created_at": now, "updated_at": now,
            "status": "running",
            "fingerprint": fingerprint,
            "fingerprint_components": components,
            "hosts_order": list(hosts),
            "computers": computers,
            "budget": {"bytes_read": 0, "tool_calls": 0, "elapsed_s": 0.0},
            "hosts": {h: {"status": "pending", "error": "", "shares": [],
                          "shares_done": [], "html": "", "audit_path": "",
                          "findings_count": 0, "tool_calls": 0, "bytes_read": 0}
                      for h in hosts},
        }
        mf = cls(run_dir, data)
        mf.save()
        return mf

    @classmethod
    def load(cls, run_dir: str) -> "RunManifest":
        data = _read_json(os.path.join(run_dir, MANIFEST_NAME))
        if data is None:
            raise FileNotFoundError(
                f"{run_dir} is not a resumable run (no readable {MANIFEST_NAME})")
        return cls(run_dir, data)

    def save(self) -> None:
        self.data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        _atomic_write_json(os.path.join(self.run_dir, MANIFEST_NAME), self.data)

    # -- mutation ------------------------------------------------------------ #
    def mark_host(self, host: str, **fields) -> None:
        entry = self.data["hosts"].setdefault(host, {"status": "pending"})
        entry.update(fields)

    def record_budget(self, bytes_read: int, tool_calls: int,
                      elapsed_s: float) -> None:
        self.data["budget"] = {"bytes_read": int(bytes_read),
                               "tool_calls": int(tool_calls),
                               "elapsed_s": round(float(elapsed_s), 1)}

    def mark_complete(self) -> None:
        self.data["status"] = "complete"
        self.save()

    # -- queries -------------------------------------------------------------- #
    def host_status(self, host: str) -> str:
        return self.data["hosts"].get(host, {}).get("status", "pending")

    def budget_spend(self) -> dict:
        return dict(self.data.get("budget") or {})

    def summary(self) -> dict:
        hosts = self.data.get("hosts", {})
        done = sum(1 for h in hosts.values() if h.get("status") == "done")
        shares = sum(len(h.get("shares_done", [])) for h in hosts.values())
        return {"run_dir": self.run_dir,
                "created_at": self.data.get("created_at", ""),
                "updated_at": self.data.get("updated_at", ""),
                "status": self.data.get("status", "running"),
                "hosts_done": done, "hosts_total": len(self.data.get("hosts_order", [])),
                "shares_done": shares,
                "resumable": self.data.get("status") != "complete" and done < len(
                    self.data.get("hosts_order", []))}


class ShareStateStore:
    """state/<host>/<share>.json — one writer per file, atomic rewrites."""

    def __init__(self, run_dir: str):
        self.run_dir = run_dir

    def _path(self, host: str, share: str) -> str:
        return os.path.join(self.run_dir, STATE_DIR, sanitize_name(host),
                            sanitize_name(share.lower()) + ".json")

    def save(self, host: str, share: str, payload: dict) -> None:
        payload = dict(payload, host=host, share=share)  # real names, not sanitized
        _atomic_write_json(self._path(host, share), payload)

    def load(self, host: str, share: str) -> Optional[dict]:
        return _read_json(self._path(host, share))

    def load_host(self, host: str) -> dict:
        """{real share name → state payload} for one host."""
        out = {}
        directory = os.path.join(self.run_dir, STATE_DIR, sanitize_name(host))
        try:
            names = os.listdir(directory)
        except OSError:
            return out
        for name in names:
            if not name.endswith(".json"):
                continue
            payload = _read_json(os.path.join(directory, name))
            if payload and payload.get("share"):
                out[payload["share"]] = payload
        return out


def load_host_result(run_dir: str, host: str) -> dict:
    """Rebuild an orchestrator-shaped results entry for a DONE host from the
    manifest + share states (findings/reports included, order = share order
    recorded in the manifest)."""
    manifest = RunManifest.load(run_dir)
    store = ShareStateStore(run_dir)
    entry = dict(manifest.data["hosts"].get(host) or {})
    states = store.load_host(host)
    ordered = [s for s in entry.get("shares_done", []) if s in states] + \
              [s for s in states if s not in entry.get("shares_done", [])]
    findings, reports = [], []
    bytes_read = 0
    for share in ordered:
        st = states[share]
        findings.extend(st.get("findings") or [])
        reports.append(st.get("report") or "")
        bytes_read += int(st.get("bytes_read") or 0)
    return {
        "host": host,
        "status": "done",
        "error": entry.get("error", ""),
        "shares": entry.get("shares", []),
        "findings": findings,
        "report_md": "\n\n".join(r for r in reports if r),
        "audit_path": entry.get("audit_path", ""),
        "html": entry.get("html", ""),
        "tool_calls": int(entry.get("tool_calls") or 0),
        "bytes_read": int(entry.get("bytes_read") or bytes_read),
        "shares_done": entry.get("shares_done", []),
        "memory": next((states[s].get("memory") for s in reversed(ordered)
                        if states[s].get("memory")), ""),
    }


def scan_run_dirs(audit_dir: str, limit: int = 50) -> list:
    """Summaries of every run directory carrying a manifest, newest first —
    the web UI resume list. Pure disk scan, nothing in-memory."""
    out = []
    try:
        entries = os.listdir(audit_dir)
    except OSError:
        return out
    for name in entries:
        if not name.startswith("domain_"):
            continue
        run_dir = os.path.join(audit_dir, name)
        if not os.path.isfile(os.path.join(run_dir, MANIFEST_NAME)):
            continue
        data = _read_json(os.path.join(run_dir, MANIFEST_NAME))
        if not data:
            continue
        hosts = data.get("hosts", {})
        order = data.get("hosts_order", [])
        done = sum(1 for h in hosts.values() if h.get("status") == "done")
        out.append({
            "run_dir": run_dir,
            "created_at": data.get("created_at", ""),
            "updated_at": data.get("updated_at", ""),
            "status": data.get("status", "running"),
            "hosts_done": done, "hosts_total": len(order),
            "shares_done": sum(len(h.get("shares_done", [])) for h in hosts.values()),
            "resumable": data.get("status") != "complete" and done < len(order),
        })
    out.sort(key=lambda r: r["updated_at"], reverse=True)
    return out[:limit]
