"""Tests for per-run resume state (credshrike/runstate.py)."""
from pathlib import Path

import pytest

from credshrike.config import Policy
from credshrike.runstate import (RunManifest, ShareStateStore,
                                 fingerprint_components, fingerprint_diff,
                                 load_host_result, run_fingerprint,
                                 scan_run_dirs)


@pytest.fixture()
def run_dir(tmp_path):
    d = tmp_path / "domain_20261112T101010Z"
    d.mkdir()
    return str(d)


def _manifest(run_dir, hosts=("ws01.corp.local", "ws02.corp.local")):
    policy = Policy()
    return RunManifest.create(
        run_dir, hosts=list(hosts),
        components=fingerprint_components("dc01", "ldap", "", None, policy),
        computers=[{"cn": "WS01", "dns_name": "ws01.corp.local"}])


# --------------------------------------------------------------------------- #
# manifest
# --------------------------------------------------------------------------- #

def test_manifest_roundtrip(run_dir):
    mf = _manifest(run_dir)
    mf.mark_host("ws01.corp.local", status="done", html="a.html",
                 findings_count=2, shares_done=["IT", "Data"])
    mf.record_budget(4096, 12, 33.3)
    mf.mark_complete()

    again = RunManifest.load(run_dir)
    assert again.host_status("ws01.corp.local") == "done"
    assert again.host_status("ws02.corp.local") == "pending"
    assert again.budget_spend() == {"bytes_read": 4096, "tool_calls": 12,
                                    "elapsed_s": 33.3}
    assert again.data["status"] == "complete"
    assert again.data["computers"][0]["cn"] == "WS01"   # resume skips AD query
    assert "password" not in Path(run_dir, "run.json").read_text(encoding="utf-8")


def test_manifest_load_rejects_garbage(tmp_path):
    (tmp_path / "run.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        RunManifest.load(str(tmp_path))


def test_fingerprint_stable_and_diff_names_keys(run_dir):
    policy = Policy()
    mf = _manifest(run_dir)
    # identical params → identical fingerprint
    assert run_fingerprint("dc01", "ldap", "", None, policy) == mf.data["fingerprint"]
    # changed dump_skip_exts → diff names policy.dump_skip_exts
    other = Policy()
    other.dump_skip_exts = [".mp4"]
    changed = fingerprint_diff(mf.data["fingerprint_components"],
                               "dc01", "ldap", "", None, other)
    assert changed == ["policy.dump_skip_exts"]
    # changed dc → diff names dc
    changed = fingerprint_diff(mf.data["fingerprint_components"],
                               "dc99", "ldap", "", None, policy)
    assert changed == ["dc"]


# --------------------------------------------------------------------------- #
# share state store
# --------------------------------------------------------------------------- #

def test_share_state_roundtrip_and_hostile_names(run_dir):
    store = ShareStateStore(run_dir)
    payload = {"status": "done", "findings": [{"severity": "high"}],
               "report": "### IT", "bytes_read": 123, "memory": "m"}
    store.save(r'WS01.corp.local\\evil$', "IT", payload)
    back = store.load(r'WS01.corp.local\\evil$', "IT")
    assert back["status"] == "done" and back["findings"][0]["severity"] == "high"
    # real names stored inside the payload, sanitized on disk
    assert back["host"] == r'WS01.corp.local\\evil$' and back["share"] == "IT"
    state_files = list(Path(run_dir, "state").rglob("*.json"))
    assert len(state_files) == 1
    assert "evil" not in state_files[0].name or "_" in state_files[0].name


def test_share_state_load_host_orders_by_manifest(run_dir):
    mf = _manifest(run_dir)
    store = ShareStateStore(run_dir)
    store.save("ws01.corp.local", "Data", {"status": "done", "report": "### Data",
                                           "findings": [], "bytes_read": 5})
    store.save("ws01.corp.local", "IT", {"status": "done", "report": "### IT",
                                         "findings": [{"a": 1}], "bytes_read": 7,
                                         "memory": "summary"})
    mf.mark_host("ws01.corp.local", status="done", shares_done=["IT", "Data"])
    mf.save()

    result = load_host_result(run_dir, "ws01.corp.local")
    assert result["status"] == "done"
    assert result["report_md"].index("### IT") < result["report_md"].index("### Data")
    assert result["bytes_read"] == 12
    assert result["memory"] == "summary"
    assert result["findings"] == [{"a": 1}]


# --------------------------------------------------------------------------- #
# scan + gitignore protection
# --------------------------------------------------------------------------- #

def test_scan_run_dirs_lists_resumable_only(tmp_path):
    # interrupted run with a manifest
    run_dir = tmp_path / "domain_20261112T101010Z"
    run_dir.mkdir()
    mf = _manifest(str(run_dir))
    mf.mark_host("ws01.corp.local", status="done", shares_done=["IT"])
    mf.save()
    # complete run — must be listed but not resumable
    done_dir = tmp_path / "domain_20261112T111111Z"
    done_dir.mkdir()
    mf2 = _manifest(str(done_dir))
    mf2.mark_host("ws01.corp.local", status="done")
    mf2.mark_host("ws02.corp.local", status="done")
    mf2.mark_complete()
    # a run without a manifest — invisible
    (tmp_path / "domain_20261112T121212Z").mkdir()

    out = scan_run_dirs(str(tmp_path))
    by_dir = {r["run_dir"]: r for r in out}
    assert len(out) == 2
    assert by_dir[str(run_dir)]["resumable"] is True
    assert by_dir[str(run_dir)]["hosts_done"] == 1
    assert by_dir[str(done_dir)]["resumable"] is False


def test_gitignore_protects_cache_and_state():
    """The user's hard requirement: the cache db and run state can never be
    committed (lab file content lives in them)."""
    import subprocess
    for path in ("runs/.cache/inventory.db", "runs/x/run.json",
                 "runs/x/state/ws01/it.json", "elsewhere/.cache/inventory.db"):
        rc = subprocess.run(["git", "check-ignore", "-q", path],
                            capture_output=True).returncode
        assert rc == 0, f"{path} is NOT git-ignored"
