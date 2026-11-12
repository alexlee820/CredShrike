"""Resume tests: host-level skip, budget restore, fingerprint guard, and
stream-mode share/file-level checkpointing."""
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from credshrike.agent.orchestrator import run_domain_sweep
from credshrike.config import Policy
from credshrike.credentials import Credential
from credshrike.runstate import RunManifest, ShareStateStore

from test_orchestrator import (_client_factory_for_hosts, _computers,
                               _credential)
from test_stream import _FakeSMB, _fake_client

PENDING = {"status": "pending", "error": "", "shares": [], "shares_done": [],
           "html": "", "audit_path": "", "findings_count": 0,
           "tool_calls": 0, "bytes_read": 0}


@pytest.fixture
def fake_smb(monkeypatch):
    from test_agent import FakeSMB
    fake = FakeSMB()
    import credshrike.agent.session as session_mod
    monkeypatch.setattr(session_mod.AgentSession, "smb",
                        lambda self, host: fake)
    import credshrike.smb_session as smb_mod

    def _no_real_smb(*a, **k):
        raise ConnectionError("no real SMB sessions in tests")
    monkeypatch.setattr(smb_mod, "create_smb_session", _no_real_smb)
    return fake


def _sweep(tmp_path, factory, policy=None, resume_dir=None, echo=None,
           hosts=None):
    return run_domain_sweep(
        credential=_credential(), policy=policy or Policy(),
        audit_dir=str(tmp_path), client_factory=factory,
        echo=echo or (lambda l: None),
        source_override=lambda: (hosts or _computers())[:2],
        reachable_check=lambda host: True,
        resume_dir=resume_dir)


def _reset_host_to_pending(run_dir: str, host: str, wipe_shares=True):
    """Turn a completed run into an interrupted one: `host` goes back to
    pending and its share checkpoints disappear (as if it crashed mid-host)."""
    mf = RunManifest.load(run_dir)
    mf.data["status"] = "running"
    mf.data["hosts"][host] = dict(PENDING)
    mf.save()
    if wipe_shares:
        from credshrike.inventory_cache import sanitize_name
        host_dir = Path(run_dir, "state", sanitize_name(host))
        if host_dir.is_dir():
            for f in host_dir.glob("*.json"):
                f.unlink()


# --------------------------------------------------------------------------- #
# host level
# --------------------------------------------------------------------------- #

def test_resume_skips_done_host(tmp_path, fake_smb):
    old_ws01 = [{"severity": "high", "category": "credential", "host": "ws01",
                 "share": "IT", "path": "a.ps1", "username": "svc",
                 "secret": "SamePass1", "evidence": "e", "note": ""}]
    old_ws02 = [{"severity": "low", "category": "other", "host": "ws02",
                 "share": "IT", "path": "x", "username": None, "secret": None,
                 "evidence": "e", "note": "old note"}]
    r1 = _sweep(tmp_path, _client_factory_for_hosts({
        "ws01.corp.local": old_ws01, "ws02.corp.local": old_ws02}))
    run_dir = r1["run_dir"]
    assert all(h["status"] == "done" for h in r1["hosts"])

    # crash: ws02 loses its progress, ws01 stays done
    _reset_host_to_pending(run_dir, "ws02.corp.local")

    new_ws02 = [{"severity": "high", "category": "credential", "host": "ws02",
                 "share": "IT", "path": "b.csv", "username": "other",
                 "secret": "Pass9", "evidence": "e", "note": ""}]
    factory2 = _client_factory_for_hosts({"ws02.corp.local": new_ws02})
    lines = []
    r2 = _sweep(tmp_path, factory2, resume_dir=run_dir, echo=lines.append)

    assert r2["resumed"] is True
    statuses = {h["host"]: h["status"] for h in r2["hosts"]}
    assert statuses == {"ws01.corp.local": "done", "ws02.corp.local": "done"}
    # ws01 was NOT re-analyzed: no goal mentions it
    goals_text = str(factory2.state["goals"])
    assert "ws01" not in goals_text
    assert any("done in previous session — skipping" in l for l in lines)
    # merged findings include the PERSISTED ws01 creds + the NEW ws02 creds
    secrets = {c.get("secret") for c in r2["merged"]["credentials"]}
    assert "SamePass1" in secrets and "Pass9" in secrets
    # index regenerated over everything, manifest complete
    assert os.path.exists(r2["index_html"])
    assert RunManifest.load(run_dir).data["status"] == "complete"


def test_resume_restores_budget(tmp_path, fake_smb):
    r1 = _sweep(tmp_path, _client_factory_for_hosts({}))
    run_dir = r1["run_dir"]
    mf = RunManifest.load(run_dir)
    mf.data["status"] = "running"
    mf.data["budget"]["bytes_read"] = 10 ** 9   # cap exhausted before crash
    mf.data["hosts"]["ws02.corp.local"] = dict(PENDING)
    mf.save()

    r2 = _sweep(tmp_path, _client_factory_for_hosts({}), resume_dir=run_dir)
    statuses = {h["host"]: h["status"] for h in r2["hosts"]}
    assert statuses["ws01.corp.local"] == "done"          # recovered
    assert statuses["ws02.corp.local"] == "skipped-budget"  # gate saw the spend


def test_resume_rejects_fingerprint_mismatch(tmp_path, fake_smb):
    r1 = _sweep(tmp_path, _client_factory_for_hosts({}))
    changed = Policy()
    changed.dump_skip_exts = [".mp4"]
    with pytest.raises(ValueError, match="dump_skip_exts"):
        _sweep(tmp_path, _client_factory_for_hosts({}), policy=changed,
               resume_dir=r1["run_dir"])


# --------------------------------------------------------------------------- #
# stream mode: share + file level
# --------------------------------------------------------------------------- #

class TwoShareSMB(_FakeSMB):
    """Two one-file shares so share-level reuse is observable."""

    def __init__(self):
        super().__init__({"f0.txt": "DB_PASSWORD=Alpha1\n",
                          "g0.txt": "DB_PASSWORD=Beta2\n"})

    def list_shares(self):
        return [{"name": "IT", "remark": "", "type": 0, "type_name": "DISK",
                 "special": False},
                {"name": "Data", "remark": "", "type": 0, "type_name": "DISK",
                 "special": False}]

    def list_dir(self, share, path="", max_entries=200):
        name = "f0.txt" if share == "IT" else "g0.txt"
        return {"share": share, "path": path,
                "entries": [{"name": name, "is_dir": False, "size": 16}],
                "truncated": False, "total_seen": 1}

    def read_file(self, share, path, offset=0, max_bytes=65536):
        import base64 as b64
        data = self.files[path].encode()
        return {"share": share, "path": path, "offset": offset,
                "size": len(data), "truncated": False,
                "content_b64": b64.b64encode(data).decode()}


@pytest.fixture
def stream_env(tmp_path, monkeypatch):
    from queue import Queue
    from credshrike.agent.audit import AuditLog
    from credshrike.agent.session import AgentSession
    import credshrike.smb_session as smb_mod
    import credshrike.agent.session as session_mod

    policy = Policy()
    policy.analysis_mode = "stream"
    policy.analysis_group_files = 2
    policy.analysis_group_wait_ms = 50
    policy.dump_max_files = 4
    credential = _credential()
    fake = TwoShareSMB()
    monkeypatch.setattr(session_mod.AgentSession, "smb",
                        lambda self, host: fake)

    def _no_real_smb(*a, **k):
        raise ConnectionError("no real SMB sessions in tests")
    monkeypatch.setattr(smb_mod, "create_smb_session", _no_real_smb)
    s = AgentSession(credential, policy,
                     AuditLog.new_run(str(tmp_path)), hosts=["ws01"])
    s.get_read_pool = lambda host: _queue_of(fake)
    return {"policy": policy, "credential": credential, "session": s}


def _queue_of(fake):
    from queue import Queue
    q = Queue()
    q.put(fake)
    return q


def test_stream_done_share_reused_and_partial_resumed(tmp_path, monkeypatch,
                                                       stream_env):
    client1, state1 = _fake_client({"f0.txt": "", "g0.txt": ""})
    policy = stream_env["policy"]
    r1 = run_domain_sweep(
        credential=stream_env["credential"], policy=policy,
        audit_dir=str(tmp_path), client_factory=lambda: client1,
        echo=lambda l: None,
        source_override=lambda: [_computers()[0]],
        reachable_check=lambda host: True)
    run_dir = r1["run_dir"]
    assert r1["hosts"][0]["status"] == "done"

    store = ShareStateStore(run_dir)
    assert set(store.load_host("ws01.corp.local")) == {"IT", "Data"}

    # crash scenario: Data loses everything; IT keeps only its in-progress
    # ledger with f0 already verdicted (file-level resume); host -> pending
    store.save("ws01.corp.local", "IT", {
        "status": "in-progress",
        "ledger": {"verdicts": {"f0.txt": {"verdict": "FOUND", "detail": ""}},
                   "unreadable": {}, "budget_skipped": []}})
    from credshrike.inventory_cache import sanitize_name
    (Path(run_dir, "state") / sanitize_name("ws01.corp.local")
     / "data.json").unlink()
    mf = RunManifest.load(run_dir)
    mf.data["status"] = "running"
    mf.data["hosts"]["ws01.corp.local"] = dict(PENDING)
    mf.save()

    client2, state2 = _fake_client({"f0.txt": "", "g0.txt": ""})
    lines = []
    r2 = run_domain_sweep(
        credential=stream_env["credential"], policy=policy,
        audit_dir=str(tmp_path), client_factory=lambda: client2,
        echo=lines.append,
        source_override=lambda: [_computers()[0]],
        reachable_check=lambda host: True,
        resume_dir=run_dir)

    assert r2["resumed"] is True
    assert r2["hosts"][0]["status"] == "done"
    # file-level resume: f0.txt already verdicted -> never re-sent to the LLM
    assert "f0.txt" not in state2["seen"]
    assert "g0.txt" in state2["seen"]
    # both shares still in the host report (coverage preserved by the ledger)
    report = r2["hosts"][0]["report_md"]
    assert "IT" in report and "Data" in report
    assert "f0.txt" in report            # verdict from the seeded ledger

    # round 3: crash with BOTH share states done -> share-level reuse, zero
    # LLM work for either share
    from credshrike.inventory_cache import sanitize_name
    mf = RunManifest.load(run_dir)
    mf.data["status"] = "running"
    mf.data["hosts"]["ws01.corp.local"] = dict(PENDING)
    mf.save()
    client3, state3 = _fake_client({"f0.txt": "", "g0.txt": ""})
    lines3 = []
    r3 = run_domain_sweep(
        credential=stream_env["credential"], policy=policy,
        audit_dir=str(tmp_path), client_factory=lambda: client3,
        echo=lines3.append,
        source_override=lambda: [_computers()[0]],
        reachable_check=lambda host: True,
        resume_dir=run_dir)
    assert r3["hosts"][0]["status"] == "done"
    assert any("done in previous session — reusing" in l for l in lines3)
    assert state3["batch_prompts"] == 0   # nothing re-analyzed at all


def test_stream_state_sink_writes_in_progress_checkpoints(tmp_path, stream_env):
    from credshrike.agent.stream_analysis import analyze_share_streaming
    sinks = []
    analyze_share_streaming(
        credential=stream_env["credential"], policy=stream_env["policy"],
        audit=stream_env["session"].audit, session=stream_env["session"],
        host="ws01", share_name="IT",
        client_factory=lambda: _fake_client({"f0.txt": ""})[0],
        echo=lambda l: None,
        state_sink=lambda snap: sinks.append(snap))
    assert sinks, "no checkpoint was written"
    assert all(s["status"] == "in-progress" for s in sinks)
    assert any("f0.txt" in s["ledger"]["verdicts"] for s in sinks)


# --------------------------------------------------------------------------- #
# discoverability: runs list, --resume latest, banner hint
# --------------------------------------------------------------------------- #

def _interrupted_run(tmp_path):
    from credshrike.config import Policy
    from credshrike.runstate import RunManifest, fingerprint_components
    run = tmp_path / "domain_20261112T101010Z"
    run.mkdir(parents=True)
    mf = RunManifest.create(str(run), hosts=["ws01.corp.local", "ws02.corp.local"],
                            components=fingerprint_components("", "auto", "", None,
                                                              Policy()),
                            computers=[])
    mf.mark_host("ws01.corp.local", status="done", shares_done=["IT"])
    mf.save()
    return run


def test_runs_list_prints_resumable_hint(tmp_path, capsys):
    from credshrike.cli import cmd_runs_list
    run = _interrupted_run(tmp_path)
    ns = SimpleNamespace(audit_dir=str(tmp_path))
    cmd_runs_list(ns)
    out = capsys.readouterr().out
    assert "domain_20261112T101010Z" in out
    assert "1/2" in out and "resumable" in out
    assert f"--resume {run}" in out and "--resume latest" in out


def test_resume_latest_picks_newest_resumable(tmp_path):
    from credshrike.agent.cli_agent import _resolve_latest_resume
    run = _interrupted_run(tmp_path)
    assert _resolve_latest_resume(str(tmp_path)) == str(run)

    # everything complete -> nothing resumable
    from credshrike.runstate import RunManifest
    mf = RunManifest.load(str(run))
    mf.mark_host("ws02.corp.local", status="done")
    mf.mark_complete()
    with pytest.raises(SystemExit, match="no resumable runs"):
        _resolve_latest_resume(str(tmp_path))


def test_fresh_sweep_echoes_resume_hint(tmp_path, fake_smb):
    lines = []
    _sweep(tmp_path, _client_factory_for_hosts({}), echo=lines.append)
    assert any("--resume" in l and "domain_" in l for l in lines)
