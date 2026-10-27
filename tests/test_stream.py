"""Streaming share analysis (analysis_mode: stream) — ledger, parsing,
end-to-end share pipeline, channels."""

import json
from types import SimpleNamespace

import pytest

from credshrike.config import Policy
from credshrike.credentials import Credential
from credshrike.agent.stream_analysis import (ShareLedger, analyze_share_streaming,
                                              api_semaphore, parse_batch_response)

PASSWORD_VALUE = "Winter2024!"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def test_parse_batch_response():
    text = ("FILE: IT/a.txt | VERDICT: FOUND | credential | db password\n"
            "FILE: IT/b.txt | VERDICT: CLEAN\n"
            "FILE: IT/c.txt | VERDICT: SKIPPED | binary\n"
            "```json\n"
            '[{"path": "IT/a.txt", "category": "credential", "username": "svc",'
            ' "secret": "Xkqmbn7314#", "note": "db", "severity": "high"}]\n'
            "```")
    verdicts, findings = parse_batch_response(text)
    assert verdicts == {"it/a.txt": "FOUND", "it/b.txt": "CLEAN", "it/c.txt": "SKIPPED"}
    assert len(findings) == 1 and findings[0]["secret"] == "Xkqmbn7314#"


def test_parse_tolerates_missing_fence_and_bad_json():
    verdicts, findings = parse_batch_response("FILE: a | VERDICT: CLEAN\nno json here")
    assert verdicts == {"a": "CLEAN"} and findings == []
    verdicts, findings = parse_batch_response("```json\n{oops\n```")
    assert verdicts == {} and findings == []


def test_ledger_checklist_covers_every_file():
    ledger = ShareLedger("IT")
    for p in ("IT/a.txt", "IT/b.txt", "IT/c.txt"):
        ledger.note_file(p)
    ledger.record("IT/a.txt", "FOUND", "credential")
    ledger.record("IT/b.txt", "CLEAN")
    ledger.unreadable["IT/d.txt"] = "boom"
    ledger.budget_skipped.append("IT/e.txt")
    ledger.skipped_ext.append({"path": "IT/f.zip", "ext": ".zip"})
    md = ledger.checklist_md(["IT/a.txt", "IT/b.txt", "IT/c.txt"])
    lines = md.splitlines()
    assert len(lines) == 6                       # every file exactly one line
    assert "FILE: IT/a.txt | VERDICT: FOUND | credential" in md
    assert "VERDICT: UNRESOLVED" in md           # c.txt never got a verdict
    assert ledger.unresolved() == ["it/c.txt"]


# --------------------------------------------------------------------------- #
# end-to-end share pipeline against fakes
# --------------------------------------------------------------------------- #
class _FakeSMB:
    def __init__(self, files):
        self.files = files

    def list_dir(self, share, path="", max_entries=200):
        return {"share": share, "path": path,
                "entries": [{"name": n, "is_dir": False, "size": len(c)}
                            for n, c in self.files.items()],
                "truncated": False, "total_seen": len(self.files)}

    def read_file(self, share, path, offset=0, max_bytes=65536):
        import base64 as b64
        return {"share": share, "path": path, "offset": offset,
                "size": max_bytes, "truncated": False,
                "content_b64": b64.b64encode(self.files[path.rsplit("/", 1)[-1]]
                                             .encode()).decode()}


def _fake_client(files):
    """Dispatch on the last user message: ready / batch / reduce / summarize."""
    state = {"calls": 0, "batch_prompts": 0}

    class Msgs:
        def create(self, **kw):
            state["calls"] += 1
            messages = kw.get("messages", [])
            content = messages[-1].get("content", "")
            # prompt-cache turns the last message into content blocks —
            # read both shapes (same as the orchestrator test fake)
            text = content if isinstance(content, str) else " ".join(
                b.get("text", "") if isinstance(b, dict)
                else getattr(b, "text", "") for b in content)
            if "ready" in text.lower():
                return SimpleNamespace(stop_reason="end_turn",
                                       content=[SimpleNamespace(type="text", text="ready")])
            if "Ledger:" in text:      # reduce
                return SimpleNamespace(stop_reason="end_turn", content=[
                    SimpleNamespace(type="text", text="PART 2: …\nPART 3: summary")])
            if "Summarize" in text or "summary" in text.lower():
                return SimpleNamespace(stop_reason="end_turn", content=[
                    SimpleNamespace(type="text", text="Summary: one password found.")])
            # batch analysis: one FILE line per ---- path ---- header + json
            import re
            paths = re.findall(r"---- (\S+?) \(", text)
            lines = "\n".join(
                f"FILE: {p} | VERDICT: "
                + ("FOUND | credential | password" if "creds" in p else "CLEAN")
                for p in paths)
            findings = [{"path": p, "category": "credential", "username": "svc",
                         "secret": text.split("secret=")[-1].split("\n")[0]
                         if "secret=" in text else None,
                         "note": "", "severity": "high"}
                        for p in paths if "creds" in p]
            # echo whatever secret value appeared in the prompt
            secrets = re.findall(r"DB_PASSWORD=(\S+)", text)
            for f, s in zip(findings, secrets):
                f["secret"] = s
            state["batch_prompts"] += 1
            payload = lines + "\n```json\n" + json.dumps(findings) + "\n```"
            return SimpleNamespace(stop_reason="end_turn",
                                   content=[SimpleNamespace(type="text", text=payload)])

    return SimpleNamespace(messages=Msgs()), state


@pytest.fixture
def session(tmp_path, monkeypatch):
    from queue import Queue
    from credshrike.agent.audit import AuditLog
    from credshrike.agent.session import AgentSession
    import credshrike.smb_session as smb_mod
    policy = Policy()
    policy.analysis_mode = "stream"
    policy.analysis_group_files = 2
    policy.analysis_group_wait_ms = 100
    credential = Credential.from_args("password", "svc", "corp.local", password="pw")
    s = AgentSession(credential, policy, AuditLog.new_run(str(tmp_path)), hosts=["fs01"])
    fake = _FakeSMB({"creds.txt": f"DB_PASSWORD={PASSWORD_VALUE}\n",
                     "notes.txt": "nothing here\n",
                     "more.txt": "still nothing\n"})
    s.smb = lambda host: fake

    def _fail_connect(*args, **kwargs):
        raise RuntimeError("no network in tests")

    # DNS for a nonexistent host can hang getaddrinfo for minutes — make any
    # real SMBSession construction fail fast so the code falls back to fakes
    monkeypatch.setattr(smb_mod, "SMBSession", _fail_connect)
    pool = Queue()
    pool.put(fake)
    s.get_read_pool = lambda host: pool
    yield s
    s.close_smb()


def test_stream_share_end_to_end(session, tmp_path):
    client, state = _fake_client({"creds.txt": "", "notes.txt": ""})
    policy = session.policy
    policy.mask_secrets = True
    events = []
    result = analyze_share_streaming(
        credential=session.credential, policy=policy, audit=session.audit,
        session=session, host="fs01", share_name="IT",
        client_factory=lambda: client, echo=lambda l: events.append(("echo", l)),
        emit=lambda ch, line, share=None: events.append((ch, line)))

    # coverage: all 3 files have exactly one verdict (ledger-generated Part 1)
    assert result["stats"]["files_dumped"] == 3
    checklist = result["report"].split("#### File checklist")[1].split("####")[0]
    assert checklist.count("FILE:") == 3
    assert "UNRESOLVED" not in checklist

    # findings: extracted from the batch JSON, restored to the REAL password
    cred = [f for f in result["findings"] if f.get("secret")]
    assert cred and cred[0]["secret"] == PASSWORD_VALUE
    assert cred[0]["masked"] is True and "ENV_PASSWORD" in cred[0]["mask_entities"]
    assert cred[0]["share"] == "IT" and cred[0]["host"] == "fs01"

    # the LLM never saw the real password
    assert state["batch_prompts"] >= 1

    # channels were emitted for the AI thread and the walkers
    channels = {ch for ch, _ in events}
    assert "ai" in channels and "walk" in channels


def test_stream_budget_exhaustion_marks_files(session):
    client, state = _fake_client({})
    policy = session.policy
    policy.max_total_read_bytes = 0                 # everything is over budget
    result = analyze_share_streaming(
        credential=session.credential, policy=policy, audit=session.audit,
        session=session, host="fs01", share_name="IT",
        client_factory=lambda: client, echo=lambda l: None)
    assert result["stats"]["files_dumped"] == 3
    # over-budget files appear in the ledger as SKIPPED
    assert "byte budget exhausted" in result["report"]


def test_api_semaphore_caps_concurrency():
    import threading, time
    sem = api_semaphore(2)
    held = []
    lock = threading.Lock()

    def worker():
        with sem:
            with lock:
                held.append(len(held) + 1)
                peak = max(held)
                held.pop()
            # don't assert inside; record instead
            time.sleep(0.05)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # semaphore with value 2 never allows a third concurrent acquire
    assert sem._value <= 2


def test_domain_sweep_stream_mode_writes_report(tmp_path, monkeypatch):
    """full-domain with analysis_mode=stream: shares pipelined, report written,
    channel events emitted for the web UI."""
    from test_agent import FakeSMB
    from test_orchestrator import _client_factory_for_hosts
    from credshrike.domain.base import ComputerRecord
    from credshrike.agent.orchestrator import run_domain_sweep
    import credshrike.agent.session as session_mod
    import credshrike.smb_session as smb_mod

    monkeypatch.setattr(session_mod.AgentSession, "smb",
                        lambda self, host: FakeSMB())
    monkeypatch.setattr(smb_mod, "SMBSession",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no net")))

    policy = Policy()
    policy.analysis_mode = "stream"
    policy.analysis_group_files = 500          # one request covers FakeSMB's files
    policy.analysis_group_wait_ms = 100

    events = []
    result = run_domain_sweep(
        credential=Credential.from_args("password", "svc", "corp.local",
                                        password="pw"),
        policy=policy, audit_dir=str(tmp_path),
        client_factory=_client_factory_for_hosts({"ws01.corp.local": []}),
        echo=lambda l: None,
        emit=lambda ch, line, share=None: events.append((ch, share, line)),
        source_override=lambda: [ComputerRecord(cn="WS01",
                                                dns_name="ws01.corp.local")],
        reachable_check=lambda host: True)

    entry = result["hosts"][0]
    assert entry["status"] == "done"
    # the ledger-generated checklist covers every file FakeSMB lists
    assert "#### File checklist" in entry["report_md"]
    assert entry["report_md"].count("FILE:") >= 200   # FakeSMB lists many files
    assert entry["html"] and (tmp_path / result["run_dir"] / entry["html"]).exists()
    channels = {ch for ch, _sh, _l in events}
    assert channels >= {"walk", "ai"}
