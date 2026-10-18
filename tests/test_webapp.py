"""Web UI tests via the Flask test client + a scripted fake LLM (no key)."""

import json
import threading
import time
from types import SimpleNamespace

import pytest

import smbenum.webapp as webapp
from smbenum.webapp import app


# --------------------------------------------------------------------------- #
# scripted fake client
# --------------------------------------------------------------------------- #
class SlowFakeMessages:
    """One tool_use round (slowly), then a final report."""

    def __init__(self):
        self.calls = 0
        self.requests = []          # full kwargs of every create()
        self.started = threading.Event()

    def create(self, **kw):
        self.calls += 1
        self.requests.append(kw)
        self.started.set()
        time.sleep(0.35)                       # give the test time to poll/stop
        if self.calls == 1:
            return SimpleNamespace(
                stop_reason="tool_use",
                content=[SimpleNamespace(type="tool_use", id="t1", name="smb_list_shares",
                                         input={"host": "filesrv01.corp.local"})])
        if self.calls == 2:
            return SimpleNamespace(stop_reason="end_turn",
                                   content=[SimpleNamespace(type="text", text="## report ok")])
        # calls >= 3: findings-extraction follow-up (no tools passed)
        findings_payload = json.dumps({"findings": [{
            "severity": "high", "category": "credential", "host": "filesrv01",
            "share": "IT", "path": "creds.ps1", "username": "svc",
            "secret": "pwd123", "evidence": "smb_read_file", "note": ""}]})
        return SimpleNamespace(
            stop_reason="end_turn",
            content=[SimpleNamespace(type="text", text=findings_payload)])


@pytest.fixture
def fake_client(monkeypatch):
    shared = SimpleNamespace(messages=SlowFakeMessages())

    def factory():
        return shared
    monkeypatch.setattr(webapp, "_client_factory", factory)
    # agent sessions must not really touch SMB: reuse the test FakeSMB
    from test_agent import FakeSMB
    fake_smb = FakeSMB()

    import smbenum.agent.session as session_mod
    original = session_mod.AgentSession.smb

    def patched(self, host):
        return fake_smb
    monkeypatch.setattr(session_mod.AgentSession, "smb", patched)
    yield shared
    session_mod.AgentSession.smb = original


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _params(**over):
    base = {"preset": "", "goal": "check shares", "host": "filesrv01.corp.local",
            "auth_type": "password", "username": "jdoe", "domain": "corp.local",
            "password": "pw", "audit_dir": "runs_test"}
    base.update(over)
    return base


def _wait_status(client, run_id, statuses, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = client.get(f"/api/runs/{run_id}").get_json()
        if s["status"] in statuses:
            return s
        time.sleep(0.1)
    return s


def test_run_lifecycle_with_report(client, fake_client):
    r = client.post("/api/runs", json=_params()).get_json()
    run_id = r["id"]
    s = _wait_status(client, run_id, {"done", "error"})
    assert s["status"] == "done", s.get("error")
    assert "report ok" in s["report"]
    # live lines captured the tool call echo
    assert any("smb_list_shares" in l for l in s["lines"])
    # context is redacted-safe (no password anywhere)
    assert "pw" not in __import__("json").dumps(s["context"])
    # budget snapshot present
    assert s["budget"]["tool_calls"] == 1
    # HTML report generated and served, with the extracted credential
    assert s["report_html"], "report_html path missing"
    page = client.get(f"/api/runs/{run_id}/report_html")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    assert "Credentials" in body and "svc" in body and "pwd123" in body
    assert "data-real" in body                     # secret masked until reveal


def test_followup_goal_reuses_session(client, fake_client):
    run_id = client.post("/api/runs", json=_params()).get_json()["id"]
    _wait_status(client, run_id, {"done", "error"})
    ok = client.post(f"/api/runs/{run_id}/goal", json={"goal": "now finance"}).get_json()
    assert ok["ok"] is True
    s = _wait_status(client, run_id, {"done", "error"}, timeout=8)
    assert s["status"] == "done"
    assert fake_client.messages.calls >= 3      # conversation continued, not reset


def test_stop_mid_run(client, fake_client):
    run_id = client.post("/api/runs", json=_params()).get_json()["id"]
    # wait for the first API call to start, then stop
    deadline = time.time() + 5
    while time.time() < deadline:
        s = client.get(f"/api/runs/{run_id}").get_json()
        if s["status"] == "running":
            break
        time.sleep(0.05)
    client.post(f"/api/runs/{run_id}/stop")
    s = _wait_status(client, run_id, {"stopped", "done", "error"})
    assert s["status"] in ("stopped", "done")   # stop lands between turns


def test_snaffler_preset_goal(client, fake_client):
    run_id = client.post("/api/runs", json=_params(preset="snaffler", goal="")).get_json()["id"]
    s = _wait_status(client, run_id, {"done", "error"})
    assert s["status"] == "done", s.get("error")
    # the preset goal text actually reached the LLM as the first user message
    requests = fake_client.messages.requests
    assert requests, "fake client saw no requests"
    first_user = requests[0]["messages"][0]
    assert "credential sweep" in str(first_user.get("content", ""))


def test_unknown_run_404(client):
    assert client.get("/api/runs/nope").status_code == 404


def test_index_served(client):
    html = client.get("/").get_data(as_text=True)
    assert "smbenum" in html and "Start run" in html


# --------------------------------------------------------------------------- #
# custom Anthropic-compatible endpoints (GLM / DeepSeek)
# --------------------------------------------------------------------------- #
def test_build_client_routes_to_custom_endpoint():
    client = webapp._build_client({"api_base_url": "https://api.deepseek.com/anthropic",
                                   "api_key": "sk-test"})
    assert "deepseek" in str(client.base_url)
    assert client.api_key == "sk-test"
    # explicit override beats any ANTHROPIC_BASE_URL the environment carries
    # (e.g. a GLM/z.ai endpoint configured for Claude Code)
    import os
    if os.environ.get("ANTHROPIC_BASE_URL"):
        assert "deepseek" not in os.environ["ANTHROPIC_BASE_URL"]


def test_loop_omits_thinking_when_off():
    from smbenum.config import Policy
    from smbenum.agent.audit import AuditLog
    from smbenum.agent.session import AgentSession
    from smbenum.agent.loop import AgentLoop
    from smbenum.credentials import Credential
    import tempfile, pathlib
    policy = Policy()
    policy.thinking_mode = "off"
    audit = AuditLog(str(pathlib.Path(tempfile.mkdtemp()) / "a.jsonl"))
    session = AgentSession(Credential.from_args("password", "u", "d", password="p"),
                           policy, audit)

    class One:
        def create(self, **kw):
            One.kwargs = kw
            return SimpleNamespace(stop_reason="end_turn",
                                   content=[SimpleNamespace(type="text", text="ok")])

    loop = AgentLoop(SimpleNamespace(messages=One()), session, policy, audit)
    loop.run("hi")
    assert "thinking" not in One.kwargs
    assert One.kwargs["model"] == policy.model
    session.close()


def test_custom_endpoint_disables_thinking_by_default():
    from smbenum.config import Policy
    policy = Policy()
    webapp._apply_policy_overrides(policy, {"api_base_url": "https://x.example/anthropic"})
    assert policy.thinking_mode == "off"                    # auto-off on custom endpoint
    policy2 = Policy()
    webapp._apply_policy_overrides(policy2, {"api_base_url": "https://x/anthropic",
                                             "thinking_mode": "adaptive"})
    assert policy2.thinking_mode == "adaptive"              # explicit choice wins
    policy3 = Policy()
    webapp._apply_policy_overrides(policy3, {})
    assert policy3.thinking_mode == "adaptive"              # official API unchanged
