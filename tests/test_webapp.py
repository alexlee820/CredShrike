"""Web UI tests via the Flask test client + a scripted fake LLM (no key)."""

import json
import threading
import time
from types import SimpleNamespace

import pytest

import credshrike.webapp as webapp
from credshrike.webapp import app


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

    import credshrike.agent.session as session_mod
    original = session_mod.AgentSession.smb

    def patched(self, host):
        return fake_smb
    monkeypatch.setattr(session_mod.AgentSession, "smb", patched)
    # _dump_single_share builds its pool via a function-local
    # create_smb_session import — patch the module symbol so no test ever
    # attempts a real SMB handshake against a resolvable lab host
    import credshrike.smb_session as smb_mod
    def _no_real_smb(*a, **k):
        raise ConnectionError("no real SMB sessions in tests")
    monkeypatch.setattr(smb_mod, "create_smb_session", _no_real_smb)
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
    # 'regex-sweep' is the name; 'snaffler' stays as a deprecated alias
    run_id = client.post("/api/runs", json=_params(preset="regex-sweep", goal="")).get_json()["id"]
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
    assert "CredShrike" in html and "Start run" in html


# --------------------------------------------------------------------------- #
# custom Anthropic-compatible endpoints (GLM / DeepSeek)
# --------------------------------------------------------------------------- #
def test_build_client_routes_to_custom_endpoint(monkeypatch):
    # explicit override beats any ANTHROPIC_BASE_URL the environment carries
    # (e.g. a GLM/z.ai endpoint configured for Claude Code) — set it ourselves
    # instead of depending on whatever the developer's shell has exported
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://ambient.example/anthropic")
    client = webapp._build_client({"api_base_url": "https://api.deepseek.com/anthropic",
                                   "api_key": "sk-test"})
    assert "deepseek" in str(client.base_url)
    assert client.api_key == "sk-test"


def test_loop_omits_thinking_when_off():
    from credshrike.config import Policy
    from credshrike.agent.audit import AuditLog
    from credshrike.agent.session import AgentSession
    from credshrike.agent.loop import AgentLoop
    from credshrike.credentials import Credential
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
    from credshrike.config import Policy
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


def test_full_preset_single_host_via_orchestrator(client, monkeypatch):
    """'full' preset with host → orchestrator path (parallel dump + banner)"""
    import credshrike.agent.orchestrator as orch
    from test_agent import FakeSMB
    from credshrike.domain.base import ComputerRecord
    import credshrike.agent.session as session_mod
    monkeypatch.setattr(session_mod.AgentSession, "smb", lambda self, host: FakeSMB())
    monkeypatch.setattr(orch, "_port_open", lambda host, port=445, timeout=3: True)

    class Ok:
        def create(self, **kw):
            return SimpleNamespace(stop_reason="end_turn",
                                   content=[SimpleNamespace(type="text", text="ok")])
    monkeypatch.setattr(webapp, "_client_factory", lambda: SimpleNamespace(messages=Ok()))

    run_id = client.post("/api/runs", json=_params(preset="full", goal="",
                                                   host="ws01.corp.local")).get_json()["id"]
    s = _wait_status(client, run_id, {"done", "error"}, timeout=15)
    assert s["status"] == "done", s.get("error")
    assert s["report_html"], "report should be generated"


def test_full_domain_webapp_path(client, monkeypatch):
    """Regression: the web full-domain branch must import the orchestrator
    from the right package (credshrike.agent.orchestrator, not credshrike.orchestrator)."""
    import credshrike.agent.orchestrator as orch
    from test_agent import FakeSMB
    from credshrike.domain.base import ComputerRecord
    import credshrike.agent.session as session_mod
    monkeypatch.setattr(session_mod.AgentSession, "smb",
                        lambda self, host: FakeSMB())
    monkeypatch.setattr(orch, "_resolve_computers",
                        lambda *a, **k: [ComputerRecord(cn="WS01", dns_name="ws01.corp.local")])
    monkeypatch.setattr(orch, "_port_open", lambda host, port=445, timeout=3: True)

    calls = {"n": 0}

    class Ok:
        def create(self, **kw):
            calls["n"] += 1
            return SimpleNamespace(stop_reason="end_turn",
                                   content=[SimpleNamespace(type="text", text="ok")])

    monkeypatch.setattr(webapp, "_client_factory", lambda: SimpleNamespace(messages=Ok()))

    run_id = client.post("/api/runs", json=_params(preset="full-domain", goal="",
                                                   dc="dc01")).get_json()["id"]
    s = _wait_status(client, run_id, {"done", "error"}, timeout=15)
    assert s["status"] == "done", s.get("error")
    assert s["report_html"] and "index.html" in s["report_html"]
    page = client.get(f"/api/runs/{run_id}/report_html")
    assert page.status_code == 200 and "Coverage matrix" in page.get_data(as_text=True)


def test_long_debug_lines_are_capped(client, fake_client):
    """Debug-mode tool results can be 40K+ chars per line — the API must cap
    them or the polling payload kills the browser."""
    import credshrike.webapp as w
    state = w.RunState("x", {})
    state.push("x" * 40000)
    got = state.public()["lines"][0]
    assert len(got) <= 4100 and "line truncated" in got


def test_full_domain_per_host_links_served(client, monkeypatch):
    """Regression: the index's relative per-host hrefs resolve under the web
    route to /api/runs/<id>/<file> — that route must serve them."""
    import credshrike.agent.orchestrator as orch
    from test_agent import FakeSMB
    from credshrike.domain.base import ComputerRecord
    import credshrike.agent.session as session_mod
    monkeypatch.setattr(session_mod.AgentSession, "smb", lambda self, host: FakeSMB())
    monkeypatch.setattr(orch, "_resolve_computers",
                        lambda *a, **k: [ComputerRecord(cn="WS01", dns_name="ws01.corp.local")])
    monkeypatch.setattr(orch, "_port_open", lambda host, port=445, timeout=3: True)

    class Ok:
        def create(self, **kw):
            return SimpleNamespace(stop_reason="end_turn",
                                   content=[SimpleNamespace(type="text", text="ok")])
    monkeypatch.setattr(webapp, "_client_factory", lambda: SimpleNamespace(messages=Ok()))

    run_id = client.post("/api/runs", json=_params(preset="full-domain", goal="",
                                                   dc="dc01")).get_json()["id"]
    s = _wait_status(client, run_id, {"done", "error"}, timeout=15)
    assert s["status"] == "done", s.get("error")
    index = client.get(f"/api/runs/{run_id}/report_html").get_data(as_text=True)
    import re
    m = re.search(r"href='([^']+\.report\.html)'", index)
    assert m, "no per-host link found in index"
    per_host = client.get(f"/api/runs/{run_id}/{m.group(1)}")
    assert per_host.status_code == 200 and "CredShrike" in per_host.get_data(as_text=True)
    # traversal is refused
    assert client.get(f"/api/runs/{run_id}/..%5Csecret.txt").status_code in (400, 404)


def test_port_bumps_when_occupied():
    """serve() must auto-increment the port instead of dying on bind error."""
    import socket as _socket
    from credshrike.webapp import _find_free_port
    blocker = _socket.socket()
    blocker.bind(("127.0.0.1", 0))
    port = blocker.getsockname()[1]
    blocker.listen(1)
    try:
        assert _find_free_port("127.0.0.1", port) > port
        # free port requested → returned unchanged (no unnecessary bump)
        assert _find_free_port("127.0.0.1", port + 100) == port + 100
    finally:
        blocker.close()


def test_index_aliases_and_favicon(client):
    """/index.html, /ui etc. are what people type by habit — they must land on
    the UI instead of Flask's bare 404 (only / was routed)."""
    assert client.get("/").status_code == 200
    for path in ("/index.html", "/index.htm", "/ui", "/ui/"):
        r = client.get(path)
        assert r.status_code in (301, 302, 308), path
        assert r.headers["Location"].endswith("/"), path
    assert client.get("/favicon.ico").status_code == 204


def test_masking_defaults_in_ui(client):
    """Web UI opens with masking on and the two replacement domains filled."""
    html = client.get("/").get_data(as_text=True)
    for cid in ("maskPii", "maskSecrets"):
        line = next(l for l in html.splitlines() if f'id="{cid}"' in l)
        assert "checked" in line, cid
    for cid, value in (("emailDomain", "corp.local"), ("netbiosDomain", "corp")):
        line = next(l for l in html.splitlines() if f'id="{cid}"' in l)
        assert f'value="{value}"' in line, cid


def test_ui_limit_overrides():
    """The limits & budgets section maps straight onto Policy caps."""
    from credshrike.config import Policy
    p = Policy()
    webapp._apply_policy_overrides(p, {
        "max_file_bytes": 1048576, "result_char_cap": 16384,
        "dump_per_file_bytes": 65536, "dump_max_files": 2000,
        "dump_depth": 8, "max_total_read_bytes": 104857600,
        "max_tool_calls": 300, "wall_clock_seconds": 7200,
        "max_entries": 1000, "scan_max_files": 500,
        "scan_max_file_bytes": 131072})
    assert p.max_file_bytes == 1048576
    assert p.result_char_cap == 16384
    assert p.dump_per_file_bytes == 65536
    assert p.dump_max_files == 2000
    assert p.dump_depth == 8
    assert p.max_total_read_bytes == 104857600
    assert p.max_tool_calls == 300
    assert p.wall_clock_seconds == 7200
    assert p.max_entries == 1000
    assert p.scan_max_files == 500
    assert p.scan_max_file_bytes == 131072
    # blank / invalid values keep the policy default
    p2 = Policy()
    webapp._apply_policy_overrides(p2, {"max_file_bytes": "", "max_tool_calls": "x"})
    assert p2.max_file_bytes == Policy().max_file_bytes
    assert p2.max_tool_calls == Policy().max_tool_calls


def test_ui_has_limit_fields(client):
    html = client.get("/").get_data(as_text=True)
    for cid in ("policyPath", "maxFileKb", "resultCharCap", "dumpPerFileKb",
                "dumpMaxFiles", "dumpDepth", "maxReadMiB", "maxToolCalls",
                "wallClock", "maxEntries", "scanMaxFiles", "scanMaxFileKb"):
        assert f'id="{cid}"' in html, cid


def test_ui_concurrency_defaults_to_10(client):
    html = client.get("/").get_data(as_text=True)
    line = next(l for l in html.splitlines() if 'id="concurrency"' in l)
    assert 'value="10"' in line
    from credshrike.config import Policy
    p = Policy()
    webapp._apply_policy_overrides(p, {"concurrency": 10})
    assert p.read_threads == 10


def test_snaffler_alias_still_works(client, fake_client):
    run_id = client.post("/api/runs", json=_params(preset="snaffler", goal="")).get_json()["id"]
    s = _wait_status(client, run_id, {"done", "stopped", "error"}, timeout=15)
    assert s["status"] in ("done", "stopped"), s.get("error")


def test_analysis_controls_above_limits_section(client):
    """Analysis mode / Snaffler triage live in the main form, not buried in
    the collapsible limits & budgets section."""
    html = client.get("/").get_data(as_text=True)
    limits = html.index("limits &amp; budgets")
    for cid in ("analysisMode", "analysisTriage", "maxConcurrentLlm"):
        assert f'id="{cid}"' in html and html.index(f'id="{cid}"') < limits, cid


def test_logo_served(client):
    r = client.get("/logo.svg")
    assert r.status_code == 200
    assert r.content_type.startswith("image/svg")
    assert b"<svg" in r.data and b"#4da3ff" in r.data
    # the UI links it as favicon and shows it in the header
    html = client.get("/").get_data(as_text=True)
    assert 'href="/logo.svg"' in html and 'src="/logo.svg"' in html
