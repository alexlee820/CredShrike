"""full-domain orchestrator tests: fan-out, merge, reachability, budget gate."""

import json
import os
from types import SimpleNamespace

import pytest

from credshrike.agent.orchestrator import merge_findings, run_domain_sweep
from credshrike.config import Policy
from credshrike.credentials import Credential
from credshrike.domain.base import ComputerRecord


def _client_factory_for_hosts(hosts_findings: dict):
    """Fake client that handles ALL call types in the per-share architecture.
    Detects call type by inspecting the last user message:
    - extraction (mentions 'findings' + 'JSON') → returns findings JSON
    - summary (mentions 'Summarize') → returns summary text
    - analysis (anything else) → returns generic report text
    Findings queue is consumed in order for extraction calls."""
    findings_queue = [f for host_fl in hosts_findings.values() for f in host_fl]
    state = {"goals": [], "total_calls": 0}

    def factory():
        class Msgs:
            def create(self, **kw):
                state["total_calls"] += 1
                messages = kw.get("messages", [])
                if messages:
                    last_content = messages[-1].get("content", "")
                    text = str(last_content) if isinstance(last_content, str) else \
                           " ".join(getattr(b, "text", "") for b in last_content)
                else:
                    text = ""

                # Extraction call — serve all findings (double-pass union dedupes)
                if "JSON" in text and "findings" in text.lower():
                    if findings_queue:
                        payload = json.dumps({"findings": findings_queue})
                    else:
                        payload = json.dumps({"findings": []})
                    return SimpleNamespace(stop_reason="end_turn",
                                           content=[SimpleNamespace(type="text", text=payload)])

                # Checklist corrective call
                if "checklist" in text.lower() and "INCOMPLETE" in text:
                    return SimpleNamespace(stop_reason="end_turn",
                                           content=[SimpleNamespace(
                                               type="text",
                                               text="FILE: f0.txt | VERDICT: CLEAN\nFILE: f1.txt | VERDICT: CLEAN")])

                # Summary call
                if "Summarize" in text or "summary" in text.lower():
                    return SimpleNamespace(stop_reason="end_turn",
                                           content=[SimpleNamespace(
                                               type="text", text="Summary: credentials found.")])

                # Analysis call — capture the goal
                state["goals"].append(messages)
                return SimpleNamespace(stop_reason="end_turn",
                                       content=[SimpleNamespace(
                                           type="text", text="share analysis report")])
        return SimpleNamespace(messages=Msgs())

    factory.state = state
    return factory


@pytest.fixture
def fake_smb(monkeypatch):
    from test_agent import FakeSMB
    fake = FakeSMB()
    import credshrike.agent.session as session_mod
    monkeypatch.setattr(session_mod.AgentSession, "smb",
                        lambda self, host: fake)
    return fake


def _computers():
    return [ComputerRecord(cn="WS01", dns_name="ws01.corp.local"),
            ComputerRecord(cn="WS02", dns_name="ws02.corp.local"),
            ComputerRecord(cn="WS03", dns_name="ws03.corp.local")]


def _credential():
    return Credential.from_args("password", "svc", "corp.local", password="pw")


def test_domain_sweep_merges_and_skips(tmp_path, fake_smb):
    findings_ws01 = [{"severity": "high", "category": "credential", "host": "ws01",
                      "share": "IT", "path": "a.ps1", "username": "svc",
                      "secret": "SamePass1", "evidence": "read a.ps1", "note": ""},
                     {"severity": "low", "category": "other", "host": "ws01",
                      "share": "IT", "path": "x", "username": None, "secret": None,
                      "evidence": "e", "note": "info"}]
    findings_ws03 = [{"severity": "medium", "category": "credential", "host": "ws03",
                      "share": "Data", "path": "b.csv", "username": "svc",
                      "secret": "SamePass1",          # SAME pair on another host
                      "evidence": "read b.csv", "note": ""},
                     {"severity": "high", "category": "credential", "host": "ws03",
                      "share": "Data", "path": "c.txt", "username": "other",
                      "secret": "Pass2", "evidence": "c", "note": ""}]
    factory = _client_factory_for_hosts({
        "ws01.corp.local": findings_ws01,
        "ws03.corp.local": findings_ws03,     # ws02 unreachable -> never swept
    })
    lines = []
    result = run_domain_sweep(
        credential=_credential(), policy=Policy(), audit_dir=str(tmp_path),
        client_factory=factory, echo=lines.append,
        source_override=_computers,
        reachable_check=lambda host: host != "ws02.corp.local")

    statuses = {h["host"]: h["status"] for h in result["hosts"]}
    assert statuses["ws02.corp.local"] == "unreachable"
    assert statuses["ws01.corp.local"] == "done"
    assert statuses["ws03.corp.local"] == "done"
    # the dump is DETERMINISTIC: the model's goal contains real file content
    for host_messages in factory.state["goals"]:
        goal_text = str(host_messages[0]["content"])
        assert "SHARE" in goal_text and "ABC" in goal_text   # real content present
    # findings were produced (cross-host merge tested in test_merge_findings_unit)
    assert len(result["merged"]["credentials"]) >= 1
    assert len(result["hosts"][0]["findings"]) > 0 or len(result["hosts"][2]["findings"]) > 0
    # index + per-host reports written
    assert os.path.exists(result["index_html"])
    done_hosts = [h for h in result["hosts"] if h["html"]]
    for h in done_hosts:
        assert os.path.exists(os.path.join(result["run_dir"], h["html"]))
    index = open(result["index_html"], encoding="utf-8").read()
    assert "Coverage matrix" in index and "hostFilter" in index
    assert "ws02.corp.local" in index and "unreachable" in index
    assert any("unreachable" in l for l in lines)


def test_domain_sweep_budget_gate(tmp_path, fake_smb):
    policy = Policy()
    policy.max_total_read_bytes = 10     # first host's share dump exhausts it
    result = run_domain_sweep(
        credential=_credential(), policy=policy, audit_dir=str(tmp_path),
        client_factory=_client_factory_for_hosts({
            "ws01.corp.local": [], "ws02.corp.local": []}),
        echo=lambda l: None, source_override=_computers,
        reachable_check=lambda host: True)
    statuses = {h["host"]: h["status"] for h in result["hosts"]}
    # first host may error (dump consumed all budget → truncated but attempted)
    # remaining hosts are skipped at the gate
    assert statuses["ws02.corp.local"] == "skipped-budget"
    assert statuses["ws03.corp.local"] == "skipped-budget"


def test_merge_findings_unit():
    merged = merge_findings([
        {"severity": "low", "category": "credential", "host": "a", "share": "s",
         "path": "p1", "username": "u", "secret": "x", "evidence": "e1", "note": ""},
        {"severity": "high", "category": "credential", "host": "b", "share": "s",
         "path": "p2", "username": "u", "secret": "x", "evidence": "e2", "note": ""},
        {"severity": "medium", "category": "weak_acl", "host": "a", "share": "s",
         "path": "p3", "username": None, "secret": None, "evidence": "e", "note": "n"},
    ])
    assert len(merged["credentials"]) == 1
    c = merged["credentials"][0]
    assert c["severity"] == "high" and len(c["locations"]) == 2
    assert len(merged["other"]) == 1


def test_resolve_preset_default_is_full_domain():
    from credshrike.agent.cli_agent import _resolve_preset
    from types import SimpleNamespace as NS
    # bare invocation -> full-domain default
    assert _resolve_preset(NS(preset=None, goal=None, repl=False)) == "full-domain"
    # explicit preset / goal / repl win
    assert _resolve_preset(NS(preset="snaffler", goal=None, repl=False)) == "snaffler"
    assert _resolve_preset(NS(preset=None, goal="find x", repl=False)) is None
    assert _resolve_preset(NS(preset=None, goal=None, repl=True)) is None


def test_dump_stats_surface_in_report(tmp_path, fake_smb):
    """The code-side dump reads EVERY file but bypasses the executor/audit —
    the report must show it explicitly or the biggest phase is invisible."""
    factory = _client_factory_for_hosts({"ws01.corp.local": []})
    result = run_domain_sweep(
        credential=_credential(), policy=Policy(), audit_dir=str(tmp_path),
        client_factory=factory, echo=lambda l: None,
        source_override=lambda: [ComputerRecord(cn="WS01", dns_name="ws01.corp.local")],
        reachable_check=lambda host: True)
    entry = result["hosts"][0]
    assert entry["dump_stats"]["files_dumped"] > 0        # FakeSMB dumps its files
    report = open(os.path.join(result["run_dir"], entry["html"]), encoding="utf-8").read()
    assert "Code-side dump (full-domain)" in report
    assert f"files read <b>{entry['dump_stats']['files_dumped']}</b>" in report


def test_parallel_sweep_preserves_order_and_completes(tmp_path, fake_smb):
    """concurrency=2 sweeps hosts in parallel; results still come back in
    host order regardless of completion order."""
    import time as _time

    def slow_factory_wrapper():
        # make later hosts finish FIRST to test order restoration
        call_count = slow_factory_wrapper.n = getattr(slow_factory_wrapper, "n", 0) + 1
        n = call_count

        class SlowMsgs:
            def create(self, **kw):
                # first host's client is slower (sleeps), so host 2 finishes first
                if n == 1:
                    _time.sleep(0.3)
                return SimpleNamespace(stop_reason="end_turn",
                                       content=[SimpleNamespace(type="text", text=f"ok{n}")])
        return SimpleNamespace(messages=SlowMsgs())

    lines = []
    result = run_domain_sweep(
        credential=_credential(), policy=Policy(), audit_dir=str(tmp_path),
        client_factory=slow_factory_wrapper, echo=lines.append,
        source_override=_computers,
        reachable_check=lambda host: True,
        concurrency=2)
    statuses = {h["host"]: h["status"] for h in result["hosts"]}
    assert all(s == "done" for s in statuses.values())       # all 3 swept
    order = [h["host"] for h in result["hosts"]]
    expected = ["ws01.corp.local", "ws02.corp.local", "ws03.corp.local"]
    assert order == expected                                  # host order preserved
    assert "concurrency=2" in "".join(lines)                  # echo mentions it
    # index generated with all hosts
    assert os.path.exists(result["index_html"])
