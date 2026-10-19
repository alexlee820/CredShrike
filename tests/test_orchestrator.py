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
    """factory() is called TWICE per host: loop client (the dump is ALREADY
    embedded in the goal — model can answer immediately), then extraction
    client (findings JSON). Even calls pop the next host."""
    queue = list(hosts_findings.items())
    state = {"last": None, "goals": []}

    def factory():
        class LoopMsgs:
            def create(self, **kw):
                state["goals"].append(kw.get("messages"))
                return SimpleNamespace(stop_reason="end_turn",
                                       content=[SimpleNamespace(
                                           type="text", text=f"report for {host}")])

        class ExtractMsgs:
            def create(self, **kw):
                payload = json.dumps({"findings": findings})
                return SimpleNamespace(
                    stop_reason="end_turn",
                    content=[SimpleNamespace(type="text", text=payload)])

        if state["last"] is None:
            host, findings = queue.pop(0)
            state["last"] = (host, findings)
            return SimpleNamespace(messages=LoopMsgs())
        host, findings = state["last"]
        state["last"] = None
        return SimpleNamespace(messages=ExtractMsgs())

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
    assert statuses == {"ws01.corp.local": "done", "ws02.corp.local": "unreachable",
                        "ws03.corp.local": "done"}
    # the dump is DETERMINISTIC and embedded: the model's first message (the
    # goal) already contains the host's actual file contents, and the model
    # never had to call a dump tool (zero tool calls per host)
    for host_messages in factory.state["goals"]:
        goal_text = str(host_messages[0]["content"])
        assert "COMPLETE deterministic content dump" in goal_text
        assert "=== SHARE IT (" in goal_text and "ABC" in goal_text  # real content
    assert all(h["tool_calls"] == 0 for h in result["hosts"])
    # cross-host merge: SamePass1 (svc) collapsed to ONE credential, 2 locations
    creds = result["merged"]["credentials"]
    same = next(c for c in creds if c["secret"] == "SamePass1")
    assert same["severity"] == "high"                     # max severity wins
    assert {(l["host"], l["path"]) for l in same["locations"]} == \
        {("ws01", "a.ps1"), ("ws03", "b.csv")}
    assert len(creds) == 2 and len(result["merged"]["other"]) == 1
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
    policy.max_total_read_bytes = 10     # first host's dump exhausts it
    result = run_domain_sweep(
        credential=_credential(), policy=policy, audit_dir=str(tmp_path),
        client_factory=_client_factory_for_hosts({
            "ws01.corp.local": [], "ws02.corp.local": []}),
        echo=lambda l: None, source_override=_computers,
        reachable_check=lambda host: True)
    statuses = {h["host"]: h["status"] for h in result["hosts"]}
    assert statuses["ws01.corp.local"] == "done"
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
