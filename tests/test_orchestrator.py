"""full-domain orchestrator tests: fan-out, merge, reachability, budget gate."""

import json
import os
from types import SimpleNamespace

import pytest

from smbenum.agent.orchestrator import merge_findings, run_domain_sweep
from smbenum.config import Policy
from smbenum.credentials import Credential
from smbenum.domain.base import ComputerRecord


def _client_factory_for_hosts(hosts_findings: dict):
    """factory() is called TWICE per host: loop client (shares call + final
    report), then extraction client (findings JSON). Even calls pop the next
    host; odd calls reuse the same host's findings."""
    queue = list(hosts_findings.items())
    state = {"last": None}

    def factory():
        class LoopMsgs:
            def create(self, **kw):
                if not getattr(self, "used", False):
                    self.used = True
                    return SimpleNamespace(
                        stop_reason="tool_use",
                        content=[SimpleNamespace(type="tool_use", id="t1",
                                                 name="smb_list_shares",
                                                 input={"host": host})])
                return SimpleNamespace(stop_reason="end_turn",
                                       content=[SimpleNamespace(type="text",
                                                                text=f"report for {host}")])

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

    return factory


@pytest.fixture
def fake_smb(monkeypatch):
    from test_agent import FakeSMB
    fake = FakeSMB()
    import smbenum.agent.session as session_mod
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
    policy.max_tool_calls = 1            # first host consumes it; rest skipped
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
