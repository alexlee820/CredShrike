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
    - analysis (contains 'FILE CHECKLIST' — the share/batch analysis prompt) →
      captures the goal, returns generic report text
    - extraction (mentions 'findings' + 'JSON') → returns findings JSON
    - corrective (mentions 'INCOMPLETE') → returns checklist lines
    - summary (the rolling-summary prompt) → returns summary text
    NOTE: analysis must be detected BEFORE summary — the analysis prompt
    also contains the word 'SUMMARY' (PART 3)."""
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

                # Analysis call — capture the goal (checked first: the
                # analysis prompt itself contains 'SUMMARY' and 'FINDINGS')
                if "FILE CHECKLIST" in text:
                    state["goals"].append(messages)
                    return SimpleNamespace(stop_reason="end_turn",
                                           content=[SimpleNamespace(
                                               type="text", text="share analysis report")])

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

                return SimpleNamespace(stop_reason="end_turn",
                                       content=[SimpleNamespace(
                                           type="text", text="")])
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


def test_parallel_file_reads_and_sequential_hosts(tmp_path, fake_smb):
    """concurrency>1 = parallel file reads within a share; hosts remain
    sequential. Verify the log mentions parallel reads and hosts complete in order."""
    lines = []
    result = run_domain_sweep(
        credential=_credential(), policy=Policy(), audit_dir=str(tmp_path),
        client_factory=_client_factory_for_hosts({"ws01.corp.local": []}),
        echo=lines.append,
        source_override=_computers,
        reachable_check=lambda host: True,
        concurrency=4)
    statuses = {h["host"]: h["status"] for h in result["hosts"]}
    assert all(s == "done" for s in statuses.values())
    order = [h["host"] for h in result["hosts"]]
    expected = ["ws01.corp.local", "ws02.corp.local", "ws03.corp.local"]
    assert order == expected    # sequential host order preserved
    assert "read_threads=4" in "".join(lines)  # log mentions parallel reads
    assert os.path.exists(result["index_html"])


def test_dump_auto_splits_into_batches(tmp_path, fake_smb):
    """A share whose dump exceeds the context budget is SPLIT into multiple
    analysis requests (fresh context window each, rolling summary between
    them) instead of truncated — every file still reaches the model."""
    big = "X" * 2000 + "\n"                      # ~2029 rendered chars per file
    fake_smb.list_dir = lambda share, path="", max_entries=200: {
        "share": share, "path": path,
        "entries": [{"name": f"big{i}.txt", "is_dir": False, "size": 2000}
                    for i in range(6)],
        "truncated": False, "total_seen": 6}
    fake_smb.file_contents = {f"big{i}.txt": big.encode() for i in range(6)}

    policy = Policy()
    policy.context_token_limit = 2800             # budget = 2800*3*0.6 = 5040
    # → 2 files per batch (~4058 chars), 6 files → exactly 3 batches
    lines = []
    factory = _client_factory_for_hosts({"ws01.corp.local": []})
    result = run_domain_sweep(
        credential=_credential(), policy=policy, audit_dir=str(tmp_path),
        client_factory=factory, echo=lines.append,
        source_override=lambda: [ComputerRecord(cn="WS01", dns_name="ws01.corp.local")],
        reachable_check=lambda host: True)

    entry = result["hosts"][0]
    assert entry["status"] == "done"
    assert entry["dump_stats"]["files_dumped"] == 6   # nothing dropped
    assert any("auto-split into 3 request(s)" in l for l in lines)

    goals = [str(m[0]["content"]) for m in factory.state["goals"]]
    assert len(goals) == 3                            # one analysis call per batch
    # each batch goal is context-sized and carries its OWN files only
    for g in goals:
        assert "BATCH" in g and "big" in g
        assert len(g) < 6000                          # fits the ~5040-char budget
    assert sum(g.count("---- big") for g in goals) == 6  # every file sent once
    # batch 2+ carries the rolling summary from batch 1 (not batch 1 itself)
    assert "MEMORY from previous batches" not in goals[0]
    assert "MEMORY from previous batches" in goals[1]
    # reports from all batches joined into one share report
    assert entry["report_md"].count("#### Batch") == 3
    assert any("batch 1/3" in l for l in lines)


def test_domain_sweep_default_threads_come_from_policy(tmp_path, fake_smb):
    """No explicit concurrency -> policy.read_threads (default 10), not 1."""
    lines = []
    policy = Policy()
    assert policy.read_threads == 10
    run_domain_sweep(
        credential=_credential(), policy=policy, audit_dir=str(tmp_path),
        client_factory=_client_factory_for_hosts({"ws01.corp.local": []}),
        echo=lines.append,
        source_override=lambda: [ComputerRecord(cn="WS01", dns_name="ws01.corp.local")],
        reachable_check=lambda host: True)
    assert any("PARALLEL FILE READS: 10" in line for line in lines)
