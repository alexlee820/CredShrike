"""Agent tests: executor guards, budget enforcement, audit trail, and the
full loop against a scripted fake Anthropic client (no network, no API key)."""

import json
import os
from types import SimpleNamespace

import pytest

from smbenum.agent.audit import AuditLog, redact
from smbenum.agent.executor import ToolExecutor, normalize_path
from smbenum.agent.session import AgentSession
from smbenum.agent.tools import REGISTRY, anthropic_tools
from smbenum.config import Policy
from smbenum.credentials import Credential


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class FakeSMB:
    def __init__(self):
        self.reads = []

    def list_shares(self):
        return [{"name": "IT", "remark": "docs", "type": 0, "type_name": "DISK", "special": False}]

    def list_dir(self, share, path="", max_entries=200):
        return {"share": share, "path": path, "entries":
                [{"name": f"f{i}.txt", "is_dir": False, "size": 10} for i in range(max_entries)],
                "truncated": False, "total_seen": max_entries}

    def read_file(self, share, path, offset=0, max_bytes=65536):
        self.reads.append((share, path, offset, max_bytes))
        return {"share": share, "path": path, "offset": offset, "size": max_bytes,
                "truncated": False, "content_b64": "QUJD"}

    def stat(self, share, path):
        return {"share": share, "path": path, "name": path, "is_dir": False, "size": 10}

    def get_security(self, share, path):
        return {"owner": "S-1-5-32-544", "group": "S-1-5-32-545",
                "dacl": {"aces": [{"type_name": "ACCESS_ALLOWED", "trustee": "S-1-1-0",
                                   "trustee_name": "Everyone", "mask": 0x89,
                                   "rights": ["FILE_READ_DATA"]}]}, "sacl": None,
                "control_flags": ["SELF_RELATIVE"]}

    def get_share_security(self, share):
        return {"share": share, "share_permissions": ["ACCESS_READ"], "sd": self.get_security(share, "")}

    def effective_access(self, share, path):
        return {"share": share, "path": path, "probes":
                {"read_data": {"allowed": True}, "write_data": {"allowed": False, "error": "denied"}}}


@pytest.fixture
def session(tmp_path):
    credential = Credential.from_args("password", "svc-scan", "corp.local", password="pw")
    policy = Policy()
    audit = AuditLog.new_run(str(tmp_path))
    s = AgentSession(credential, policy, audit, hosts=["filesrv01.corp.local"])
    fake = FakeSMB()
    s.smb = lambda host: fake  # type: ignore[method-assign]
    yield s
    s.close()


def _executor(sess):
    return ToolExecutor(sess, sess.policy, sess.audit)


# --------------------------------------------------------------------------- #
# guards
# --------------------------------------------------------------------------- #
def test_allowlist_refuses_unknown_tool(session):
    ex = _executor(session)
    out = ex.execute("smb_delete_file", {"host": "filesrv01.corp.local", "path": "x"})
    assert out["is_error"] and "not in the read-only tool registry" in out["content"]


def test_host_scope_enforced(session):
    out = _executor(session).execute("smb_list_shares", {"host": "othersrv.corp.local"})
    assert out["is_error"] and "outside session scope" in out["content"]


@pytest.mark.parametrize("bad", ["..", "../x", "a/../../b", "a\\..\\..\\c", "a/.."])
def test_traversal_rejected(bad):
    with pytest.raises(Exception):
        normalize_path(bad)


def test_normalize_path_accepts_windows_and_unix():
    assert normalize_path("IT\\Reports\\q4") == "IT/Reports/q4"
    assert normalize_path("/IT//Reports/") == "IT/Reports"
    assert normalize_path("") == ""


def test_max_bytes_clamped_to_policy(session):
    session.policy.max_file_bytes = 1024
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "a.log", "max_bytes": 10_000_000})
    assert not out["is_error"]
    # handler saw the clamped value (the fake recorded it)
    assert session.smb("x").reads[-1][3] == 1024
    # and the audit recorded the cap
    verdict = json.loads(open(session.audit.path).readlines()[-1])["verdict"]
    assert verdict == "capped"


def test_result_truncated_with_paging_marker(session):
    session.policy.result_char_cap = 200
    out = _executor(session).execute("smb_list_dir", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "", "max_entries": 100})
    assert "[TRUNCATED" in out["content"] and len(out["content"]) < 200 + 200


def test_budget_tool_calls(session):
    session.policy.max_tool_calls = 1
    ex = _executor(session)
    first = ex.execute("smb_list_shares", {"host": "filesrv01.corp.local"})
    assert not first["is_error"]
    second = ex.execute("smb_list_shares", {"host": "filesrv01.corp.local"})
    assert second["is_error"] and "budget exhausted" in second["content"]


def test_audit_redacts_sensitive_keys():
    red = redact({"path": "x", "password": "hunter2", "nested": {"aes_key": "abcd"}})
    assert red == {"path": "x", "password": "<redacted>", "nested": {"aes_key": "<redacted>"}}


# --------------------------------------------------------------------------- #
# tool registry sanity
# --------------------------------------------------------------------------- #
def test_registry_is_read_only_surface():
    names = set(REGISTRY)
    assert names == {"domain_list_computers", "smb_list_shares", "smb_list_dir",
                     "smb_read_file", "smb_stat", "smb_get_permissions", "sid_lookup"}
    specs = anthropic_tools()
    assert all(spec["input_schema"]["additionalProperties"] is False for spec in specs)
    assert all(spec["strict"] is True for spec in specs)


# --------------------------------------------------------------------------- #
# the loop, against a scripted fake client
# --------------------------------------------------------------------------- #
def _block(kind, **kw):
    return SimpleNamespace(type=kind, **kw)


def _tool_use(id_, name, input_):
    return _block("tool_use", id=id_, name=name, input=input_)


def _text(t):
    return _block("text", text=t)


class FakeMessages:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kw):
        self.calls.append(kw)
        if not self.script:
            raise AssertionError("fake client ran out of scripted responses")
        return self.script.pop(0)


def test_full_loop_with_tool_use_and_final_report(session):
    fake_smb = session.smb("seed")
    client = SimpleNamespace(messages=FakeMessages([
        SimpleNamespace(stop_reason="tool_use",
                        content=[_tool_use("t1", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"}),
                                 _tool_use("t2", "smb_get_permissions",
                                           {"host": "filesrv01.corp.local", "share": "IT"})]),
        # refused unknown tool stays in-conversation without crashing
        SimpleNamespace(stop_reason="tool_use",
                        content=[_tool_use("t3", "rm_rf", {"everything": True})]),
        SimpleNamespace(stop_reason="end_turn", content=[_text("## Findings\n- IT share exposed")]),
    ]))

    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(client, session, session.policy, session.audit)
    result = loop.run("check the IT share")

    assert result.startswith("## Findings")
    # conversation shape: user, assistant, user(tool_results), assistant, user, assistant

    def _types(content):
        if isinstance(content, str):
            return "str"
        return [b["type"] if isinstance(b, dict) else getattr(b, "type", "?")
                for b in content]

    kinds = [(m["role"], _types(m["content"])) for m in loop.messages]
    assert kinds[0] == ("user", "str")
    assert kinds[1][0] == "assistant" and "tool_use" in kinds[1][1]
    assert kinds[2][0] == "user" and kinds[2][1].count("tool_result") == 2  # ONE message, both results
    # the refused tool came back as an is_error result
    refused_msg = loop.messages[4]["content"]
    assert any(b["is_error"] if isinstance(b, dict) else getattr(b, "is_error", False)
               for b in refused_msg)

    # three tool calls audited: allowed, allowed, refused
    verdicts = [json.loads(line)["verdict"] for line in open(session.audit.path)]
    assert verdicts == ["allowed", "allowed", "refused"]
    # read budget untouched (no reads); refused calls don't consume budget
    # (2 executed: shares + permissions — rm_rf was refused before execution)
    assert session.budget.tool_calls == 2

    # request carried model + tools + thinking from policy
    last_call = client.messages.calls[0]
    assert last_call["model"] == session.policy.model
    assert last_call["thinking"] == {"type": "adaptive"}
    tool_names = {t["name"] for t in last_call["tools"]}
    assert "smb_read_file" in tool_names and "rm_rf" not in tool_names


def test_budget_exhaustion_forces_final_summary(session):
    session.policy.max_tool_calls = 1
    client = SimpleNamespace(messages=FakeMessages([
        SimpleNamespace(stop_reason="tool_use",
                        content=[_tool_use("t1", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"})]),
        # model tries a second call anyway
        SimpleNamespace(stop_reason="tool_use",
                        content=[_tool_use("t2", "smb_list_dir",
                                           {"host": "filesrv01.corp.local",
                                            "share": "IT", "path": ""})]),
        SimpleNamespace(stop_reason="end_turn", content=[_text("final partial report")]),
    ]))
    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(client, session, session.policy, session.audit)
    result = loop.run("audit everything")
    assert result == "final partial report"
    # the budget-final injection message exists
    injected = [m for m in loop.messages
                if m["role"] == "user" and isinstance(m["content"], str)
                and "Budget exhausted" in m["content"]]
    assert injected, "expected a budget-exhaustion summary request in the conversation"
    # second call was refused, not executed
    verdicts = [json.loads(line)["verdict"] for line in open(session.audit.path)]
    assert verdicts.count("refused") == 1
