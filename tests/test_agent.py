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
        self.file_contents = {}   # path -> bytes; default b"ABC"

    def list_shares(self):
        return [{"name": "IT", "remark": "docs", "type": 0, "type_name": "DISK", "special": False}]

    def list_dir(self, share, path="", max_entries=200):
        return {"share": share, "path": path, "entries":
                [{"name": f"f{i}.txt", "is_dir": False, "size": 10} for i in range(max_entries)],
                "truncated": False, "total_seen": max_entries}

    def read_file(self, share, path, offset=0, max_bytes=65536):
        import base64 as _b64
        self.reads.append((share, path, offset, max_bytes))
        content = self.file_contents.get(path, b"ABC")
        return {"share": share, "path": path, "offset": offset, "size": max_bytes,
                "truncated": False, "content_b64": _b64.b64encode(content).decode()}

    def stat(self, share, path):
        size = 10 * 1024 * 1024 if path == "huge.log" else 10   # huge.log = 10 MiB
        return {"share": share, "path": path, "name": path, "is_dir": False, "size": size}

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
                     "smb_read_file", "smb_stat", "smb_get_permissions", "sid_lookup",
                     "smb_scan_share", "smb_dump_share"}
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


# --------------------------------------------------------------------------- #
# read gate: flag-but-don't-read modes
# --------------------------------------------------------------------------- #
def test_read_gate_ai_flags_token_heavy_request(session):
    session.policy.read_gate = "ai"
    session.policy.max_read_tokens = 1024        # 4 bytes/token -> >4096 bytes flagged
    reads_before = len(session.smb("x").reads)

    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "big.log",
        "max_bytes": 100000})
    assert not out["is_error"]
    assert '"flagged": true' in out["content"]
    assert "token gate" in out["content"] and "instruction" in out["content"]
    # nothing was actually read
    assert len(session.smb("x").reads) == reads_before
    # harness-side record kept
    assert len(session.flagged_files) == 1
    assert session.flagged_files[0]["estimated_tokens"] == 25000  # 100000/4
    # audit verdict is 'flagged'
    verdict = json.loads(open(session.audit.path).readlines()[-1])["verdict"]
    assert verdict == "flagged"
    # gated call still consumes a tool-call (prevents retry hammering)
    assert session.budget.tool_calls == 1


def test_read_gate_ai_allows_small_request(session):
    session.policy.read_gate = "ai"
    session.policy.max_read_tokens = 2048        # allows up to 8192 bytes
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "small.txt",
        "max_bytes": 4096})
    assert not out["is_error"] and "flagged" not in out["content"]
    assert len(session.smb("x").reads) == 1
    assert session.flagged_files == []


def test_read_gate_size_flags_oversized_file(session):
    session.policy.read_gate = "size"
    session.policy.flag_oversize_bytes = 1024 * 1024   # 1 MiB
    reads_before = len(session.smb("x").reads)

    # huge.log is 10 MiB per FakeSMB.stat -> flagged, not read
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "huge.log",
        "max_bytes": 4096})
    assert not out["is_error"]
    assert '"flagged": true' in out["content"] and "size gate" in out["content"]
    assert '"size_bytes": 10485760' in out["content"]
    assert len(session.smb("x").reads) == reads_before
    assert session.flagged_files[0]["size_bytes"] == 10485760

    # small file passes the gate and is actually read
    out2 = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "notes.txt",
        "max_bytes": 4096})
    assert "flagged" not in out2["content"]
    assert len(session.smb("x").reads) == reads_before + 1


def test_read_gate_none_by_default(session):
    # default policy: no gate, big request still executes (clamped by cap)
    session.policy.max_file_bytes = 1024
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "huge.log",
        "max_bytes": 10_000_000})
    assert "flagged" not in out["content"]
    assert session.smb("x").reads[-1][3] == 1024   # clamped, but READ


# --------------------------------------------------------------------------- #
# redaction: scrub tool results BEFORE they reach the LLM
# --------------------------------------------------------------------------- #
import base64 as _b64mod


def _decode_b64_in(content: str) -> str:
    """Pull the content_b64 value out of a rendered tool result and decode it."""
    import json as _json
    obj = _json.loads(content.split("\n[+")[0])
    return _b64mod.b64decode(obj["content_b64"]).decode("utf-8")


def test_redact_literal_masks_plain_fields(session):
    session.policy.redact_literals = ["filesrv01.corp.local"]
    out = _executor(session).execute("smb_list_shares", {"host": "filesrv01.corp.local"})
    assert "filesrv01.corp.local" not in out["content"]
    assert "[REDACTED]" in out["content"]
    assert "[+1 redaction(s) applied" in out["content"]


def test_redact_pattern_with_group_keeps_context(session):
    session.policy.redact_patterns = [r"password\s*=\s*(\S+)"]
    session.smb("x").file_contents["creds.txt"] = b"$u='svc'; password=hunter2; go"
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "creds.txt",
        "max_bytes": 4096})
    decoded = _decode_b64_in(out["content"])
    assert "password=[REDACTED]" in decoded          # key kept, value masked
    assert "hunter2" not in decoded and "hunter2" not in out["content"]
    assert "$u='svc'" in decoded                     # rest of content untouched


def test_redact_applies_inside_base64_file_content(session):
    # file contents travel base64 — the scrubber must decode/re-encode
    session.policy.redact_literals = ["Azrael-Key-77"]
    session.smb("x").file_contents["note.txt"] = b"token: Azrael-Key-77 end"
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "note.txt",
        "max_bytes": 1024})
    assert "Azrael-Key-77" not in out["content"]     # not even in b64 form
    assert _decode_b64_in(out["content"]) == "token: [REDACTED] end"


def test_redaction_counted_in_audit_and_session(session):
    session.policy.redact_literals = ["hunter2"]
    session.smb("x").file_contents["c.txt"] = b"a hunter2 b hunter2"
    _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "c.txt", "max_bytes": 512})
    last = json.loads(open(session.audit.path).readlines()[-1])
    assert last["redactions"] == 2
    assert session.redactions_applied == 2


def test_no_redact_rules_is_noop(session):
    session.smb("x").file_contents["c.txt"] = b"password=hunter2"
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "c.txt", "max_bytes": 512})
    assert "hunter2" not in out["content"]           # it's base64, still not plaintext
    assert _decode_b64_in(out["content"]) == "password=hunter2"
    assert session.redactions_applied == 0
    assert "redactions" not in json.loads(open(session.audit.path).readlines()[-1])


# --------------------------------------------------------------------------- #
# domain source selection (session default vs per-call override)
# --------------------------------------------------------------------------- #
def test_domain_source_session_default_and_override(session):
    from smbenum.domain.base import ComputerRecord
    captured = {}

    class FakeSource:
        name = "fake"

        def list_computers(self, filter_ext="", attrs=None):
            return [ComputerRecord(cn="WS01")]

    def fake_directory(source="auto"):
        captured["source"] = source
        return FakeSource()

    session.directory = fake_directory

    from smbenum.agent.tools import REGISTRY
    tool = REGISTRY["domain_list_computers"]
    # no per-call source -> session default (e.g. adws chosen in UI/CLI)
    session.domain_source = "adws"
    out = tool.handler(session, {})
    assert captured["source"] == "adws" and out["source"] == "fake"
    # per-call choice wins over the session default
    tool.handler(session, {"source": "ldap"})
    assert captured["source"] == "ldap"


# --------------------------------------------------------------------------- #
# AI transcript capture (for the HTML report)
# --------------------------------------------------------------------------- #
def test_loop_captures_transcript(session):
    client = SimpleNamespace(messages=FakeMessages([
        SimpleNamespace(stop_reason="tool_use",
                        content=[_text("starting with shares"),
                                 _tool_use("t1", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"})]),
        SimpleNamespace(stop_reason="end_turn", content=[_text("## final report")]),
    ]))
    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(client, session, session.policy, session.audit)
    loop.run("check the shares")

    kinds = [e["kind"] for e in loop.transcript]
    assert kinds == ["goal", "assistant", "tool_results", "assistant"]
    assert loop.transcript[0]["text"] == "check the shares"
    first = loop.transcript[1]
    assert first["text"] == "starting with shares"
    assert first["tools"] == [{"name": "smb_list_shares",
                               "input": {"host": "filesrv01.corp.local"}}]
    res = loop.transcript[2]["items"][0]
    assert res["name"] == "smb_list_shares" and res["ok"] and res["chars"] > 0
    assert loop.transcript[3]["text"] == "## final report"


def test_registry_includes_dump_tool():
    assert "smb_dump_share" in REGISTRY
    assert REGISTRY["smb_dump_share"].char_cap == 40000


def test_dump_tool_char_cap_overrides_policy(session):
    # policy cap 300 would truncate any dump page; the tool's 40K cap wins
    session.policy.result_char_cap = 300
    session.smb("x").file_contents["big.txt"] = b"z" * 3000
    out = _executor(session).execute("smb_read_file", {
        "host": "filesrv01.corp.local", "share": "IT", "path": "big.txt",
        "max_bytes": 4096})
    assert "[TRUNCATED" in out["content"]          # normal tool: policy cap applies
    out2 = _executor(session).execute("smb_dump_share", {
        "host": "filesrv01.corp.local", "share": "IT"})
    assert "[TRUNCATED" not in out2["content"]     # dump tool: 40K cap applies


def test_debug_mode_captures_and_echoes_full_results(session):
    session.policy.debug = True
    echo_lines = []
    client = SimpleNamespace(messages=FakeMessages([
        SimpleNamespace(stop_reason="tool_use",
                        content=[_tool_use("t1", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"})]),
        SimpleNamespace(stop_reason="end_turn", content=[_text("done")]),
    ]))
    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(client, session, session.policy, session.audit,
                     echo=echo_lines.append)
    loop.run("check")

    # full result stashed harness-side
    assert len(session.debug_results) == 1
    d = session.debug_results[0]
    assert d["tool"] == "smb_list_shares" and "IT" in d["content"] and d["chars"] > 0
    # echo included the full result block
    assert any(l.startswith("  ▼ smb_list_shares result:") and '"name": "IT"' in l
               for l in echo_lines)


def test_debug_off_captures_nothing(session):
    assert not session.policy.debug
    _executor(session).execute("smb_list_shares", {"host": "filesrv01.corp.local"})
    assert session.debug_results == []


# --------------------------------------------------------------------------- #
# context-window management
# --------------------------------------------------------------------------- #
def _resp(text, input_tokens=0):
    return SimpleNamespace(stop_reason="end_turn",
                           content=[_text(text)],
                           usage=SimpleNamespace(input_tokens=input_tokens,
                                                 output_tokens=10))


def test_context_tracking_and_ratio_compaction(session):
    session.policy.context_token_limit = 1000
    session.policy.compact_at_ratio = 0.5
    session.policy.compact_keep_recent = 2
    big = "x" * 2000
    client = SimpleNamespace(messages=FakeMessages([
        SimpleNamespace(stop_reason="tool_use", usage=SimpleNamespace(input_tokens=100, output_tokens=5),
                        content=[_tool_use("t1", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"})]),
        # second call reports 600 input tokens -> over 50% of 1000 -> compact
        _resp("final", input_tokens=600),
    ]))
    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(client, session, session.policy, session.audit,
                     echo=lambda l: None)
    # seed one old tool_result big enough to be compacted (protect last 2 msgs)
    loop.messages = [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t-old", "content": big}]}]
    loop.run("go")
    assert loop.context_tokens == 600
    assert loop._compactions == 1
    old = loop.messages[0]["content"][0]
    assert old["content"].startswith("[compacted: was 2000 chars")
    assert old["tool_use_id"] == "t-old"          # pairing structure intact


def test_context_overflow_self_heals(session):
    calls = {"n": 0}

    class Heal:
        def create(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("Error code: 400 - prompt is too long for this model")
            return _resp("recovered", input_tokens=100)

    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(SimpleNamespace(messages=Heal()), session, session.policy,
                     session.audit, echo=lambda l: None)
    loop.messages = [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t-old", "content": "y" * 5000}]}]
    out = loop.run("go")
    assert out == "recovered" and calls["n"] == 2
    assert loop._compactions == 1                 # compacted once, then retried


def test_goal_survives_compaction(session):
    # goals are STRING user messages — compaction must never touch them
    session.policy.context_token_limit = 1000
    session.policy.compact_at_ratio = 0.1
    session.policy.compact_keep_recent = 1
    client = SimpleNamespace(messages=FakeMessages([
        SimpleNamespace(stop_reason="tool_use", usage=SimpleNamespace(input_tokens=50, output_tokens=5),
                        content=[_tool_use("t1", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"})]),
        _resp("mid", input_tokens=500),
        SimpleNamespace(stop_reason="tool_use", usage=SimpleNamespace(input_tokens=600, output_tokens=5),
                        content=[_tool_use("t2", "smb_list_shares",
                                           {"host": "filesrv01.corp.local"})]),
        _resp("final", input_tokens=900),
    ]))
    from smbenum.agent.loop import AgentLoop
    loop = AgentLoop(client, session, session.policy, session.audit, echo=lambda l: None)
    out = loop.run("FIND THE GOLDEN PASSWORD")
    assert out == "final"
    assert loop.messages[0] == {"role": "user", "content": "FIND THE GOLDEN PASSWORD"}
    assert loop._compactions >= 1
    # aggressive escalation: second overflow clears even recent results
    loop._compact(aggressive=True)
    leftover = [b for m in loop.messages if isinstance(m.get("content"), list)
                for b in m["content"]
                if b.get("type") == "tool_result" and len(b.get("content", "")) > 200]
    assert leftover == []          # everything compacted...
    assert loop.messages[0]["content"] == "FIND THE GOLDEN PASSWORD"   # ...except the goal
