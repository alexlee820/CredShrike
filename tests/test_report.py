"""HTML report + findings extraction tests."""

import json
from types import SimpleNamespace

from credshrike.agent.findings import extract_findings, _parse_findings_json
from credshrike.config import Policy
from credshrike.report import build_report_html, write_report


def _client(script: list[str]):
    """Fake client whose create() pops canned text responses."""
    queue = list(script)
    calls = []

    class Messages:
        def create(self, **kw):
            calls.append(kw)
            text = queue.pop(0)
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])

    return SimpleNamespace(messages=Messages()), calls


def test_extract_findings_plain_json():
    payload = {"findings": [{"severity": "high", "category": "credential",
                             "host": "h", "share": "IT", "path": "a.ps1",
                             "username": "svc", "secret": "pwd123",
                             "evidence": "smb_read_file", "note": ""}]}
    # two passes now run — both return the same payload, union dedupes
    client, calls = _client([json.dumps(payload), json.dumps(payload)])
    out = extract_findings(client, Policy(), [{"role": "user", "content": "go"}])
    assert out[0]["secret"] == "pwd123" and out[0]["severity"] == "high"
    assert len(out) == 1 and len(calls) == 2


def test_extract_findings_fenced_and_dirty_prose():
    fenced = "Here you go:\n```json\n{\"findings\": []}\n```\nsorry!"
    assert _parse_findings_json(fenced) == {"findings": []}
    assert _parse_findings_json('junk {"findings": [{"severity":"low"}]} junk')


def test_extract_findings_retries_on_garbage_then_succeeds():
    # pass1: garbage then good (parse retry); pass2: good directly
    good = '{"findings": [{"severity": "WEIRD", "category": "nope", "secret": "x"}]}'
    client, calls = _client(["total garbage not json", good, good])
    out = extract_findings(client, Policy(), [])
    assert out[0]["severity"] == "low"           # invalid enum sanitized
    assert out[0]["category"] == "other"


def test_report_html_contains_all_sections(tmp_path):
    audit_path = str(tmp_path / "audit.jsonl")
    with open(audit_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"tool": "smb_list_dir", "args": {"host": "h", "share": "IT",
                                                              "path": ""},
                             "verdict": "allowed", "result_chars": 10,
                             "duration_ms": 5}) + "\n")
        fh.write(json.dumps({"tool": "smb_read_file", "args": {"host": "h", "share": "IT",
                                                               "path": "creds.ps1",
                                                               "max_bytes": 4096},
                             "verdict": "capped", "result_chars": 99,
                             "duration_ms": 15}) + "\n")
    html = build_report_html(
        context={"principal": "corp\\svc", "auth_type": "password", "scope": ["h"],
                 "model": "glm-5.3", "endpoint": "api.z.ai"},
        findings=[{"severity": "high", "category": "credential", "host": "h",
                   "share": "IT", "path": "creds.ps1", "username": "svc_backup",
                   "secret": "Sup3rS3cret!", "evidence": "smb_read_file", "note": "n"}],
        scan_results=[{"matches": [{"path": "creds.ps1", "tier": "red", "line": 3,
                                    "pattern": "password_assignment",
                                    "snippet": "password = ***"}],
                       "stats": {"files_scanned": 12, "bytes_scanned": 4096}}],
        flagged=[{"host": "h", "share": "IT", "path": "big.zip", "size_bytes": 9999999,
                  "reason": "size gate", "ts": ""}],
        report_md="## Findings\n- stuff",
        audit_path=audit_path, redactions=2,
        domain_computers=[
            {"cn": "WS01", "dns_name": "ws01.corp.local", "operating_system": "Windows 11",
             "os_version": "10.0", "is_dc": False, "disabled": False, "description": "dev box"},
            {"cn": "DC01", "dns_name": "dc01.corp.local", "operating_system": "Server 2022",
             "os_version": "10.0", "is_dc": True, "disabled": False, "description": ""}],
        share_inventories={"dc01.corp.local": [
            {"name": "IT", "type_name": "DISK", "remark": "docs", "special": False},
            {"name": "IPC$", "type_name": "IPC", "remark": "", "special": True}]})
    # all sections present
    for marker in ("Credentials", "All findings", "Sweep hits", "SMB activity",
                   "Flagged files", "AI final report", "Audit trail", "creds.ps1",
                   "svc_backup", "big.zip", "glm-5.3",
                   "Domain computers", "Share inventory",
                   "ws01.corp.local", "dc01.corp.local", "Windows 11",
                   "IPC$", "docs"):
        assert marker in html, marker
    # tabbed layout: nav + panels + hash deep-linking
    assert html.count('class="tab-panel') == 12 and 'data-tab="creds"' in html and 'data-tab="transcript"' in html
    # triage tabs: panels always exist, BUTTONS only when data is present
    assert 'data-tab="artifacts"' not in html and 'data-tab="fps"' not in html
    assert 'function activate(' in html and '@media print' in html
    # secret masked by default, real value only in the reveal attribute
    assert "Sup3rS3cret!" in html                     # present for the toggle...
    assert html.count("data-real='") == 1             # exactly one reveal attribute
    # the report file writes and is standalone
    path = write_report(str(tmp_path / "out.html"), context={"principal": "x"},
                        findings=[], scan_results=[], flagged=[], report_md="",
                        audit_path=audit_path)
    assert "CredShrike" in open(path, encoding="utf-8").read()[:2000]


def test_report_transcript_tab():
    html = build_report_html(
        context={"principal": "x"}, findings=[], scan_results=[], flagged=[],
        report_md="final", audit_path="",
        transcript=[
            {"kind": "goal", "text": "find passwords"},
            {"kind": "assistant", "text": "starting sweep",
             "tools": [{"name": "smb_scan_share", "input": {"share": "IT"}}]},
            {"kind": "tool_results", "items": [{"name": "smb_scan_share", "ok": True,
                                                "chars": 4321}]},
            {"kind": "assistant", "text": "found nothing", "tools": []},
        ])
    assert 'data-tab="transcript"' in html and "Transcript" in html
    assert "find passwords" in html and "AI · turn 1" in html
    assert "smb_scan_share" in html and "(4321c)" in html
    assert "AI · turn 2" in html


def test_report_debug_tab_only_when_debug_results():
    base = dict(context={"principal": "x"}, findings=[], scan_results=[],
                flagged=[], report_md="", audit_path="")
    plain = build_report_html(**base)
    assert "data-tab=\"debug\"" not in plain                     # no tab when off
    dbg = build_report_html(**base, debug_results=[
        {"tool": "domain_list_computers", "args": {"source": "adws"},
         "chars": 42, "content": '{"source": "adws", "computers": []}'}])
    assert "data-tab=\"debug\"" in dbg and "adws" in dbg and "domain_list_computers" in dbg


def test_long_values_do_not_break_layout():
    long_secret = "S" * 500
    html_out = build_report_html(
        context={"principal": "x"}, findings=[{"severity": "high",
            "category": "credential", "host": "h", "share": "s", "path": "p",
            "username": "u" * 400, "secret": long_secret,
            "evidence": "e" * 1000, "note": ""}],
        scan_results=[], flagged=[], report_md="", audit_path="",
        debug_results=[{"tool": "t", "args": {}, "chars": 99999,
                        "content": "z" * 60000}])
    # masked view is compact regardless of secret length
    import re
    masked = re.search(r"<span class='secret'[^>]*>([^<]*)</span>", html_out).group(1)
    assert len(masked) < 40 and "500 chars" in masked
    assert html_out.count("overflow-wrap:anywhere") >= 1     # wrap-safe CSS present
    # debug content capped, not fully rendered
    assert "z" * 60000 not in html_out


def test_extraction_completeness_crosscheck():
    """Both extraction passes omit HACKADAY\jchen which the final report
    names -> union is still short -> ONE corrective round fires and names
    the miss."""
    import json as _json
    from credshrike.agent.findings import extract_findings
    calls = []
    bs = chr(92)

    incomplete = _json.dumps({"findings": [{
        "severity": "high", "category": "credential", "host": "FILE01",
        "share": "CTF$", "path": "vault.txt",
        "username": "HACKADAY" + bs + "mwong",
        "secret": "Pass1", "evidence": "read vault", "note": ""}]})
    complete = _json.dumps({"findings": [
        {"severity": "high", "category": "credential", "host": "FILE01",
         "share": "CTF$", "path": "vault.txt",
         "username": "HACKADAY" + bs + "mwong",
         "secret": "Pass1", "evidence": "read vault", "note": ""},
        {"severity": "high", "category": "credential", "host": "FILE01",
         "share": "CTF$", "path": "IT/backup_old.bat",
         "username": "HACKADAY" + bs + "jchen", "secret": "Welcome1",
         "evidence": "net use /user:HACKADAY jchen Welcome1", "note": ""}]})

    class Msgs:
        def create(self, **kw):
            calls.append(kw)
            text = incomplete if len(calls) <= 2 else complete
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])

    from credshrike.config import Policy
    messages = [
        {"role": "user", "content": "goal"},
        {"role": "assistant", "content": [
            SimpleNamespace(type="text",
                            text="| 6 | backup_old.bat | HACKADAY" + bs + "jchen | Welcome1 |")],
        },
    ]
    out = extract_findings(SimpleNamespace(messages=Msgs()), Policy(), messages)
    users = {f["username"] for f in out}
    assert ("HACKADAY" + bs + "jchen") in users and ("HACKADAY" + bs + "mwong") in users
    assert len(calls) == 3                        # 2 passes + 1 corrective round
    assert "jchen" in str(calls[2]["messages"][-1])   # corrective prompt named the miss


def test_placeholder_usernames_sanitized():
    from credshrike.agent.findings import _sanitize
    out = _sanitize({"findings": [
        {"severity": "low", "category": "credential", "username": "—",
         "secret": "x", "host": "", "share": "", "path": "", "evidence": "", "note": ""},
        {"severity": "low", "category": "credential", "username": "�",
         "secret": "y", "host": "", "share": "", "path": "", "evidence": "", "note": ""}]})
    assert all(f["username"] is None for f in out)


def test_double_extraction_union_catches_omissions():
    """Two passes each miss a different credential — the union keeps both,
    no corrective round needed (both are in the report text)."""
    import json as _json
    from credshrike.agent.findings import extract_findings
    calls = []

    a_only = _json.dumps({"findings": [
        {"severity": "high", "category": "credential", "host": "h", "share": "s",
         "path": "a", "username": "HACKADAY" + chr(92) + "mwong", "secret": "P1",
         "evidence": "e1", "note": ""}]})
    b_only = _json.dumps({"findings": [
        {"severity": "high", "category": "credential", "host": "h", "share": "s",
         "path": "b", "username": "HACKADAY" + chr(92) + "jchen", "secret": "P2",
         "evidence": "e2", "note": ""}]})

    class Msgs:
        def create(self, **kw):
            calls.append(kw)
            text = a_only if len(calls) == 1 else b_only
            return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])

    from credshrike.config import Policy
    messages = [
        {"role": "user", "content": "goal"},
        {"role": "assistant", "content": [
            SimpleNamespace(type="text",
                            text="mwong and jchen both found")],
        },
    ]
    out = extract_findings(SimpleNamespace(messages=Msgs()), Policy(), messages)
    users = {f["username"] for f in out}
    expected = {"HACKADAY" + chr(92) + "mwong", "HACKADAY" + chr(92) + "jchen"}
    assert users == expected                                  # union, no dupes
    assert len(calls) == 2                                    # both were pass 1&2


def test_union_dedupes_same_credential():
    from credshrike.agent.findings import _merge_passes
    entry = {"severity": "low", "category": "credential", "host": "h", "share": "s",
             "path": "a", "username": "HACKADAY" + chr(92) + "x", "secret": "P",
             "evidence": "e1", "note": ""}
    higher = dict(entry, severity="high", evidence="e2", path="b")
    merged = _merge_passes([[entry], [higher]])
    assert len(merged) == 1
    assert merged[0]["severity"] == "high"            # max severity wins
    assert "e1" in merged[0]["evidence"] and "e2" in merged[0]["evidence"]


def test_long_note_cannot_break_findings_layout():
    """A monster LLM note must not re-flow severity/category cells:
    the index used _esc (uncapped) for notes; both templates now pin the
    findings tables to fixed columns + top-aligned cells, and cap the note
    with the full text in the hover title."""
    import re
    from credshrike.report import build_domain_index_html, build_report_html

    note = "Credential exposure confirmed via plaintext assignment. " * 60
    findings = [{"severity": "high", "category": "credential", "host": "FS01",
                 "share": "CTF$", "path": "creds.txt", "note": note,
                 "evidence": "password=..."}]
    html = build_report_html(context={"principal": "demo"}, findings=findings,
                             scan_results=[], flagged=[], report_md="", audit_path="")
    assert 'id="findTable"' in html
    assert "#findTable" in html and "table-layout: fixed" in html
    assert "vertical-align:top" in html
    # severity pills must never break mid-word (a narrow window used to
    # split "medium" into MEDI/UM and shove the pill down) — nowrap wins
    # over overflow-wrap:anywhere, and the column gets a fixed 90px floor
    assert "white-space:nowrap" in html and html.count("white-space:nowrap") >= 2
    assert "#findTable th:nth-child(1){width:90px}" in html.replace("{{", "{").replace("}}", "}") or            "#findTable th:nth-child(1){{width:90px}}" in html
    # capped shown text (<=170 chars incl. ellipsis) + full note in the title
    assert re.search(r"<td title='[^']{1000,}'>(.{1,170})…</td>", html)

    merged = {"other": [{"severity": "medium", "category": "pii",
                         "locations": [{"host": "FS01", "share": "CTF$",
                                        "path": "hr.csv"}], "note": note}]}
    idx = build_domain_index_html(context={"principal": "demo"}, hosts=[],
                                  merged=merged, computers=[])
    assert 'id="otherTable"' in idx
    assert "vertical-align:top" in idx
    # index note cell capped the same way (this is the regression: it used
    # to render all ~3400 chars raw into the cell)
    assert re.search(r"<td title='[^']{1000,}'>(.{1,170})…</td>", idx)
