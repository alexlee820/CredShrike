"""HTML report + findings extraction tests."""

import json
from types import SimpleNamespace

from smbenum.agent.findings import extract_findings, _parse_findings_json
from smbenum.config import Policy
from smbenum.report import build_report_html, write_report


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
    client, calls = _client([json.dumps(payload)])
    out = extract_findings(client, Policy(), [{"role": "user", "content": "go"}])
    assert out[0]["secret"] == "pwd123" and out[0]["severity"] == "high"
    assert len(calls) == 1


def test_extract_findings_fenced_and_dirty_prose():
    fenced = "Here you go:\n```json\n{\"findings\": []}\n```\nsorry!"
    assert _parse_findings_json(fenced) == {"findings": []}
    assert _parse_findings_json('junk {"findings": [{"severity":"low"}]} junk')


def test_extract_findings_retries_on_garbage_then_succeeds():
    client, calls = _client(["total garbage not json",
                             '{"findings": [{"severity": "WEIRD", "category": "nope", '
                             '"secret": "x"}]}'])
    out = extract_findings(client, Policy(), [])
    assert len(calls) == 2                       # retried once
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
        audit_path=audit_path, redactions=2)
    # all sections present
    for marker in ("Credentials", "All findings", "Sweep hits", "SMB activity",
                   "Flagged files", "AI final report", "Audit trail", "creds.ps1",
                   "svc_backup", "big.zip", "glm-5.3"):
        assert marker in html, marker
    # secret masked by default, real value only in the reveal attribute
    assert "Sup3rS3cret!" in html                     # present for the toggle...
    assert html.count("data-real='") == 1             # exactly one reveal attribute
    # the report file writes and is standalone
    path = write_report(str(tmp_path / "out.html"), context={"principal": "x"},
                        findings=[], scan_results=[], flagged=[], report_md="",
                        audit_path=audit_path)
    assert "smbenum" in open(path, encoding="utf-8").read()[:2000]
