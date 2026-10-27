"""Snaffler-structured triage: discard / artifacts / relay / green layers."""

import json

from credshrike.config import Policy
from credshrike.credentials import Credential
from credshrike.patterns import (DISCARD_EXTS, DISCARD_NAMES, compile_patterns,
                                 triage)


def test_discard_layer():
    for name in ("img/logo.png", "font/app.woff2", "style/site.css",
                 "schema/data.xsd", "gp/policy.admx", "app/file.lock"):
        assert triage(name)["kind"] == "discard", name
    assert triage("java/jmxremote.password.template")["kind"] == "discard"
    assert triage("sysvol/sceregvl.inf")["kind"] == "discard"
    assert len(DISCARD_EXTS) == 27 and "sceregvl.inf" in DISCARD_NAMES


def test_artifact_extensions_reported_not_read():
    cases = {  # path -> tier
        "keepass/vault.kdbx": "black", "ssh/key.ppk": "black",
        "vms/disk.vmdk": "red", "dump/lsass.dmp": "black",
        "db/data.mdf": "yellow", "net/capture.pcap": "yellow",
        "vpn/office.ovpn": "yellow", "iac/prod.tfvars": "red",
        "krb/svc.keytab": "yellow", "ark/safe.cred": "red",
    }
    for path, tier in cases.items():
        v = triage(path)
        assert v["kind"] == "artifact" and v["tier"] == tier, path
        assert not v.get("read"), path              # report-only


def test_artifact_names_and_paths():
    for path, tier in (("ad/NTDS.DIT", "black"), ("home/.ssh/id_rsa", "black"),
                       ("c/hiberfil.sys", "black"), ("nx/running-config", "black"),
                       ("ark/Psmapp.cred", "black"), ("tools/mobaxterm.ini", "black"),
                       ("git/.git-credentials", "red"), ("wp/.htpasswd", "red"),
                       ("db/database.yml", "red"), ("logs/lsass_1234.dmp", "black"),
                       ("laps/BitlockerLAPSPasswords.csv", "red")):
        v = triage(path)
        assert v["kind"] == "artifact" and v["tier"] == tier, (path, v)
    assert triage("u/bob/.aws/credentials")["tier"] == "black"     # path rule
    assert triage("mdt/Deploy/control/customsettings.ini")["tier"] == "red"
    assert triage("sccm/REMINST/SMSTemp/x.var")["tier"] == "red"


def test_artifact_but_readable_when_ext_is_relay():
    # Snaffler would only report these; CredShrike ALSO reads (regex+AI)
    for path, tier in (("docs/passwords.txt", "red"),
                       ("ff/logins.json", "red"),
                       ("cfg/accounts.csv", "red"),
                       ("x/secrets.yaml", "red")):
        v = triage(path)
        assert v["kind"] == "artifact" and v["tier"] == tier and v["read"], path


def test_relay_triggers_cover_languages_and_certs():
    for path in ("s/deploy.ps1", "s/module.psd1", "c/App.cs", "web/page.aspx",
                 "web/ctrl.ascx", "v/run.vbs", "j/app.ts", "j/Serve.java",
                 "j/old.ls", "j/mod.es6", "p/index.php", "p/inc/helper.inc",
                 "py/tool.py", "r/app.rb", "pl/s.pl", "b/build.bat",
                 "sh/.bashrc", "sh/deploy.sh", "sh/.netrc", "sh/.npmrc",
                 "sh/.irb_history", "sh/.exports",
                 "net/cisco-rtr.cfg", "rdp/server.rdp", "xml/unattend.xml",
                 "ff/logins.json", "keys/host.pem", "keys/host_rsa",
                 "cert/site.pfx", "cert/site.pkcs12", "cert/backup.pk12",
                 "env/prod.env", "cfg/main.ini", "cfg/app.inf", "cfg/x.cnf",
                 "cfg/build.dist", "db/cache.sqlite", "db/firebird.fdb",
                 "old/creds.vnc", "keys/server.key"):
        assert triage(path)["kind"] in ("relay", "artifact"), path


def test_green_wide_net_catches_leftovers():
    v = triage("misc/mypassw_list.dat")            # .dat not readable
    assert v["kind"] == "green" and "passw" in v["reason"]
    assert triage("notes/readme.md")["kind"] is None


def test_new_relay_patterns_match():
    pats = {p["name"]: p["compiled"] for p in compile_patterns()}
    assert pats["jdbc_password"].search("jdbc:mysql://db:3306/x?user=r&password=S3cret!")
    assert pats["php_db_connect"].search('mysqli_connect("h","app","DbPw99","db")')
    assert pats["python_db_connect"].search(
        "pymysql.connect(host='h', user='u', password='PyPw123')")
    assert pats["dbi_dsn_password"].search(
        "DBI->connect('dbi:Pg:dbname=x','u','RubyPw9')")
    assert pats["unattend_password"].search(
        "<AdministratorPassword><Value>MyP@ss123</Value>")
    assert pats["machinekey_validation"].search(
        '<machineKey validationKey="A1B2C3' + "F" * 40 + '" />')
    assert pats["rdp_dpapi_password"].search(
        "password 51:b:01000000D08C9DDFA0123456789")
    assert pats["cisco_enable_secret"].search("enable secret 5 $1$mERr$TTmMH7")
    assert len(pats) == 18


# --------------------------------------------------------------------------- #
# end-to-end: the smb_scan_share tool reports artifacts + reads relay files
# --------------------------------------------------------------------------- #
def _session_with_files(tmp_path, files, monkeypatch=None):
    from queue import Queue
    from test_agent import FakeSMB
    from credshrike.agent.audit import AuditLog
    from credshrike.agent.session import AgentSession
    import credshrike.smb_session as smb_mod
    fake = FakeSMB()
    fake.list_dir = lambda share, path="", max_entries=200: {
        "share": share, "path": path,
        "entries": [{"name": n, "is_dir": False, "size": len(c)}
                    for n, c in files.items()],
        "truncated": False, "total_seen": len(files)}
    fake.file_contents = files
    policy = Policy()
    session = AgentSession(
        Credential.from_args("password", "svc", "corp.local", password="pw"),
        policy, AuditLog.new_run(str(tmp_path)), hosts=["fs01"])
    session.smb = lambda host: fake
    if monkeypatch is not None:
        # DNS for a nonexistent host can hang getaddrinfo — fail fast instead
        monkeypatch.setattr(smb_mod, "SMBSession",
                            lambda *a, **k: (_ for _ in ()).throw(
                                RuntimeError("no network in tests")))
        pool = Queue()
        pool.put(fake)
        session.get_read_pool = lambda host: pool
    return session, policy


def test_scan_tool_artifacts_and_relay(tmp_path, monkeypatch):
    from credshrike.agent.executor import ToolExecutor

    files = {
        "vault.kdbx": b"\x00binary",                            # artifact black
        "NTDS.DIT": b"\x00binary",                              # artifact black
        "creds.ovpn": b"binaryish",                             # artifact yellow
        "deploy.ps1": b"$pw = 'PSpass123!' password=Setup1!\n",  # relay
        "logo.png": b"PNGDATA",                                 # discard (walk)
        "random.dat": b"x",                                     # no match at all
    }
    session, policy = _session_with_files(tmp_path, files, monkeypatch)
    try:
        out = ToolExecutor(session, policy, session.audit).execute(
            "smb_scan_share", {"host": "fs01", "share": "IT"})
        assert not out["is_error"], out
        result = json.loads(out["content"])
        stats = result["stats"]

        # artifacts: kdbx+NTDS.DIT black, ovpn yellow — none read
        arts = {a["path"]: a for a in result["artifacts"]}
        assert arts["vault.kdbx"]["tier"] == "black"
        assert arts["NTDS.DIT"]["tier"] == "black"
        assert arts["creds.ovpn"]["tier"] == "yellow"
        assert stats["files_artifacts"] == 3

        # relay: only the .ps1 was opened and regex-scanned
        assert stats["files_scanned"] == 1
        assert any(m["path"] == "deploy.ps1" for m in result["matches"])
        # artifacts also appear as report rows
        assert any(m["pattern"] == "artifact:black" and m["path"] == "vault.kdbx"
                   for m in result["matches"])

        # junk (.png) never walked; .dat triaged to nothing
        assert stats["files_skipped_ext"] == 1
        assert stats["files_skipped_notier"] == 1
    finally:
        session.close_smb()


def test_scan_tool_reads_password_named_files(tmp_path, monkeypatch):
    """passwords.csv is an artifact AND readable — content reaches the AI."""
    from credshrike.agent.executor import ToolExecutor

    session, policy = _session_with_files(
        tmp_path, {"passwords.csv": b"jchen,Welcome1\n"}, monkeypatch)
    try:
        out = ToolExecutor(session, policy, session.audit).execute(
            "smb_scan_share", {"host": "fs01", "share": "IT"})
        result = json.loads(out["content"])
        arts = {a["path"]: a for a in result["artifacts"]}
        assert arts["passwords.csv"]["tier"] == "red"
        assert result["stats"]["files_scanned"] == 1        # read despite artifact
        assert any(d["path"] == "passwords.csv" for d in result["data_files"])
    finally:
        session.close_smb()


def test_report_has_reportonly_and_fp_tabs(tmp_path):
    """The HTML report separates report-only (artifact) files from known FPs."""
    from credshrike.report import build_report_html
    audit = tmp_path / "a.jsonl"
    audit.write_text("", encoding="utf-8")
    html = build_report_html(
        context={"principal": "corp\svc", "auth_type": "password"},
        findings=[], scan_results=[], flagged=[], report_md="",
        audit_path=str(audit),
        artifacts=[
            {"path": "IT/vault.kdbx", "tier": "black", "size": 1024,
             "host": "fs01", "share": "IT", "reason": "artifact extension .kdbx"},
            {"path": "IT/creds.ovpn", "tier": "yellow", "size": 10,
             "host": "fs01", "share": "IT", "reason": "artifact extension .ovpn"}],
        known_fps=[{"path": "SYSVOL/sceregvl.inf", "host": "fs01",
                    "share": "NETLOGON", "reason": "known false positive: sceregvl.inf"}])
    assert 'data-tab="artifacts"' in html and "Report-only files" in html
    assert 'data-tab="fps"' in html and "Known false positives" in html
    assert "vault.kdbx" in html and "black" in html
    assert "sceregvl.inf" in html
    # tiers sorted black before yellow
    assert html.index("vault.kdbx") < html.index("creds.ovpn")
    # tabs stay hidden when the lists are empty (non-triage runs)
    plain = build_report_html(
        context={"principal": "corp\svc", "auth_type": "password"},
        findings=[], scan_results=[], flagged=[], report_md="",
        audit_path=str(audit))
    assert 'data-tab="artifacts"' not in plain and 'data-tab="fps"' not in plain
