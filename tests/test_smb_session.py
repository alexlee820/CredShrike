"""SMBSession tests with a fully mocked impacket SMBConnection."""

import base64

import pytest

import credshrike.smb_session as mod
from credshrike.credentials import AuthType, Credential
from credshrike.smb_session import login_smb

from test_sd_parser import build_sd, _ace, OWNER, ADMINS


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class FakeSharedFile:
    """Mirrors impacket.smb.SharedFile's real accessor names."""

    def __init__(self, name, size=0, is_dir=False):
        self._name, self._size = name, size
        self._attrs = 0x10 if is_dir else 0x20  # FILE_ATTRIBUTE_DIRECTORY / ARCHIVE

    def get_longname(self):
        return self._name

    get_shortname = get_longname

    def get_filesize(self):
        return self._size

    def get_attributes(self):
        return self._attrs

    def get_ctime_epoch(self):
        return 1700000000

    get_atime_epoch = get_ctime_epoch
    get_mtime_epoch = get_ctime_epoch


class FakeServer:
    """Stands in for the low-level smb.SMB1 / smb3.SMB3 object."""

    def __init__(self, sd_bytes=b""):
        self.sd_bytes = sd_bytes
        self.query_info_calls = []

    def queryInfo(self, treeId, fileId, inputBlob="", infoType=0, fileInfoClass=0,
                  additionalInformation=0, flags=0):
        self.query_info_calls.append((infoType, additionalInformation))
        return self.sd_bytes

    def query_sec_info(self, tid, fid, additional_information=7):
        self.query_info_calls.append(("smb1", additional_information))
        return self.sd_bytes


class FakeSMBConnection:
    """Records auth calls; returns canned browsing data."""

    def __init__(self, host, sess_ip=None, sess_port=445, timeout=60, **kwargs):
        self.host = host
        self.dialect = 0x0302  # SMB3
        self.login_calls = []
        self.kerberos_calls = []
        self.listing = [FakeSharedFile("file1.txt", 100), FakeSharedFile("sub", is_dir=True)]
        self.file_bytes = b"A" * 100000
        self._server = FakeServer()
        self._next_fid = 0x100
        self.opened = []

    # auth -------------------------------------------------------------- #
    def login(self, user, password, domain="", lmhash="", nthash=""):
        self.login_calls.append((user, password, domain, lmhash, nthash))

    def kerberosLogin(self, user, password, domain="", lmhash="", nthash="", aesKey="",
                      kdcHost=None, TGT=None, TGS=None, useCache=True):
        self.kerberos_calls.append(dict(user=user, password=password, domain=domain,
                                        aesKey=aesKey, kdcHost=kdcHost, TGT=TGT,
                                        TGS=TGS, useCache=useCache))

    kerberos_login = kerberosLogin

    # browsing ---------------------------------------------------------- #
    def getDialect(self):
        return self.dialect

    def getRemoteName(self):
        return self.host

    def getRemoteHost(self):
        return self.host

    def getSMBServer(self):
        return self._server

    def listShares(self):
        return [
            {"shi1_netname": "IT", "shi1_remark": "IT dept", "shi1_type": 0},
            {"shi1_netname": "IPC$", "shi1_remark": "", "shi1_type": 3},
        ]

    def listPath(self, share, path, password=None):
        return self.listing

    def connectTree(self, share):
        return 1

    def disconnectTree(self, tid):
        pass

    def openFile(self, treeId, pathName, desiredAccess=0, shareMode=0,
                 creationOption=0, creationDisposition=1, **kw):
        from impacket.smbconnection import SessionError
        from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_NO_SUCH_FILE
        self.opened.append((pathName, desiredAccess))
        if pathName == "missing.txt":
            raise SessionError(STATUS_NO_SUCH_FILE, b"")
        if desiredAccess & 0x00000002 and pathName == "locked.txt":
            raise SessionError(STATUS_ACCESS_DENIED, b"")
        self._next_fid += 1
        return self._next_fid

    def readFile(self, treeId, fileId, offset=0, bytesToRead=None, singleCall=True):
        chunk = self.file_bytes[offset: offset + (bytesToRead or len(self.file_bytes))]
        return chunk

    def closeFile(self, tid, fid):
        pass

    def close(self):
        pass


@pytest.fixture
def fake_conn(monkeypatch):
    conn = FakeSMBConnection("filesrv01.corp.local")
    monkeypatch.setattr(mod, "SMBConnection", lambda *a, **k: conn)
    return conn


# --------------------------------------------------------------------------- #
# auth dispatch
# --------------------------------------------------------------------------- #
def test_login_password(fake_conn):
    cred = Credential.from_args("password", "jdoe", "corp.local", password="pw")
    login_smb(fake_conn, cred)
    assert fake_conn.login_calls == [("jdoe", "pw", "corp.local", "", "")]


def test_login_ntlm(fake_conn):
    cred = Credential.from_args("ntlm", "jdoe", "corp.local", hashes=":" + "ab" * 16)
    login_smb(fake_conn, cred)
    assert fake_conn.login_calls[0][0] == "jdoe"
    assert fake_conn.login_calls[0][4] == "ab" * 16


def test_login_aes(fake_conn):
    cred = Credential.from_args("aes", "svc$", "corp.local", aes_key="cd" * 32, kdc="dc01")
    login_smb(fake_conn, cred)
    assert fake_conn.kerberos_calls[0]["aesKey"] == "cd" * 32
    assert fake_conn.kerberos_calls[0]["useCache"] is False
    assert fake_conn.kerberos_calls[0]["kdcHost"] == "dc01"


def test_login_ticket(fake_conn, monkeypatch, tmp_path):
    """Ticket auth goes through KRB5CCNAME + kerberosLogin(useCache=True) —
    impacket's battle-tested path (TGT dicts break on Server 2022)."""
    import os
    ccache_file = tmp_path / "t.ccache"
    ccache_file.write_bytes(b"\x05\x04rest")
    cred = Credential.from_args("ticket", "ignored", "corp.local",
                                ticket=str(ccache_file), kdc="dc01")
    seen_env = {}

    def fake_login(user, password, domain="", **kw):
        seen_env["krb5ccname"] = os.environ.get("KRB5CCNAME")
        seen_env["call"] = {"user": user, "domain": domain, **kw}

    fake_conn.kerberosLogin = fake_login
    saved_env = os.environ.get("KRB5CCNAME")
    login_smb(fake_conn, cred, spn_host="filesrv01.corp.local")
    assert seen_env["krb5ccname"] == str(ccache_file.resolve())  # set during login
    assert os.environ.get("KRB5CCNAME") == saved_env              # restored after
    call = seen_env["call"]
    assert call["useCache"] is True and call["kdcHost"] == "dc01"


# --------------------------------------------------------------------------- #
# session behavior
# --------------------------------------------------------------------------- #
def _session(fake_conn, **kw):
    cred = Credential.from_args("password", "jdoe", "corp.local", password="pw")
    return mod.SMBSession(cred, "filesrv01.corp.local", **kw).connect()


def test_list_shares(fake_conn):
    sess = _session(fake_conn)
    shares = sess.list_shares()
    assert [s["name"] for s in shares] == ["IT", "IPC$"]
    assert shares[1]["type_name"] == "IPC"


def test_list_dir_shapes_and_cap(fake_conn):
    sess = _session(fake_conn)
    out = sess.list_dir("IT", "Reports", max_entries=1)
    assert out["truncated"] is True and len(out["entries"]) == 1
    assert out["entries"][0]["name"] == "file1.txt" and out["entries"][0]["is_dir"] is False


def test_read_file_is_byte_capped(fake_conn):
    sess = _session(fake_conn)
    out = sess.read_file("IT", "file1.txt", max_bytes=4096)
    data = base64.b64decode(out["content_b64"])
    assert len(data) == 4096 and out["truncated"] is True
    out2 = sess.read_file("IT", "file1.txt", offset=99990, max_bytes=4096)
    assert base64.b64decode(out2["content_b64"]) == b"A" * 10


def test_stat(fake_conn):
    sess = _session(fake_conn)
    st = sess.stat("IT", "file1.txt")
    assert st["size"] == 100 and st["is_dir"] is False and st["written"]


def test_get_security_parses_and_annotates(fake_conn):
    fake_conn._server.sd_bytes = build_sd(
        dacl_aces=[_ace(0, 0, 0x001F01FF, ADMINS), _ace(0, 0x04, 0x00000089, "S-1-1-0")])
    sess = _session(fake_conn)
    sd = sess.get_security("IT", "Reports")
    assert sd["owner"] == OWNER
    assert sd["dacl"]["aces"][0]["trustee_name"] == "BUILTIN\\Administrators"
    # queried with the SECURITY info type and OWNER|GROUP|DACL bits
    info_type, addinfo = fake_conn._server.query_info_calls[-1]
    assert info_type == mod.SMB2_0_INFO_SECURITY and addinfo == mod.SECINFO_OGD


def test_effective_access_probe(fake_conn):
    sess = _session(fake_conn)
    probes = sess.effective_access("IT", "locked.txt")["probes"]
    assert probes["read_data"]["allowed"] is True
    assert probes["write_data"]["allowed"] is False
    assert "0x" in probes["write_data"]["error"]


def test_probe_on_missing_file_is_denied(fake_conn):
    sess = _session(fake_conn)
    probes = sess.effective_access("IT", "missing.txt")["probes"]
    assert all(p["allowed"] is False for p in probes.values())
