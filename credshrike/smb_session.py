"""Read-only SMB session: browsing, security descriptors, effective access.

Everything here is deliberately read-only: opens use FILE_OPEN disposition
(existing objects only), reads are byte-capped, and no wrapper for writing,
creating, deleting or renaming exists on this class. The agent executor
depends on that property.
"""

from __future__ import annotations

import logging
import ntpath
import os
import tempfile
from typing import Optional

from impacket import smb, smb3
from impacket.dcerpc.v5 import srvs, transport as dce_transport
from impacket.smb import SMB_DIALECT
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import (FILE_APPEND_DATA, FILE_ATTRIBUTE_DIRECTORY,
                                  FILE_NON_DIRECTORY_FILE, FILE_OPEN,
                                  FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE,
                                  FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
                                  READ_CONTROL, SMB2_0_INFO_SECURITY, SYNCHRONIZE, DELETE,
                                  FILE_EXECUTE)

from .acl import parse_security_descriptor, SidResolver, decode_share_permissions, SDParseError
from .credentials import AuthType, Credential
from .krbutil import extract_for_spn, load_ticket

LOG = logging.getLogger(__name__)

DEFAULT_MAX_READ_BYTES = 256 * 1024
DEFAULT_MAX_ENTRIES = 500

# security information bits: OWNER | GROUP | DACL (we skip SACL: needs privilege)
SECINFO_OGD = 0x00000007

# what "write" access looks like for share-level permission bits
SHARE_TYPE_NAMES = {0x00000000: "DISK", 0x00000001: "PRINT", 0x00000002: "DEVICE",
                    0x00000003: "IPC", 0x80000000: "SPECIAL", 0x40000000: "TEMPORARY"}


# --------------------------------------------------------------------------- #
# auth dispatch
# --------------------------------------------------------------------------- #
def _ticket_ccache_path(credential: Credential) -> str:
    """Return a .ccache FILE path for the credential's ticket (.kirbi is
    converted to a temp ccache). impacket's battle-tested ticket path is
    KRB5CCNAME + kerberosLogin(useCache=True) — passing TGT dicts directly
    breaks against Server 2022 (session-setup continuation)."""
    path = credential.ticket_path
    if path.lower().endswith(".kirbi"):
        ccache = load_ticket(path)
        from .krbutil import ccache_to_bytes
        fd, tmp = tempfile.mkstemp(prefix="credshrike_tkt_", suffix=".ccache")
        with os.fdopen(fd, "wb") as fh:
            fh.write(ccache_to_bytes(ccache))
        return tmp
    return os.path.abspath(path)


def login_smb(conn: SMBConnection, credential: Credential, spn_host: Optional[str] = None) -> None:
    """Authenticate an SMBConnection according to the credential type."""
    credential.validate()
    from .krbutil import ensure_kdc
    ensure_kdc(credential)   # early, actionable error instead of impacket recv-crash
    user, domain = credential.username, credential.domain
    if credential.auth_type is AuthType.PASSWORD:
        conn.login(user, credential.password, domain)
    elif credential.auth_type is AuthType.NTLM:
        conn.login(user, "", domain, credential.lmhash or "", credential.nthash or "")
    elif credential.auth_type is AuthType.AES:
        conn.kerberosLogin(user, "", domain, aesKey=credential.aes_key,
                           kdcHost=credential.kdc_host or None, useCache=False)
    elif credential.auth_type is AuthType.TICKET:
        ccache_path = _ticket_ccache_path(credential)
        saved = os.environ.get("KRB5CCNAME")
        os.environ["KRB5CCNAME"] = ccache_path
        try:
            conn.kerberosLogin("", "", domain or " ", kdcHost=credential.kdc_host or None,
                               useCache=True)
        finally:
            if saved is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = saved
            if ccache_path.startswith(tempfile.gettempdir()) and \
                    "credshrike_tkt_" in ccache_path:
                try:
                    os.unlink(ccache_path)
                except OSError:
                    pass
    else:  # pragma: no cover - enum exhaustiveness
        raise ValueError(f"unsupported auth type {credential.auth_type}")


# --------------------------------------------------------------------------- #
# session
# --------------------------------------------------------------------------- #
class SMBSession:
    """Authenticated, read-only browsing session against one host."""

    def __init__(self, credential: Credential, host: str, port: int = 445,
                 timeout: int = 30, resolver: Optional[SidResolver] = None):
        self.credential = credential
        self.host = host
        self.port = port
        self.timeout = timeout
        self.resolver = resolver or SidResolver()
        self._conn: Optional[SMBConnection] = None
        self._dce_cache: dict[str, object] = {}

    # -- lifecycle --------------------------------------------------------- #
    def connect(self) -> "SMBSession":
        if self._conn is not None:
            return self
        conn = SMBConnection(self.host, self.host, sess_port=self.port, timeout=self.timeout)
        login_smb(conn, self.credential, spn_host=self.host)
        self._conn = conn
        # wire remote SID resolution through this session's lsarpc pipe
        self.resolver = SidResolver(static_map=self.resolver.static_map,
                                    remote_lookup=self._lsa_lookup_sids)
        return self

    def close(self) -> None:
        for dce in self._dce_cache.values():
            try:
                dce.disconnect()
            except Exception:  # noqa: BLE001 - best effort teardown
                pass
        self._dce_cache.clear()
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                self._conn = None

    def __enter__(self) -> "SMBSession":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    @property
    def conn(self) -> SMBConnection:
        if self._conn is None:
            raise RuntimeError("session not connected (use .connect() or 'with')")
        return self._conn

    def _dce(self, pipe_name: str, uuid, cache_key: str):
        """Connected+bound DCERPC endpoint over this SMB session (cached)."""
        if cache_key in self._dce_cache:
            return self._dce_cache[cache_key]
        rpc = dce_transport.SMBTransport(self.conn.getRemoteName(), self.conn.getRemoteHost(),
                                         filename=pipe_name, smb_connection=self.conn)
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(uuid)
        self._dce_cache[cache_key] = dce
        return dce

    # -- browsing ---------------------------------------------------------- #
    def list_shares(self) -> list[dict]:
        """Shares with remarks, types and (via level-502) raw share ACLs."""
        out = []
        for entry in self.conn.listShares():
            raw_type = int(entry["shi1_type"]["Data"]) if hasattr(entry["shi1_type"], "get") \
                else int(entry["shi1_type"])
            out.append({
                "name": str(entry["shi1_netname"]).rstrip("\x00"),
                "remark": str(entry["shi1_remark"] or "").rstrip("\x00"),
                "type": raw_type & 0x0FFFFFFF,
                "type_name": SHARE_TYPE_NAMES.get(raw_type & 0x0FFFFFFF,
                                                  hex(raw_type & 0x0FFFFFFF)),
                "special": bool(raw_type & 0x80000000),
            })
        return out

    def list_dir(self, share: str, path: str = "", max_entries: int = DEFAULT_MAX_ENTRIES) -> dict:
        """List a directory inside a share. ``path`` is relative ('' or '.'
        = share root). Returns entries + truncation flag."""
        search = ntpath.join(_norm(path), "*") if path not in ("", ".", "*") \
            else (path if path == "*" else "*")
        entries = []
        for i, f in enumerate(self.conn.listPath(share, search)):
            if i >= max_entries:
                return {"share": share, "path": _norm(path), "entries": entries,
                        "truncated": True, "total_seen": i}
            if f.get_longname() in (".", ".."):
                continue  # pseudo-entries — noise for the model, poison for paths
            attrs = f.get_attributes()
            is_dir = bool(attrs & FILE_ATTRIBUTE_DIRECTORY)
            entries.append({
                "name": f.get_longname().rstrip("\x00"),
                "is_dir": is_dir,
                "size": f.get_filesize(),
                "attributes": hex(attrs),
                "created": _iso(f.get_ctime_epoch()), "accessed": _iso(f.get_atime_epoch()),
                "written": _iso(f.get_mtime_epoch()),
            })
        return {"share": share, "path": _norm(path), "entries": entries,
                "truncated": False, "total_seen": len(entries)}

    def read_file(self, share: str, path: str, offset: int = 0,
                  max_bytes: int = DEFAULT_MAX_READ_BYTES) -> dict:
        """Read up to ``max_bytes`` from ``offset``. Hard-capped, streamed in
        chunks so a huge file can never blow memory."""
        tid = self.conn.connectTree(share)
        try:
            fid = self.conn.openFile(
                tid, _winpath(path),
                desiredAccess=FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationOption=FILE_NON_DIRECTORY_FILE, creationDisposition=FILE_OPEN)
            try:
                chunks: list[bytes] = []
                total = 0
                cursor = offset
                while total < max_bytes:
                    want = min(65536, max_bytes - total)
                    piece = self.conn.readFile(tid, fid, cursor, want, singleCall=True)
                    if not piece:
                        break
                    chunks.append(piece)
                    cursor += len(piece)
                    total += len(piece)
                    if len(piece) < want:
                        break
                return {"share": share, "path": path, "offset": offset,
                        "size": total, "truncated": total == max_bytes,
                        "content_b64": _b64(b"".join(chunks))}
            finally:
                self.conn.closeFile(tid, fid)
        finally:
            self.conn.disconnectTree(tid)

    def stat(self, share: str, path: str) -> dict:
        """Attributes + timestamps + size for one file/dir."""
        matches = self.conn.listPath(share, _winpath(path))
        if not matches:
            raise FileNotFoundError(f"not found: {share}/{path}")
        f = matches[0]
        attrs = f.get_attributes()
        return {
            "share": share, "path": _norm(path), "name": f.get_longname().rstrip("\x00"),
            "is_dir": bool(attrs & FILE_ATTRIBUTE_DIRECTORY), "size": f.get_filesize(),
            "attributes": hex(attrs),
            "created": _iso(f.get_ctime_epoch()), "accessed": _iso(f.get_atime_epoch()),
            "written": _iso(f.get_mtime_epoch()),
        }

    # -- permissions ------------------------------------------------------- #
    def get_security(self, share: str, path: str) -> dict:
        """Parsed + name-annotated security descriptor for a file/dir."""
        raw = self._query_file_sd(share, path)
        parsed = parse_security_descriptor(raw)
        return self.resolver.annotate(parsed)

    def get_share_security(self, share: str) -> dict:
        """Share-level permissions. Best source is NetrShareGetInfo level 502
        (share permission bits + the share's own security descriptor); many
        servers restrict that RPC to admins, so we fall back to the filesystem
        security descriptor of the share ROOT directory — the DACL that
        actually governs the shared folder."""
        result: dict = {"share": share}
        try:
            dce = self._dce(r"\srvsvc", srvs.MSRPC_UUID_SRVS, "srvsvc")
            resp = srvs.hNetrShareGetInfo(dce, share, 502)
            info = resp["InfoStruct"]["ShareInfo502"]
            result["path"] = str(info["shi502_path"] or "").rstrip("\x00")
            result["remark"] = str(info["shi502_remark"] or "").rstrip("\x00")
            result["share_permissions"] = decode_share_permissions(int(info["shi502_permissions"]))
            sd_raw = bytes(info["shi502_security_descriptor"] or b"")
            if sd_raw:
                try:
                    result["sd"] = self.resolver.annotate(parse_security_descriptor(sd_raw))
                    result["sd_source"] = "netrsharegetinfo-502"
                except SDParseError as exc:
                    result["sd_error"] = str(exc)
            return result
        except Exception as exc:  # noqa: BLE001 - fall back to filesystem root SD
            LOG.debug("NetrShareGetInfo(502) failed for %s: %s", share, exc)
            result["share_permissions_error"] = (
                f"unavailable via srvsvc ({type(exc).__name__}) — server restricts it")

        try:
            raw = self._query_file_sd(share, "")
            result["sd"] = self.resolver.annotate(parse_security_descriptor(raw))
            result["sd_source"] = "filesystem-root"
        except Exception as exc:  # noqa: BLE001
            result["sd_error"] = f"{type(exc).__name__}: {exc}"
        return result

    def effective_access(self, share: str, path: str) -> dict:
        """Probe which operations the current credential can actually perform.

        Each probe opens the existing object with a single desired-access bit
        (FILE_OPEN, so nothing is ever created/modified) and reports whether
        the server granted it.
        """
        probes = {
            "read_data": FILE_READ_DATA,
            "write_data": FILE_WRITE_DATA,
            "append_data": FILE_APPEND_DATA,
            "execute": FILE_EXECUTE,
            "delete": DELETE,
            "read_attributes": FILE_READ_ATTRIBUTES,
        }
        out: dict = {"share": share, "path": path, "probes": {}}
        for label, mask in probes.items():
            out["probes"][label] = self._probe_open(share, path, mask)
        return out

    def _probe_open(self, share: str, path: str, desired_access: int) -> dict:
        tid = None
        try:
            tid = self.conn.connectTree(share)
            fid = self.conn.openFile(
                tid, _winpath(path), desiredAccess=desired_access | SYNCHRONIZE,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationOption=0, creationDisposition=FILE_OPEN)
            self.conn.closeFile(tid, fid)
            return {"allowed": True}
        except SessionError as exc:
            return {"allowed": False, "error": "%s (0x%08X)" % (exc.getErrorString(), exc.getErrorCode())}
        except (smb.SessionError, smb3.SessionError) as exc:
            return {"allowed": False, "error": "0x%08X" % exc.get_error_code()}
        finally:
            if tid is not None:
                try:
                    self.conn.disconnectTree(tid)
                except Exception:  # noqa: BLE001
                    pass

    def _query_file_sd(self, share: str, path: str) -> bytes:
        tid = self.conn.connectTree(share)
        try:
            fid = self.conn.openFile(
                tid, _winpath(path), desiredAccess=READ_CONTROL | SYNCHRONIZE,
                shareMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                creationOption=0, creationDisposition=FILE_OPEN)
            try:
                server = self.conn.getSMBServer()
                if self.conn.getDialect() == SMB_DIALECT:
                    return bytes(server.query_sec_info(tid, fid, SECINFO_OGD))
                raw = server.queryInfo(tid, fid, infoType=SMB2_0_INFO_SECURITY,
                                       fileInfoClass=0, additionalInformation=SECINFO_OGD)
                return bytes(raw)
            finally:
                self.conn.closeFile(tid, fid)
        finally:
            self.conn.disconnectTree(tid)

    # -- SID resolution ----------------------------------------------------- #
    def _lsa_lookup_sids(self, sids: list[str]) -> dict[str, str]:
        """LSarLookupSids2 over \\PIPE\\lsarpc. Batches; tolerates partial
        mapping (0x107 SOME_NOT_MAPPED) by returning what we have per chunk."""
        from impacket.dcerpc.v5 import lsat

        names: dict[str, str] = {}
        try:
            from impacket.dcerpc.v5 import lsad
            dce = self._dce(r"\lsarpc", lsat.MSRPC_UUID_LSAT, "lsarpc")
            policy = lsad.hLsarOpenPolicy2(dce)
        except Exception as exc:  # noqa: BLE001
            LOG.debug("lsarpc unavailable: %s", exc)
            return names
        try:
            for chunk_start in range(0, len(sids), 200):
                chunk = sids[chunk_start: chunk_start + 200]
                try:
                    resp = lsat.hLsarLookupSids2(dce, policy, chunk)
                except Exception as exc:  # noqa: BLE001 - partial mapping etc.
                    LOG.debug("hLsarLookupSids2 failed for chunk: %s", exc)
                    continue
                domains = resp["ReferencedDomains"]["Domains"]
                for sid, entry in zip(chunk, resp["TranslatedNames"]["Names"]):
                    idx = int(entry["DomainIndex"])
                    name = str(entry["Name"])
                    if 0 <= idx < len(domains):
                        dom = str(domains[idx]["Name"])
                        names[sid] = f"{dom}\\{name}" if name else dom
                    elif name:
                        names[sid] = name
        finally:
            try:
                from impacket.dcerpc.v5 import lsad
                lsad.hLsarClose(dce, policy)
            except Exception:  # noqa: BLE001
                pass
        return names


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
def _norm(path: str) -> str:
    return (path or "").replace("\\", "/").strip("/")


def _winpath(path: str) -> str:
    p = (path or "").strip()
    p = p.replace("\\", "/").strip("/")
    return p.replace("/", "\\")


def _iso(ts) -> Optional[str]:
    if not ts:
        return None
    try:
        import datetime
        return datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:  # noqa: BLE001
        return str(ts)


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")
