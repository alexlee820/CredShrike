"""smbenum — manual CLI.

    smbenum smb list-shares --host FILESRV01 --user jdoe --domain corp.local --password '...'
    smbenum smb ls --host FILESRV01 --share IT --path Reports
    smbenum smb read --host FILESRV01 --share IT --path Reports/q4.xlsx --max-bytes 4096
    smbenum smb permissions --host FILESRV01 --share IT --path Reports --probe
    smbenum domain computers --dc dc01.corp.local --source ldap
    smbenum agent --profile lab.yaml --host filesrv01

Auth material is inferred from which flag you pass: --ticket (ccache/kirbi),
--aes-key, --hashes LM:NT, or --password. Explicit --auth-type overrides.
Output is JSON unless stated otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys

from .credentials import AuthType, Credential
from .smb_session import DEFAULT_MAX_ENTRIES, DEFAULT_MAX_READ_BYTES, SMBSession


# --------------------------------------------------------------------------- #
# shared arg plumbing
# --------------------------------------------------------------------------- #
def add_auth_args(parser: argparse.ArgumentParser) -> None:
    g = parser.add_argument_group("authentication")
    g.add_argument("--profile", help="YAML profile file (see policy.example.yaml)")
    g.add_argument("--auth-type", choices=[t.value for t in AuthType],
                   help="force auth type; otherwise inferred from provided material")
    g.add_argument("--user", help="username (sAMAccountName or UPN)")
    g.add_argument("--domain", help="domain / Kerberos realm (FQDN)")
    g.add_argument("--password", help="plaintext password")
    g.add_argument("--hashes", help="LM:NT hashes (either side may be empty)")
    g.add_argument("--aes-key", help="aes256-cts-hmac-sha1-96 (or aes128) hex key")
    g.add_argument("--ticket", help="Kerberos ticket file (.ccache or .kirbi)")
    g.add_argument("--kdc", help="KDC override (host[:port]) for Kerberos auth")
    g.add_argument("--timeout", type=int, default=30, help="SMB timeout seconds (default 30)")


def build_credential(args) -> Credential:
    if args.profile:
        from .config import Profile
        profile = Profile.load(args.profile)
        if not args.user:
            return profile.credential
        # CLI material overrides profile
        args.user = args.user or profile.credential.username
        args.domain = args.domain or profile.credential.domain
        args.kdc = args.kdc or profile.credential.kdc_host
    auth_type = getattr(args, "auth_type", None)
    if not auth_type:
        if getattr(args, "ticket", None):
            auth_type = AuthType.TICKET.value
        elif getattr(args, "aes_key", None):
            auth_type = AuthType.AES.value
        elif getattr(args, "hashes", None):
            auth_type = AuthType.NTLM.value
        else:
            auth_type = AuthType.PASSWORD.value
    cred = Credential.from_args(
        auth_type=auth_type,
        username=args.user or "",
        domain=args.domain or "",
        password=args.password or "",
        hashes=args.hashes or "",
        aes_key=args.aes_key or "",
        ticket=args.ticket or "",
        kdc=args.kdc or "",
    )
    cred.validate()
    return cred


def open_session(args, host: str) -> SMBSession:
    return SMBSession(build_credential(args), host, timeout=args.timeout).connect()


def emit(obj, file=None) -> None:
    json.dump(obj, file or sys.stdout, indent=2, default=str)
    print(file=file or sys.stdout)


# --------------------------------------------------------------------------- #
# smb subcommands
# --------------------------------------------------------------------------- #
def cmd_smb_list_shares(args) -> None:
    with open_session(args, args.host) as sess:
        shares = sess.list_shares()
        if args.acl:
            for share in shares:
                if share["special"]:
                    continue
                try:
                    share["acl"] = sess.get_share_security(share["name"])
                except Exception as exc:  # noqa: BLE001
                    share["acl_error"] = str(exc)
        emit(shares)


def cmd_smb_ls(args) -> None:
    with open_session(args, args.host) as sess:
        emit(sess.list_dir(args.share, args.path or "", max_entries=args.max_entries))


def cmd_smb_read(args) -> None:
    import base64
    with open_session(args, args.host) as sess:
        result = sess.read_file(args.share, args.path, offset=args.offset,
                                max_bytes=args.max_bytes)
        if args.raw:
            sys.stdout.buffer.write(base64.b64decode(result["content_b64"]))
            return
        if not args.b64:
            try:
                result["content"] = base64.b64decode(result["content_b64"]).decode(
                    "utf-8", errors="replace")
                del result["content_b64"]
            except Exception:  # noqa: BLE001 - keep b64 if undecodable
                pass
        emit(result)


def cmd_smb_stat(args) -> None:
    with open_session(args, args.host) as sess:
        emit(sess.stat(args.share, args.path))


def cmd_smb_permissions(args) -> None:
    with open_session(args, args.host) as sess:
        out: dict = {"host": args.host, "share": args.share}
        if args.path:
            out["object"] = args.path
            out["sd"] = sess.get_security(args.share, args.path)
            if args.probe:
                out["effective_probes"] = sess.effective_access(args.share, args.path)
        else:
            out["share_acl"] = sess.get_share_security(args.share)
            if args.probe:
                out["effective_probes"] = sess.effective_access(args.share, "")
        emit(out)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="smbenum", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subs = parser.add_subparsers(dest="command", required=True)

    # --- smb --- #
    smb = subs.add_parser("smb", help="SMB browsing operations")
    smb_subs = smb.add_subparsers(dest="smb_command", required=True)

    def smb_cmd(name: str, help_: str, funcs=None) -> argparse.ArgumentParser:
        p = smb_subs.add_parser(name, help=help_)
        add_auth_args(p)
        p.add_argument("--host", required=True, help="target host (FQDN preferred for Kerberos)")
        return p

    p = smb_cmd("list-shares", "enumerate shares")
    p.add_argument("--acl", action="store_true", help="include per-share ACL (level 502)")
    p.set_defaults(func=cmd_smb_list_shares)

    p = smb_cmd("ls", "list a directory inside a share")
    p.add_argument("--share", required=True)
    p.add_argument("--path", default="", help="path inside the share (default: root)")
    p.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    p.set_defaults(func=cmd_smb_ls)

    p = smb_cmd("read", "read bytes from a file (capped)")
    p.add_argument("--share", required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_READ_BYTES)
    p.add_argument("--b64", action="store_true", help="keep content base64-encoded")
    p.add_argument("--raw", action="store_true", help="write raw bytes to stdout")
    p.set_defaults(func=cmd_smb_read)

    p = smb_cmd("stat", "file/directory metadata")
    p.add_argument("--share", required=True)
    p.add_argument("--path", required=True)
    p.set_defaults(func=cmd_smb_stat)

    p = smb_cmd("permissions", "DACL + optional effective-access probes")
    p.add_argument("--share", required=True)
    p.add_argument("--path", default="", help="omit for share-level ACL")
    p.add_argument("--probe", action="store_true", help="run effective-access open probes")
    p.set_defaults(func=cmd_smb_permissions)

    # --- domain (Phase 2) / agent (Phase 3) parsers are registered by their
    # modules importing build_parser hooks; kept here so --help is stable. #
    from .domain import register_cli as register_domain_cli
    register_domain_cli(subs)
    from .agent import register_cli as register_agent_cli
    register_agent_cli(subs)
    from .webapp import register as register_ui
    register_ui(subs)

    return parser


def main(argv=None) -> int:
    # Windows consoles default to a legacy codepage (cp1252/cp950) that cannot
    # encode the echo glyphs (→ ← ⋮ ★) — force UTF-8 with replacement so a
    # console's encoding never crashes a run
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - non-standard streams
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
        return 0
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
