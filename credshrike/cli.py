"""CredShrike — manual CLI.

    CredShrike smb list-shares --host FILESRV01 --user jdoe --domain corp.local --password '...'
    CredShrike smb ls --host FILESRV01 --share IT --path Reports
    CredShrike smb read --host FILESRV01 --share IT --path Reports/q4.xlsx --max-bytes 4096
    CredShrike smb permissions --host FILESRV01 --share IT --path Reports --probe
    CredShrike domain computers --dc dc01.corp.local --source ldap
    credshrike agent --profile lab.yaml --host filesrv01

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
    g.add_argument("--socks-proxy", default=None, metavar="URL",
                   help="SOCKS/HTTP proxy for SMB/LDAP/ADWS/Kerberos ONLY — "
                        "LLM API calls stay direct (unlike proxychains). "
                        "socks5:// socks5h:// (DNS at the proxy) socks4:// "
                        "http://[user:pass@]host:port")


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
    from .smb_session import create_smb_session
    return create_smb_session(build_credential(args), host,
                              timeout=args.timeout).connect()


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
# standalone mask / restore (PasteGuard-style, no LLM or SMB involved)
# --------------------------------------------------------------------------- #
def cmd_runs_list(args) -> None:
    """`credshrike runs list` — every run dir with a manifest, newest first,
    with progress and a resumable flag (the CLI answer to 'which run dir do I
    pass to --resume?')."""
    from .runstate import scan_run_dirs

    runs = scan_run_dirs(args.audit_dir)
    if not runs:
        print(f"no runs found under {args.audit_dir}/")
        return
    print(f"{'run directory':<44} {'updated':<20} {'hosts':>9}  {'shares':>6}  status")
    print("-" * 96)
    for r in runs:
        name = r["run_dir"].replace(chr(92), "/").split("/")[-1]
        flag = "  → resumable" if r["resumable"] else ""
        print(f"{name:<44} {r['updated_at'] or '?':<20} "
              f"{r['hosts_done']:>4}/{r['hosts_total']:<4} "
              f"{r['shares_done']:>6}  {r['status']}{flag}")
    resumable = [r for r in runs if r["resumable"]]
    if resumable:
        print()
        print(f"resume: credshrike agent --preset full-domain ... "
              f"--resume {resumable[0]['run_dir']}")
        print("or:     credshrike agent --preset full-domain ... --resume latest")


def cmd_mask(args) -> None:
    """Mask (or --restore) free text from a file/stdin.

    Useful on its own before pasting logs, configs or ticket dumps into an AI
    chat — the same detector the agent uses on the LLM boundary.
    """
    from .masking import Masker

    if args.file and args.file != "-":
        text = open(args.file, "r", encoding="utf-8", errors="replace").read()
    else:
        text = sys.stdin.read()

    if args.restore:
        from .masking import MaskContext
        mapping = json.load(open(args.restore, "r", encoding="utf-8"))
        sys.stdout.write(MaskContext.from_mapping(mapping).restore(text))
        return

    pii, secrets = bool(args.pii), bool(args.secrets)
    if not pii and not secrets:      # the command's whole purpose
        pii = secrets = True
    allow = [{"pattern": p} for p in (args.allow or [])]
    deny = [{"pattern": p, "regex": not args.deny_literal, "type": "DENYLIST"}
            for p in (args.deny or [])]
    backend = None
    if args.semantic or args.semantic_model:
        from .semantic import get_backend
        backend = get_backend(model_name=args.semantic_model or "")
    same_length = ([] if args.no_surrogates
                   else ["PERSON", "ENV_PASSWORD", "USERNAME", "EMAIL_ADDRESS"])
    from .surrogate import SurrogateFactory
    factory = (SurrogateFactory(style=args.surrogate_style,
                                email_domain=args.email_domain,
                                netbios_domain=args.netbios_domain)
               if same_length else None)
    masker = Masker(pii=pii, secrets=secrets, allowlist=allow, denylist=deny,
                    semantic_backend=backend,
                    same_length_entities=same_length,
                    surrogate_factory=factory)
    masked, hits = masker.mask_text(text)
    sys.stdout.write(masked)
    if args.mapping:
        with open(args.mapping, "w", encoding="utf-8") as fh:
            json.dump(masker.context.mapping, fh, indent=2, ensure_ascii=False)
        print(f"\n[mask] {hits} value(s) masked; mapping saved to {args.mapping} "
              f"(restore with: credshrike mask --restore {args.mapping})",
              file=sys.stderr)


def _register_mask(subparsers) -> None:
    p = subparsers.add_parser(
        "mask", help="mask PII/secrets in text (PasteGuard-style; no LLM, no SMB)")
    p.add_argument("file", nargs="?", default="-",
                   help="file to mask (default: stdin)")
    p.add_argument("--pii", action="store_true",
                   help="mask emails, IPs, phones, cards, IBANs, VAT (default: on)")
    p.add_argument("--secrets", action="store_true",
                   help="mask API keys, JWTs, private keys, passwords, DSNs "
                        "(default: on)")
    p.add_argument("--allow", action="append", metavar="PATTERN",
                   help="never mask this literal (repeatable)")
    p.add_argument("--deny", action="append", metavar="PATTERN",
                   help="always mask this pattern (repeatable)")
    p.add_argument("--deny-literal", action="store_true",
                   help="treat --deny patterns as literals instead of regexes")
    p.add_argument("--semantic", action="store_true",
                   help="also mask names/addresses with GLiNER (PERSON/LOCATION; "
                        "needs `pip install gliner`, downloads the model once)")
    p.add_argument("--semantic-model", default=None, metavar="MODEL",
                   help="GLiNER checkpoint or local path (implies --semantic)")
    p.add_argument("--no-surrogates", action="store_true",
                   help="use [[TYPE_N]] placeholders for names/passwords too "
                        "(default: same-length pseudonyms)")
    p.add_argument("--surrogate-style", choices=["name", "syllable", "masked"],
                   default="name",
                   help="name = real-name dictionaries (default), syllable = "
                        "pronounceable filler, masked = Xxxx/0000")
    p.add_argument("--email-domain", default="corp.local",
                   help="domain used for masked email/UPN addresses "
                        "(default corp.local)")
    p.add_argument("--netbios-domain", default="corp",
                   help="domain used for masked DOMAIN\\user accounts "
                        "(default corp; FQDN forms use --email-domain)")
    p.add_argument("--mapping", metavar="PATH",
                   help="save the placeholder→value map as JSON (enables restore)")
    p.add_argument("--restore", metavar="MAPPING_JSON",
                   help="restore a masked text using a saved mapping")
    p.set_defaults(func=cmd_mask)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="CredShrike", description=__doc__,
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

    _register_mask(subs)

    # --- runs (resume helpers) --- #
    runs = subs.add_parser("runs", help="run history / resume helpers")
    runs_subs = runs.add_subparsers(dest="runs_command", required=True)
    p = runs_subs.add_parser("list", help="list runs with progress + resumable flag")
    p.add_argument("--audit-dir", default="runs", help="runs directory (default runs)")
    p.set_defaults(func=cmd_runs_list)

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
    # manual smb/domain commands: route SMB/LDAP/ADWS through the proxy
    # before anything connects (agent mode re-applies from its policy)
    if getattr(args, "socks_proxy", None):
        from .socks_proxy import apply_socks_proxy
        apply_socks_proxy(args.socks_proxy)
    # ...and share the inventory cache, so repeat one-shot browsing during a
    # lab session hits cache (agent/ui runs arm their own run-scoped cache)
    inv_cache = None
    if args.command in ("smb", "domain"):
        from .config import Policy
        from .inventory_cache import InventoryCache
        from .smb_session import arm_inventory_cache
        inv_cache = InventoryCache.open("runs", Policy())
        if inv_cache is not None:
            arm_inventory_cache(inv_cache)
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
    finally:
        if inv_cache is not None:
            from .smb_session import disarm_inventory_cache
            disarm_inventory_cache()
            inv_cache.close()


if __name__ == "__main__":
    sys.exit(main())
