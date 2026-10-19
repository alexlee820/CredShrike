"""`CredShrike domain …` CLI subcommands."""

from __future__ import annotations

import argparse

from ..cli import add_auth_args, build_credential, emit


def _make_source(args):
    credential = build_credential(args)
    source = args.source or "ldap"
    if args.port is None:
        args.port = 636 if (args.ssl and source == "ldap") else (9389 if source == "adws" else 389)
    if source == "ldap":
        from .ldap_source import LdapSource
        return LdapSource(credential, args.dc, port=args.port, use_ssl=args.ssl)
    if source == "adws":
        from .adws_source import AdwsSource
        return AdwsSource(credential, args.dc, port=args.port)
    raise ValueError(f"unknown source '{source}' (ldap|adws)")


def cmd_domain_computers(args) -> None:
    with _make_source(args) as source:
        records = source.list_computers(args.filter or "")
        emit([r.to_dict() for r in records])


def register(subparsers) -> None:
    domain = subparsers.add_parser("domain", help="Active Directory queries (LDAP / ADWS)")
    domain_subs = domain.add_subparsers(dest="domain_command", required=True)

    p = domain_subs.add_parser("computers", help="enumerate domain computer objects")
    add_auth_args(p)
    p.add_argument("--dc", required=True, help="domain controller host")
    p.add_argument("--source", choices=["ldap", "adws"], default="ldap",
                   help="transport (default ldap; adws = WCF net.tcp on 9389)")
    p.add_argument("--port", type=int, default=None,
                   help="port override (default 389 / 9389 per source, 636 with --ssl)")
    p.add_argument("--ssl", action="store_true", help="LDAP over SSL (LDAPS)")
    p.add_argument("--filter", default="", help="extra LDAP filter, ANDed with (objectClass=computer)")
    p.set_defaults(func=cmd_domain_computers)
