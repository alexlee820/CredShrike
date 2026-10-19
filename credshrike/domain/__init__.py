"""Domain computer enumeration: LDAP and ADWS sources behind one interface."""

from .base import ComputerRecord, DirectorySource


def register_cli(subparsers) -> None:
    """Attach `CredShrike domain …` subcommands (implemented in cli_domain)."""
    from .cli_domain import register
    register(subparsers)


__all__ = ["ComputerRecord", "DirectorySource", "register_cli"]
