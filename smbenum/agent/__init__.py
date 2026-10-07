"""Capability-limited LLM agent: read-only tool registry + guarded loop."""


def register_cli(subparsers) -> None:
    """Attach `smbenum agent …` subcommands (implemented in cli_agent)."""
    from .cli_agent import register
    register(subparsers)
