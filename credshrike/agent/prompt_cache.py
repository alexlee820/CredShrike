"""Anthropic prompt-caching helpers.

The Messages API is stateless: every request re-sends the whole
conversation. ``cache_control`` breakpoints let the provider reuse the
prefill (K/V) for an identical prefix, cutting latency and input cost
(cache reads are ~0.1x). The cache is TRANSPARENT — it never changes what
the model sees; if it expires or the endpoint does not support it, the
provider recomputes the same tokens.

Two breakpoints are used:

1. the system block (tools precede the system prompt in the cache prefix,
   so this also caches the tool definitions);
2. the last message — the conversation is append-only, so next turn's
   prefix includes everything cached so far (rolling cache).

The client still uploads the full prompt; only provider-side compute is
reused. Up to 4 breakpoints are allowed by the API; two is enough here.
"""

from __future__ import annotations

from typing import Any

_CACHE = {"type": "ephemeral"}


def cacheable_system(system: str, enabled: bool):
    if not enabled or not system:
        return system
    return [{"type": "text", "text": system, "cache_control": dict(_CACHE)}]


def cacheable_messages(messages: list[dict], enabled: bool) -> list[dict]:
    """Return a copy with a breakpoint on the LAST content block.

    ``self.messages`` is never mutated — the caller keeps sending plain
    messages next time, and the provider matches on the token prefix."""
    if not enabled or not messages:
        return messages
    last = messages[-1]
    content = last.get("content")
    if isinstance(content, str):
        new_content: Any = [{"type": "text", "text": content,
                             "cache_control": dict(_CACHE)}]
    elif isinstance(content, list) and content:
        blocks = [dict(block) for block in content]
        blocks[-1] = {**blocks[-1], "cache_control": dict(_CACHE)}
        new_content = blocks
    else:
        return messages
    return [*messages[:-1], {**last, "content": new_content}]


def is_cache_unsupported(exc: Exception) -> bool:
    """True when the endpoint rejected ``cache_control`` (not a rate limit)."""
    text = str(exc).lower()
    if "cache_control" in text or "prompt caching" in text:
        return True
    status = getattr(exc, "status_code", None)
    return status in (400, 404, 415, 422) and \
        ("cache" in text or "unsupported" in text or "unknown field" in text)
