"""Same-length pseudonyms for PERSON names and password values.

Design (chosen with the operator):

1. real-name dictionaries indexed by length (initials preserved by default)
   ``Alice Smith`` -> ``Amber Scott``
2. syllable generator for lengths the dictionaries do not cover
   ``Qvrtz`` -> ``Karel``-style pronounceable strings
3. ``None`` when a value is too short / cannot be made collision-safe — the
   caller then falls back to the ``[[TYPE_N]]`` placeholder

Passwords preserve their per-character class (upper/lower/digit/symbol), so
the model can still reason about password policy while never seeing the real
value. Everything is registered in :class:`credshrike.masking.MaskContext`,
so the report can restore the original and mark the finding as masked.

Safety rules for every candidate:

* same length as the original (code points)
* not equal to the original
* not already present in the text being masked
* not equal to / a substring of any existing surrogate or original value
  (otherwise restoration could corrupt unrelated text)
"""

from __future__ import annotations

import random
import re
import string
from typing import Iterable, Optional

from .names_data import (CJK_GIVEN, CJK_SURNAMES, FIRST_NAMES, LAST_NAMES)

__all__ = ["SurrogateFactory", "person_surrogate", "password_surrogate",
           "is_cjk"]

_CJK_RE = re.compile(r"[㐀-鿿]")
_PARTS_RE = re.compile(r"([^A-Za-z0-9]+)")     # keep separators

_ONSETS = ["b", "br", "d", "dr", "f", "g", "gr", "k", "l", "m", "n", "p", "r",
           "s", "st", "t", "tr", "v", "z", "sh", "th", "ch", "j", "w"]
_NUCLEI = ["a", "e", "i", "o", "u", "ai", "ea", "ia", "io", "ou", "ie", "y"]
_CODAS = ["", "", "n", "l", "r", "s", "th", "nd", "rk", "m"]

_PASSWORD_POOLS = {
    "upper": string.ascii_uppercase,
    "lower": string.ascii_lowercase,
    "digit": string.digits,
    "symbol": "!@#$%^&*_-+=?.,:;",
}
_MASKED_CHARS = {"upper": "X", "lower": "x", "digit": "0", "symbol": "!"}
_PASSWORD_ENTITIES = {"ENV_PASSWORD", "PASSWORD", "PASSWORD_ASSIGNMENT"}


def _by_length(names: Iterable[str]) -> dict[int, list[str]]:
    index: dict[int, list[str]] = {}
    for name in sorted(set(names)):
        if name:
            index.setdefault(len(name), []).append(name)
    return index


_FIRST = _by_length(FIRST_NAMES)
_LAST = _by_length(LAST_NAMES)
_CJK_SURNAMES = list(dict.fromkeys(CJK_SURNAMES))
_CJK_GIVEN = list(dict.fromkeys(CJK_GIVEN))


def is_cjk(text: str) -> bool:
    return bool(_CJK_RE.search(text or ""))


def _match_case(template: str, candidate: str) -> str:
    if template.isupper():
        return candidate.upper()
    if template.islower():
        return candidate.lower()
    if template[:1].isupper():
        return candidate[:1].upper() + candidate[1:].lower()
    return candidate


def _pick(pool: dict[int, list[str]], length: int, initial: Optional[str],
          rng: random.Random, avoid: set[str]) -> Optional[str]:
    candidates = [n for n in pool.get(length, []) if n.lower() not in avoid]
    if not candidates:
        return None
    if initial:
        matching = [n for n in candidates if n[0].lower() == initial.lower()]
        if matching:
            candidates = matching
    return rng.choice(candidates)


def _syllable(length: int, rng: random.Random,
              initial: Optional[str] = None) -> str:
    """Pronounceable filler of exactly ``length`` letters."""
    for _ in range(40):
        out = ""
        while len(out) < length:
            out += rng.choice(_ONSETS) + rng.choice(_NUCLEI) + rng.choice(_CODAS)
        out = out[:length]
        if initial:
            out = initial.lower() + out[1:].lower()
        if out.isalpha():
            return out
    return "x" * length


def _cjk_name(value: str, rng: random.Random) -> str:
    chars = list(value)
    if len(chars) >= 2:
        return rng.choice(_CJK_SURNAMES) + "".join(
            rng.choice(_CJK_GIVEN) for _ in range(len(chars) - 1))
    return rng.choice(_CJK_GIVEN)


def person_surrogate(value: str, rng: random.Random,
                     keep_initials: bool = True,
                     style: str = "name") -> Optional[str]:
    """Real-looking same-length name (or a masked/syllable variant)."""
    if not value:
        return None

    if style == "masked":
        out = []
        for ch in value:
            if ch.isupper():
                out.append("X")
            elif ch.islower():
                out.append("x")
            elif ch.isdigit():
                out.append("0")
            else:
                out.append(ch)
        return "".join(out)

    if is_cjk(value):
        return _cjk_name(value, rng)

    parts = _PARTS_RE.split(value)
    alpha = [i for i, part in enumerate(parts) if part.isalpha()]
    if not alpha:
        return None
    first, last = alpha[0], alpha[-1]
    out = list(parts)

    for i in alpha:
        part = parts[i]
        length = len(part)
        initial = part[0] if keep_initials else None
        if i == first and i != last:
            pool = _FIRST
        elif i == last and i != first:
            pool = _LAST
        else:                                  # single token / middle part
            pool = _FIRST if rng.random() < 0.6 else _LAST
        # never reuse the original token itself (e.g. "Alice" inside a longer
        # span must not stay "Alice"), nor the whole value
        avoid = {value.lower(), part.lower()}
        candidate = None
        if style == "name":
            candidate = _pick(pool, length, initial, rng, avoid)
            if candidate is None:              # try the other pool
                candidate = _pick(_LAST if pool is _FIRST else _FIRST,
                                  length, initial, rng, avoid)
        if candidate is None:
            candidate = _syllable(length, rng, initial)
        out[i] = _match_case(part, candidate)
    return "".join(out)


def _char_class(ch: str) -> Optional[str]:
    if ch.isupper():
        return "upper"
    if ch.islower():
        return "lower"
    if ch.isdigit():
        return "digit"
    if not ch.isspace():
        return "symbol"
    return None


def password_surrogate(value: str, rng: random.Random,
                       style: str = "class") -> Optional[str]:
    """Same length + same per-character class (spaces preserved)."""
    if not value:
        return None
    out = []
    for ch in value:
        cls = _char_class(ch)
        if cls is None:
            out.append(ch)
        elif style == "masked":
            out.append(_MASKED_CHARS[cls])
        else:
            out.append(rng.choice(_PASSWORD_POOLS[cls]))
    candidate = "".join(out)
    return None if candidate == value else candidate


class SurrogateFactory:
    """Generates and validates same-length replacements for one Masker."""

    def __init__(self, *, style: str = "name", keep_initials: bool = True,
                 min_len: int = 4, rng: Optional[random.Random] = None) -> None:
        self.style = style if style in ("name", "syllable", "masked") else "name"
        self.keep_initials = bool(keep_initials)
        self.min_len = max(1, int(min_len))
        self.rng = rng or random.Random()

    def handles(self, entity: str) -> bool:
        entity = (entity or "").upper()
        return entity == "PERSON" or entity in _PASSWORD_ENTITIES

    def make(self, value: str, entity: str, text: str,
             existing: Optional[dict] = None) -> Optional[str]:
        """Return a safe same-length candidate, or None to use a placeholder."""
        if not value or len(value) < self.min_len or not self.handles(entity):
            return None
        existing = existing or {}
        for _ in range(30):
            if (entity or "").upper() == "PERSON":
                candidate = person_surrogate(value, self.rng,
                                             self.keep_initials, self.style)
            else:
                candidate = password_surrogate(value, self.rng, self.style)
            if candidate and self._safe(candidate, value, text, existing):
                return candidate
        return None

    @staticmethod
    def _safe(candidate: str, value: str, text: str, existing: dict) -> bool:
        if candidate == value:
            return False
        if candidate in text:
            return False
        for token, original in existing.items():
            if candidate == token or candidate == original:
                return False
            if candidate in token or token in candidate:
                return False
            if candidate in original or original in candidate:
                return False
        return True
