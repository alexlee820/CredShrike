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
           "username_surrogate", "email_surrogate", "is_cjk"]

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
_USERNAME_ENTITIES = {"USERNAME"}
_EMAIL_ENTITIES = {"EMAIL_ADDRESS"}
_USERNAME_PREFIXES = ("svc-", "svc_", "adm-", "adm_", "admin-", "admin_",
                      "srv-", "srv_", "test-", "test_", "app-", "app_")


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


def _numeric_part(part: str, rng: random.Random) -> str:
    """Keep digit positions; letters become random lowercase letters."""
    return "".join(rng.choice(string.digits) if ch.isdigit()
                   else rng.choice(string.ascii_lowercase) if ch.isalpha()
                   else ch for ch in part)


def _word_part(part: str, pool: dict[int, list[str]], rng: random.Random,
               avoid: set[str], initial: Optional[str] = None) -> str:
    if not part.isalpha():
        return _numeric_part(part, rng)
    length = len(part)
    candidate = _pick(pool, length, initial, rng, avoid)
    if candidate is None and length >= 5:
        # classic AD shape: first initial + surname (jchen -> kford)
        tail = _pick(_LAST, length - 1, None, rng, avoid)
        if tail:
            candidate = rng.choice(string.ascii_lowercase) + tail
    if candidate is None:
        candidate = _pick(_LAST, length, None, rng, avoid)
    if candidate is None:
        candidate = _syllable(length, rng, None)
    return candidate.lower() if part.islower() else _match_case(part, candidate)


def username_surrogate(value: str, rng: random.Random,
                       keep_initials: bool = True) -> Optional[str]:
    """Realistic, same-length account name. Preserves:

    * common role prefixes (``svc-``, ``adm_``, ...)
    * separators (``.``/``_``/``-``) and digit positions
    * machine-account ``$`` suffix and letter case
    """
    if not value:
        return None
    trailing = "$" if value.endswith("$") else ""
    body = value[:-1] if trailing else value
    prefix = ""
    for candidate_prefix in _USERNAME_PREFIXES:
        if body.lower().startswith(candidate_prefix):
            prefix = body[:len(candidate_prefix)]
            body = body[len(candidate_prefix):]
            break
    if not body:
        return None

    parts = _PARTS_RE.split(body)
    alpha = [i for i, part in enumerate(parts) if any(c.isalpha() for c in part)]
    if not alpha:
        return None
    out = list(parts)
    avoid = {value.lower(), body.lower()}

    if len(alpha) == 1:
        i = alpha[0]
        part = parts[i]
        out[i] = _word_part(part, _LAST if len(part) >= 4 else _FIRST,
                            rng, avoid | {part.lower()},
                            part[0] if (keep_initials and len(part) > 2) else None)
    else:
        first, last = alpha[0], alpha[-1]
        for i in alpha:
            part = parts[i]
            if i == first:
                pool = _FIRST
            elif i == last:
                pool = _LAST
            else:
                pool = _FIRST if rng.random() < 0.5 else _LAST
            out[i] = _word_part(part, pool, rng, avoid | {part.lower()},
                                part[0] if (keep_initials and len(part) > 2) else None)

    result = prefix + "".join(out) + trailing
    return None if result == value else result


def email_surrogate(value: str, rng: random.Random,
                    domain: str = "corp.local") -> Optional[str]:
    """``jchen@hackaday.lab`` -> ``kford@corp.local`` (local part realistic,
    domain normalised; the whole string is restored later)."""
    local, sep, original_domain = value.rpartition("@")
    if not sep or not local:
        return None
    new_local = username_surrogate(local, rng)
    if not new_local or new_local.lower() == local.lower():
        return None
    return f"{new_local}@{domain or original_domain}"


class SurrogateFactory:
    """Generates and validates same-length replacements for one Masker."""

    def __init__(self, *, style: str = "name", keep_initials: bool = True,
                 min_len: int = 4, rng: Optional[random.Random] = None,
                 email_domain: str = "corp.local",
                 netbios_domain: str = "corp") -> None:
        self.style = style if style in ("name", "syllable", "masked") else "name"
        self.keep_initials = bool(keep_initials)
        self.min_len = max(1, int(min_len))
        self.rng = rng or random.Random()
        self.email_domain = email_domain or "corp.local"
        self.netbios_domain = netbios_domain or "corp"
        self._username_map: dict[str, str] = {}

    def handles(self, entity: str) -> bool:
        entity = (entity or "").upper()
        return (entity == "PERSON" or entity in _PASSWORD_ENTITIES
                or entity in _USERNAME_ENTITIES or entity in _EMAIL_ENTITIES)

    def _username(self, value: str, text: str, existing: dict) -> Optional[str]:
        """One surrogate per original account name across this context."""
        key = value.lower()
        cached = self._username_map.get(key)
        if cached and self._safe(cached, value, text, existing):
            return cached
        for _ in range(30):
            candidate = username_surrogate(value, self.rng, self.keep_initials)
            if candidate and candidate.lower() != key and \
                    self._safe(candidate, value, text, existing):
                self._username_map[key] = candidate
                return candidate
        return None

    def make(self, value: str, entity: str, text: str,
             existing: Optional[dict] = None) -> Optional[str]:
        """Return a safe surrogate, or None to use a placeholder."""
        entity = (entity or "").upper()
        if not value or not self.handles(entity):
            return None
        existing = existing or {}

        if entity in _EMAIL_ENTITIES:
            local, sep, _domain = value.rpartition("@")
            if not sep or len(local) < 2:
                return None
            new_local = self._username(local, text, existing)
            if not new_local:
                return None
            candidate = f"{new_local}@{self.email_domain}"
            return candidate if self._safe(candidate, value, text, existing) else None

        if entity in _USERNAME_ENTITIES and "\\" in value:
            # DOMAIN\user -> corp\user (or corp.local\user for an FQDN domain)
            domain, _sep, user = value.partition("\\")
            if len(user) < 2:
                return None
            new_user = self._username(user, text, existing)
            if not new_user:
                return None
            new_domain = self.email_domain if "." in domain else self.netbios_domain
            candidate = f"{new_domain}\\{new_user}"
            return candidate if self._safe(candidate, value, text, existing) else None

        if len(value) < self.min_len:
            return None

        for _ in range(30):
            if entity == "PERSON":
                candidate = person_surrogate(value, self.rng,
                                             self.keep_initials, self.style)
            elif entity in _USERNAME_ENTITIES:
                candidate = self._username(value, text, existing)
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
            if candidate == token:
                # Reusing an account's own bare token (same original value)
                # is exactly what we want (bare username vs DOMAIN\user vs
                # email local part); any other collision is not.
                if original == value:
                    continue
                return False
            if candidate == original:
                return False
            # A candidate may legitimately occur inside a longer token (the
            # bare username inside that account's email); longest-first
            # restore handles that. It must never overlap a REAL value, or
            # restoring the longer token first would corrupt the shorter one.
            if candidate in original or original in candidate:
                return False
        return True
