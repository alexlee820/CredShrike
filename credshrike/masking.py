"""PasteGuard-style privacy masking for content bound for the LLM.

Python port of the ``mask`` half of https://github.com/sgasser/pasteguard
(the proxy itself is Node.js; its detector is a Python service). Applied at the
one place where CredShrike content leaves for the model — share dumps and tool
results — so PII and secrets are replaced with placeholders before they reach
the provider, then restored in the model's output for the operator's report.

Detection is deterministic: format regexes plus checksums (Luhn, IBAN mod-97,
python-stdnum for EU VAT when installed, libphonenumber when installed).
PasteGuard's semantic backend (GLiNER: PERSON, LOCATION) is intentionally not
ported — it requires an ML model download; use ``mask_denylist`` for the
names/codenames that matter on your engagement.

Placeholders use PasteGuard's format (``[[TYPE_N]]``); identical values reuse
one placeholder. ``restore()`` is exact-string, longest-placeholder-first.

Adaptation vs upstream: where a pattern targets an assignment (``DB_PASSWORD=x``,
``Bearer x``, ``postgres://u:p@h``) only the *value* group is masked, so the
model still sees the surrounding context and can classify the finding.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

__all__ = ["Detector", "MaskContext", "Masker", "restore_findings"]

PLACEHOLDER_OPEN = "[["
PLACEHOLDER_CLOSE = "]]"

# Optional validators — used when the extra package happens to be installed.
try:  # pragma: no cover - environment dependent
    import phonenumbers as _phonenumbers
except Exception:  # noqa: BLE001
    _phonenumbers = None
try:  # pragma: no cover - environment dependent
    from stdnum.eu import vat as _eu_vat
except Exception:  # noqa: BLE001
    _eu_vat = None


# --------------------------------------------------------------------------- #
# checksum validators
# --------------------------------------------------------------------------- #
def _luhn_valid(value: str) -> bool:
    digits = re.sub(r"[\s\-]", "", value)
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _ipv4_valid(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _ipv6_valid(value: str) -> bool:
    candidate = value.rstrip(".")
    if ":" not in candidate:
        return False
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


def _iban_valid(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if not 5 <= len(compact) <= 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
        return int(numeric) % 97 == 1
    except ValueError:
        return False


_VAT_COUNTRIES = ("AT|BE|BG|HR|CY|CZ|DK|EE|FI|FR|DE|EL|GR|HU|IE|IT|LV|LT|LU|"
                  "MT|NL|PL|PT|RO|SK|SI|ES|SE|EU")
_VAT_RE = re.compile(r"(?<![A-Za-z0-9])(" + _VAT_COUNTRIES + r")[ ]?([0-9A-Za-z]{8,12})(?![A-Za-z0-9])")


def _vat_valid(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if len(compact) < 10:
        return False
    if _eu_vat is not None:  # upstream behaviour: real checksum when available
        try:
            return bool(_eu_vat.is_valid(compact))
        except Exception:  # noqa: BLE001 - unknown country: fall through
            return False
    # structural fallback: require the country code to be uppercase in the
    # source text and at least two digits in the body (cuts obvious false hits)
    return value[:2].isupper() and sum(c.isdigit() for c in value) >= 2


def _phone_valid(value: str) -> bool:
    if not 8 <= len(re.sub(r"\D", "", value)) <= 15:
        return False
    if _phonenumbers is not None:
        # libphonenumber, when installed, is the real validity judgment;
        # international form first, then the common national formats
        for region in (None, "US", "GB", "DE", "IT", "IN"):
            try:
                if _phonenumbers.is_valid_number(_phonenumbers.parse(value, region)):
                    return True
            except Exception:  # noqa: BLE001 - unparseable in this region
                continue
        return False
    return True


# --------------------------------------------------------------------------- #
# detectors
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Detector:
    """One regex + validator pair. ``group`` selects the span to mask (0 =
    the whole match; a capture group keeps surrounding context visible)."""
    entity: str
    pattern: re.Pattern
    group: int = 0
    validate: Optional[Callable[[str], bool]] = None
    kind: str = "secret"
    # space-separated formats (IBAN): the greedy pattern can swallow the next
    # token(s); drop trailing tokens until the value validates (upstream
    # PasteGuard does the same in its detector)
    trim_spaces: bool = False


_EMAIL_RE = re.compile(
    r"(?<![\w.%+\-@])[\w%+\-]+(?:\.[\w%+\-]+)*@(?:[\w\-]+\.)+[^\W\d_]{2,}(?![\w\-])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])(?!\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f.:]{2,45}(?![\w:.])")
_IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]{2}[0-9]{2}(?:[ ]?[A-Za-z0-9]){11,30}(?![A-Za-z0-9])")
_CARD_RE = re.compile(r"(?<![\d])(?:\d[ \-]?){13,19}(?<![\s\-])(?!\d)")
_PHONE_INTL_RE = re.compile(
    r"(?<![\w+])\+\d{1,3}[\s.\-]?(?:\(\d{1,4}\)[\s.\-]?)?(?:\d[\s.\-]?){6,14}\d(?![\w])")
_PHONE_US_RE = re.compile(
    r"(?<![\w])(?:\(\d{3}\)[\s.\-]?\d{3}[\s.\-]?\d{4}|\d{3}[\s.\-]\d{3}[\s.\-]\d{4})(?![\w])")

_OPENSSH_KEY_RE = re.compile(
    r"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----", re.DOTALL)
_PEM_KEY_RES = (
    re.compile(r"-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----", re.DOTALL),
    re.compile(r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.DOTALL),
    re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-----.*?-----END ENCRYPTED PRIVATE KEY-----",
               re.DOTALL),
)

_SK_RE = re.compile(r"sk[-_][a-zA-Z0-9_-]{20,}")
_AWS_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_GITHUB_RE = re.compile(r"gh[pousr]_[a-zA-Z0-9]{36,}")
_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{20,}\.eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}")
_BEARER_RE = re.compile(r"Bearer\s+([a-zA-Z0-9._-]{40,})", re.IGNORECASE)
_ENV_PASSWORD_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]{0,128}(?:PASSWORD|_PWD)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
    re.IGNORECASE)
_ENV_SECRET_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]{0,128}_SECRET\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
    re.IGNORECASE)
_PASSWORD_ASSIGN_RE = re.compile(
    r"\b(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]?([^\s'\"]{6,})['\"]?", re.IGNORECASE)
_CONN_RE = re.compile(
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://"
    r"([^:\s]+):([^@\s]+)@", re.IGNORECASE)


def _pii_detectors() -> list[Detector]:
    detectors = [
        Detector("EMAIL_ADDRESS", _EMAIL_RE, kind="pii"),
        Detector("IP_ADDRESS", _IPV6_RE, validate=_ipv6_valid, kind="pii"),
        Detector("IP_ADDRESS", _IPV4_RE, validate=_ipv4_valid, kind="pii"),
        Detector("IBAN_CODE", _IBAN_RE, validate=_iban_valid, kind="pii",
                 trim_spaces=True),
        Detector("VAT_CODE", _VAT_RE, validate=_vat_valid, kind="pii"),
        Detector("CREDIT_CARD", _CARD_RE, validate=_luhn_valid, kind="pii"),
    ]
    detectors.append(Detector("PHONE_NUMBER", _PHONE_INTL_RE, validate=_phone_valid, kind="pii"))
    detectors.append(Detector("PHONE_NUMBER", _PHONE_US_RE, validate=_phone_valid, kind="pii"))
    return detectors


def _secret_detectors() -> list[Detector]:
    detectors = [
        Detector("OPENSSH_PRIVATE_KEY", _OPENSSH_KEY_RE),
        *[Detector("PEM_PRIVATE_KEY", rx) for rx in _PEM_KEY_RES],
        Detector("CONNECTION_STRING", _CONN_RE, group=2),
        Detector("ENV_PASSWORD", _ENV_PASSWORD_RE, group=1),
        Detector("ENV_SECRET", _ENV_SECRET_RE, group=1),
        Detector("ENV_PASSWORD", _PASSWORD_ASSIGN_RE, group=1),
        Detector("API_KEY_SK", _SK_RE),
        Detector("API_KEY_AWS", _AWS_RE),
        Detector("API_KEY_GITHUB", _GITHUB_RE),
        Detector("JWT_TOKEN", _JWT_RE),
        Detector("BEARER_TOKEN", _BEARER_RE, group=1),
    ]
    return detectors


def _denylist_detectors(entries: Iterable) -> list[Detector]:
    detectors = []
    for entry in entries or []:
        if isinstance(entry, str):
            entry = {"pattern": entry}
        pattern = str(entry.get("pattern") or "")
        if not pattern:
            continue
        is_regex = bool(entry.get("regex", False))
        entity = str(entry.get("type") or "DENYLIST").upper().replace(" ", "_")
        try:
            rx = re.compile(pattern if is_regex else re.escape(pattern))
        except re.error:
            continue
        detectors.append(Detector(entity, rx))
    return detectors


def _is_llm_marker(value: str) -> bool:
    """Never mask something we (or the redaction layer) produced ourselves —
    ``[REDACTED]`` and existing ``[[TYPE_N]]`` placeholders must survive."""
    v = value.strip()
    return (v.startswith(PLACEHOLDER_OPEN) and v.endswith(PLACEHOLDER_CLOSE)) \
        or v.upper() == "[REDACTED]" or "REDACTED" in v.upper()


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(not (end <= s or start >= e) for s, e in spans)


def _subtract_overlaps(start: int, end: int,
                       blockers: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Fragments of [start, end) not covered by any blocker (upstream's
    semantic-vs-deterministic merge: deterministic spans win, the uncovered
    parts of a fuzzy span remain eligible)."""
    pieces = [(start, end)]
    for bstart, bend in blockers:
        remaining = []
        for pstart, pend in pieces:
            if bend <= pstart or bstart >= pend:
                remaining.append((pstart, pend))
                continue
            if pstart < bstart:
                remaining.append((pstart, bstart))
            if bend < pend:
                remaining.append((bend, pend))
        pieces = remaining
    return pieces


# --------------------------------------------------------------------------- #
# placeholder context
# --------------------------------------------------------------------------- #
class MaskContext:
    """Placeholder <-> original mapping for one conversation/context window.
    Thread-safe: tool results may be sanitized from worker threads."""

    def __init__(self) -> None:
        self.mapping: dict[str, str] = {}     # placeholder -> original
        self.reverse: dict[str, str] = {}     # original -> placeholder
        self.counters: dict[str, int] = {}    # type -> last index
        self.hits: dict[str, int] = {}        # type -> distinct values masked
        self._lock = threading.Lock()

    def placeholder_for(self, entity: str, value: str, text: str) -> str:
        with self._lock:
            existing = self.reverse.get(value)
            if existing:
                return existing
            while True:
                n = self.counters.get(entity, 0) + 1
                self.counters[entity] = n
                placeholder = f"{PLACEHOLDER_OPEN}{entity}_{n}{PLACEHOLDER_CLOSE}"
                # never collide with a placeholder that already exists in the
                # source text (it would be restored to the wrong value)
                if placeholder not in self.mapping and placeholder not in text:
                    break
            self.mapping[placeholder] = value
            self.reverse[value] = placeholder
            self.hits[entity] = self.hits.get(entity, 0) + 1
            return placeholder

    def restore(self, text: str, marker_text: str = "",
                show_markers: bool = False) -> str:
        if not text or not self.mapping:
            return text
        # longest first: a shorter placeholder must never eat a longer one
        for placeholder in sorted(self.mapping, key=len, reverse=True):
            if placeholder in text:
                original = self.mapping[placeholder]
                if show_markers and marker_text:
                    original = marker_text + original
                text = text.replace(placeholder, original)
        return text

    def summary(self) -> dict[str, int]:
        with self._lock:
            return dict(self.hits)

    @classmethod
    def from_mapping(cls, mapping: dict) -> "MaskContext":
        """Rebuild a context from a saved placeholder -> original map (CLI
        restore path: mask now, restore later with --mapping)."""
        context = cls()
        context.mapping = dict(mapping)
        context.reverse = {v: k for k, v in context.mapping.items()}
        return context


# --------------------------------------------------------------------------- #
# masker
# --------------------------------------------------------------------------- #
class Masker:
    """Detect -> placeholder -> restore. One Masker per context window."""

    def __init__(self, *, pii: bool = True, secrets: bool = True,
                 max_scan_chars: int = 200_000,
                 allowlist: Optional[list] = None,
                 denylist: Optional[list] = None,
                 marker_text: str = "[protected]",
                 show_markers: bool = False,
                 semantic_backend=None,
                 semantic_threshold: float = 0.7) -> None:
        self.context = MaskContext()
        self.max_scan_chars = max(1000, int(max_scan_chars or 200_000))
        self.marker_text = marker_text
        self.show_markers = bool(show_markers)
        self.allowlist = list(allowlist or [])
        detectors = _denylist_detectors(denylist or [])
        if secrets:
            detectors += _secret_detectors()
        if pii:
            detectors += _pii_detectors()
        self.detectors = detectors
        # optional GLiNER layer (PERSON / LOCATION); deterministic detectors
        # still win on overlap, exactly like upstream's merge
        self.semantic_backend = semantic_backend
        self.semantic_threshold = float(semantic_threshold)

    @classmethod
    def from_policy(cls, policy) -> Optional["Masker"]:
        """Build the session masker, or None when masking is disabled.
        The semantic (GLiNER) backend is loaded EAGERLY when configured so a
        missing package/model fails before any SMB traffic starts."""
        pii = bool(getattr(policy, "mask_pii", False))
        secrets = bool(getattr(policy, "mask_secrets", False))
        semantic = bool(getattr(policy, "mask_semantic", False))
        if not (pii or secrets or semantic):
            return None
        backend = None
        if semantic:
            from .semantic import get_backend
            backend = get_backend(
                model_name=str(getattr(policy, "mask_semantic_model", "") or ""),
                labels=list(getattr(policy, "mask_semantic_labels", []) or []),
                threshold=float(getattr(policy, "mask_semantic_threshold", 0.7)),
                floors=dict(getattr(policy, "mask_semantic_floors", {}) or {}),
                max_tokens=int(getattr(policy, "mask_semantic_max_tokens", 384)),
                overlap=int(getattr(policy, "mask_semantic_overlap", 64)),
            )
        return cls(
            pii=pii, secrets=secrets,
            max_scan_chars=int(getattr(policy, "mask_max_scan_chars", 200_000)),
            allowlist=list(getattr(policy, "mask_allowlist", []) or []),
            denylist=list(getattr(policy, "mask_denylist", []) or []),
            marker_text=str(getattr(policy, "mask_marker_text", "[protected]")),
            show_markers=bool(getattr(policy, "mask_show_markers", False)),
            semantic_backend=backend,
            semantic_threshold=float(getattr(policy, "mask_semantic_threshold", 0.7)),
        )

    # ------------------------------------------------------------------ #
    def mask_text(self, text: str) -> tuple[str, int]:
        """Mask one string; returns (masked_text, values_masked)."""
        if not text or (not self.detectors and self.semantic_backend is None):
            return text, 0
        allow_spans = self._allow_spans(text)
        pieces: list[str] = []
        hits = 0
        for offset, chunk in _chunks(text, self.max_scan_chars):
            masked_chunk, chunk_hits = self._mask_chunk(chunk, offset, allow_spans)
            pieces.append(masked_chunk)
            hits += chunk_hits
        return "".join(pieces), hits

    def mask_obj(self, obj):
        """Recursively mask every string in a tool result (lists/dicts)."""
        if isinstance(obj, dict):
            return {k: self.mask_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.mask_obj(v) for v in obj]
        if isinstance(obj, str):
            return self.mask_text(obj)[0]
        return obj

    def restore(self, text: str) -> str:
        return self.context.restore(text, self.marker_text, self.show_markers)

    def summary(self) -> dict[str, int]:
        return self.context.summary()

    # ------------------------------------------------------------------ #
    def _allow_spans(self, text: str) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for entry in self.allowlist:
            if isinstance(entry, str):
                entry = {"pattern": entry}
            pattern = str(entry.get("pattern") or "")
            if not pattern:
                continue
            try:
                rx = re.compile(pattern if entry.get("regex") else re.escape(pattern))
            except re.error:
                continue
            for match in rx.finditer(text):
                spans.append(match.span())
        return spans

    def _mask_chunk(self, chunk: str, offset: int,
                    allow_spans: list[tuple[int, int]]) -> tuple[str, int]:
        accepted: list[tuple[int, int]] = []
        edits: list[tuple[int, int, str]] = []
        for detector in self.detectors:
            for match in detector.pattern.finditer(chunk):
                try:
                    start, end = match.span(detector.group)
                except IndexError:
                    continue
                if start < 0 or end <= start:
                    continue
                value = chunk[start:end]
                if _is_llm_marker(value):
                    continue
                if detector.validate is not None and not detector.validate(value):
                    if not detector.trim_spaces:
                        continue
                    # drop trailing space-separated tokens until valid
                    while " " in value:
                        value = value.rsplit(" ", 1)[0]
                        if detector.validate(value):
                            end = start + len(value)
                            break
                    else:
                        continue
                if _overlaps(start + offset, end + offset, allow_spans):
                    continue
                if _overlaps(start, end, accepted):
                    continue
                placeholder = self.context.placeholder_for(detector.entity, value, chunk)
                accepted.append((start, end))
                edits.append((start, end, placeholder))

        if self.semantic_backend is not None:
            edits.extend(self._semantic_edits(chunk, offset, allow_spans, accepted))

        if not edits:
            return chunk, 0
        # splice back-to-front so earlier offsets stay valid
        for start, end, placeholder in sorted(edits, reverse=True):
            chunk = chunk[:start] + placeholder + chunk[end:]
        return chunk, len(edits)

    def _semantic_edits(self, chunk: str, offset: int,
                        allow_spans: list[tuple[int, int]],
                        accepted: list[tuple[int, int]]) -> list[tuple[int, int, str]]:
        """GLiNER pass. Deterministic spans already in ``accepted`` win on
        overlap; the uncovered fragments of a semantic span stay eligible
        (upstream's _subtract_overlaps merge). Longest fragment first, then
        higher score — same as upstream's fuzzy ordering."""
        # NO exception swallowing: if semantic masking is configured and the
        # backend fails, the run must stop rather than send unmasked content
        spans = self.semantic_backend.detect(chunk, threshold=self.semantic_threshold)
        candidates: list[tuple[int, float, int, int, str]] = []
        for span in spans:
            if not 0 <= span.start < span.end <= len(chunk):
                continue
            if _overlaps(span.start + offset, span.end + offset, allow_spans):
                continue
            for frag_start, frag_end in _subtract_overlaps(span.start, span.end, accepted):
                if frag_end <= frag_start:
                    continue
                if _is_llm_marker(chunk[frag_start:frag_end]):
                    continue
                candidates.append((-(frag_end - frag_start), -span.score,
                                   frag_start, frag_end, span.entity))
        edits: list[tuple[int, int, str]] = []
        for _neg_len, _neg_score, start, end, entity in sorted(candidates):
            if _overlaps(start, end, accepted):
                continue
            placeholder = self.context.placeholder_for(entity, chunk[start:end], chunk)
            accepted.append((start, end))
            edits.append((start, end, placeholder))
        return edits


def _chunks(text: str, size: int):
    """Yield (offset, chunk) covering the WHOLE text — unlike upstream's
    ``max_scan_chars`` truncation, nothing past the cap is left unmasked."""
    if len(text) <= size:
        yield 0, text
        return
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        if end < len(text):
            newline = text.rfind("\n", start, end)
            if newline > start + size // 2:
                end = newline + 1
        yield start, text[start:end]
        start = end


# --------------------------------------------------------------------------- #
def restore_findings(findings: list[dict], masker: Optional[Masker],
                     fields: Iterable[str] = ("host", "share", "path", "username",
                                              "secret", "evidence", "note")) -> list[dict]:
    """Put original values back into extracted findings (they were parsed
    from a masked conversation, so secrets arrive as placeholders)."""
    if masker is None:
        return findings
    for finding in findings:
        for field in fields:
            value = finding.get(field)
            if isinstance(value, str) and value:
                finding[field] = masker.restore(value)
    return findings
