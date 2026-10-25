"""GLiNER semantic PII backend for the masker (PERSON / LOCATION / ADDRESS).

Python port of PasteGuard's ``detector/detector/gliner_layer.py``. The
deterministic detectors in :mod:`credshrike.masking` handle structured values
(emails, cards, keys, ...); this backend adds the names-and-places layer that
regexes cannot see.

It is OPTIONAL: ``gliner`` pulls torch and downloads a model on first use.
Enable with ``--mask-semantic`` (or ``mask_semantic: true``); when the package
is missing the run fails fast with an install hint instead of silently
sending unmasked PII — mirroring upstream PasteGuard, which has no degraded
fallback either.

Labels/thresholds match upstream:

- labels ``person``, ``location``, ``address``; ``address`` maps to LOCATION
- first use downloads ``urchade/gliner_multi_pii-v1`` (~1.1 GB)
- per-label floors: person 0.99, location 0.80, address 0.80
- the call-level threshold can only RAISE a floor (``max``)
- 384-token windows, 64-token overlap, inference serialized by a lock
"""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

__all__ = ["SemanticSpan", "GlinerBackend", "get_backend", "token_windows",
           "model_cache_root", "materialize_model",
           "DEFAULT_MODEL", "DEFAULT_LABELS", "LABEL_ENTITIES"]

DEFAULT_MODEL = "urchade/gliner_multi_pii-v1"
DEFAULT_LABELS = ("person", "location", "address")
LABEL_ENTITIES = {"person": "PERSON", "location": "LOCATION",
                  "address": "LOCATION"}     # Presidio-compatible entity set
DEFAULT_FLOORS = {"person": 0.99, "location": 0.80, "address": 0.80}

_TOKEN_RE = re.compile(r"\w+(?:[-_]\w+)*|\S")
_MODEL_DIR_ENV = "CREDSHRIKE_MODEL_DIR"


def model_cache_root() -> Path:
    """Where Windows-safe snapshots are stored (override: CREDSHRIKE_MODEL_DIR)."""
    override = os.environ.get(_MODEL_DIR_ENV)
    if override:
        return Path(os.path.expanduser(override))
    return Path.home() / ".cache" / "credshrike" / "models"


def materialize_model(model_id: str) -> str:
    """Download a HF repo with ``snapshot_download(local_dir=...)``.

    huggingface_hub's default cache stores blobs and links them with symlinks.
    Windows cannot create symlinks without Developer Mode or administrator
    rights, which surfaces as ``OSError: [WinError 1314] A required privilege
    is not held by the client`` (not a PermissionError, so hf_hub's copy
    fallback misses it). ``local_dir`` writes real files to a stable folder
    instead — no symlinks, no privilege needed.
    """
    from huggingface_hub import snapshot_download

    slug = model_id.replace("/", "--").replace(":", "-")
    target = model_cache_root() / slug
    if not (target / "gliner_config.json").is_file():
        snapshot_download(repo_id=model_id, local_dir=str(target))
    return str(target)


@dataclass(frozen=True)
class SemanticSpan:
    entity: str
    start: int
    end: int
    score: float


def token_windows(text: str, max_tokens: int = 384,
                  overlap: int = 64) -> Iterator[tuple[int, str]]:
    """Yield (char_offset, window) covering the whole text in token windows.
    Same geometry as upstream: window = max(64, max_tokens-64), step =
    window - overlap; short texts are a single window."""
    max_tokens = max(64, int(max_tokens or 384))
    window = max(64, max_tokens - 64)
    overlap = max(0, min(int(overlap or 0), window - 1))
    step = max(1, window - overlap)
    tokens = list(_TOKEN_RE.finditer(text))
    if len(tokens) <= max_tokens:
        yield 0, text
        return
    for start in range(0, len(tokens), step):
        chunk = tokens[start:start + window]
        if not chunk:
            break
        cstart, cend = chunk[0].start(), chunk[-1].end()
        yield cstart, text[cstart:cend]
        if start + window >= len(tokens):
            break


class GlinerBackend:
    """Lazy, thread-safe GLiNER wrapper. ``load()`` is idempotent."""

    name = "gliner"

    def __init__(self, model_name: str = DEFAULT_MODEL,
                 labels: Optional[Iterable[str]] = None,
                 threshold: float = 0.7,
                 floors: Optional[dict] = None,
                 max_tokens: int = 384,
                 overlap: int = 64) -> None:
        self.model_name = model_name or DEFAULT_MODEL
        self.labels = tuple(labels or DEFAULT_LABELS)
        self.threshold = float(threshold)
        self.floors = {**DEFAULT_FLOORS, **(floors or {})}
        self.max_tokens = int(max_tokens or 384)
        self.overlap = int(overlap or 64)
        self._model = None
        self._lock = threading.Lock()

    @property
    def model(self) -> str:
        return self.model_name

    # ------------------------------------------------------------------ #
    def load(self) -> None:
        if self._model is not None:
            return
        try:
            from gliner import GLiNER
        except ImportError as exc:  # pragma: no cover - env dependent
            raise RuntimeError(
                "semantic masking needs the optional 'gliner' package — install "
                "it with: pip install \"gliner>=0.2.27,<0.3\"  (pulls torch; the "
                f"model {self.model_name!r} downloads on first use)") from exc
        try:
            model_ref = os.path.expanduser(self.model_name)
            if os.name == "nt" and not Path(model_ref).exists():
                # avoid the symlink-based HF cache on Windows (see module doc)
                model_ref = materialize_model(self.model_name)
            self._model = GLiNER.from_pretrained(model_ref)
        except Exception as exc:  # pragma: no cover - model/network dependent
            raise RuntimeError(
                f"failed to load GLiNER model {self.model_name!r}: "
                f"{type(exc).__name__}: {exc}") from exc

    # ------------------------------------------------------------------ #
    def detect(self, text: str, threshold: Optional[float] = None) -> list[SemanticSpan]:
        """Entity spans with absolute character offsets."""
        if not text or not text.strip() or not self.labels:
            return []
        self.load()
        call_threshold = self.threshold if threshold is None else float(threshold)
        floors = {label: max(float(self.floors.get(label, 0.0)), call_threshold)
                  for label in self.labels}
        # query the model below the strictest floor, then filter per label
        predict_floor = max(0.0, min(floors.values()) - 0.1)

        best: dict[tuple[int, int, str], float] = {}
        with self._lock:      # torch inference is not assumed thread-safe
            for offset, window in token_windows(text, self.max_tokens, self.overlap):
                for entity in self._model.predict_entities(
                        window, list(self.labels), threshold=predict_floor):
                    label = str(entity.get("label", "")).lower()
                    mapped = LABEL_ENTITIES.get(label)
                    if mapped is None:
                        continue
                    score = float(entity.get("score", 0.0))
                    if score < floors.get(label, 1.0):
                        continue
                    start = offset + int(entity.get("start", 0))
                    end = offset + int(entity.get("end", 0))
                    if not 0 <= start < end <= len(text):
                        continue
                    key = (start, end, label)     # overlapping windows: max score
                    if score > best.get(key, -1.0):
                        best[key] = score

        spans = [SemanticSpan(LABEL_ENTITIES[label], start, end, score)
                 for (start, end, label), score in best.items()]
        spans.sort(key=lambda span: (span.start, span.end))
        return spans


# --------------------------------------------------------------------------- #
# process-wide singleton: the model is loaded ONCE, no matter how many
# sessions/batches (one per context window) ask for a masker
# --------------------------------------------------------------------------- #
_BACKENDS: dict[tuple, GlinerBackend] = {}
_BACKEND_LOCK = threading.Lock()


def get_backend(model_name: str = DEFAULT_MODEL,
                labels: Optional[Iterable[str]] = None,
                threshold: float = 0.7,
                floors: Optional[dict] = None,
                max_tokens: int = 384,
                overlap: int = 64) -> GlinerBackend:
    """Shared, eagerly-loaded backend (fails fast with an install hint)."""
    model_name = model_name or DEFAULT_MODEL
    labels = tuple(labels or DEFAULT_LABELS)
    key = (model_name, labels, tuple(sorted((floors or {}).items())),
           int(max_tokens), int(overlap))
    with _BACKEND_LOCK:
        backend = _BACKENDS.get(key)
        if backend is None:
            backend = GlinerBackend(model_name=model_name, labels=labels,
                                    threshold=threshold, floors=floors,
                                    max_tokens=max_tokens, overlap=overlap)
            _BACKENDS[key] = backend
    backend.load()          # idempotent; raises a clear error when unavailable
    return backend
