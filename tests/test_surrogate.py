"""Same-length pseudonyms (names/passwords) and the PasteGuard report badge."""

import random

import pytest

from credshrike.masking import Masker, restore_findings
from credshrike.surrogate import (SurrogateFactory, is_cjk, password_surrogate,
                                  person_surrogate)


def _cls(ch: str) -> str:
    if ch.isupper():
        return "U"
    if ch.islower():
        return "L"
    if ch.isdigit():
        return "D"
    if ch.isspace():
        return "S"
    return "P"


# --------------------------------------------------------------------------- #
# name surrogates
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["Alice Smith", "Bob Lee", "Jean-Luc Picard",
                                  "ALICE SMITH", "jean luc", "O'Brien"])
def test_person_surrogate_same_length_and_initials(name):
    out = person_surrogate(name, random.Random(7))
    assert out and len(out) == len(name) and out != name
    # initials preserved (letters only, separators untouched)
    for a, b in zip(name, out):
        if a.isalpha():
            assert b.isalpha() and b.upper() == b.upper()
    assert out[0].upper() == name[0].upper()
    assert [c for c in name if not c.isalpha()] == [c for c in out if not c.isalpha()]


def test_person_surrogate_preserves_case():
    assert person_surrogate("ALICE SMITH", random.Random(1)).isupper()
    assert person_surrogate("jean luc", random.Random(1)).islower()
    assert person_surrogate("Alice Smith", random.Random(1))[0].isupper()


def test_cjk_names_stay_cjk_and_same_length():
    out = person_surrogate("陳大文", random.Random(3))
    assert len(out) == 3 and out != "陳大文"
    assert is_cjk(out)


def test_person_surrogate_handles_separators():
    out = person_surrogate("Jean-Luc Picard", random.Random(5))
    assert out.index("-") == "Jean-Luc Picard".index("-")
    assert out.count(" ") == 1


# --------------------------------------------------------------------------- #
# password surrogates
# --------------------------------------------------------------------------- #
def test_password_surrogate_preserves_length_and_classes():
    value = "Winter2024!"
    out = password_surrogate(value, random.Random(11))
    assert out and len(out) == len(value) and out != value
    assert [_cls(c) for c in out] == [_cls(c) for c in value]


def test_password_surrogate_masked_style():
    out = password_surrogate("Winter2024!", random.Random(1), style="masked")
    assert out == "Xxxxxx0000!"


# --------------------------------------------------------------------------- #
# factory safety rails
# --------------------------------------------------------------------------- #
def test_factory_refuses_short_values():
    factory = SurrogateFactory(min_len=4)
    assert factory.make("Bob", "PERSON", "", {}) is None
    assert factory.make("abc", "ENV_PASSWORD", "", {}) is None
    assert factory.make("Alice", "PERSON", "", {}) is not None


def test_factory_avoids_text_and_existing_values():
    factory = SurrogateFactory(rng=random.Random(2))
    text = "Amber is mentioned here"
    for _ in range(20):
        candidate = factory.make("Alice", "PERSON", text, {})
        if candidate is None:
            continue
        assert candidate != "Amber"
        assert candidate not in text
    existing = {"Alice": "Alice Smith"}
    candidate = factory.make("Alice", "PERSON", "", existing)
    assert candidate not in ("Alice", "Alice Smith")


# --------------------------------------------------------------------------- #
# masker integration
# --------------------------------------------------------------------------- #
def test_masker_uses_surrogate_for_person_and_restores():
    masker = Masker(pii=False, secrets=False,
                    denylist=[{"pattern": "Alice Smith", "type": "PERSON"}])
    text = "Owner: Alice Smith"
    masked, hits = masker.mask_text(text)
    assert hits == 1 and "Alice Smith" not in masked
    assert len(masked) == len(text)
    assert masker.entities_in(masked) == {"PERSON"}
    assert masker.restore(masked) == text


def test_short_password_falls_back_to_placeholder():
    masker = Masker(pii=False, secrets=False,
                    denylist=[{"pattern": "abc", "type": "ENV_PASSWORD"}])
    masked, _ = masker.mask_text("x abc y")
    assert "[[ENV_PASSWORD_1]]" in masked


def test_same_length_can_be_disabled():
    masker = Masker(pii=False, secrets=False,
                    denylist=[{"pattern": "Alice Smith", "type": "PERSON"}],
                    same_length_entities=[])
    masked, _ = masker.mask_text("Alice Smith")
    assert masked == "[[PERSON_1]]"


def test_restored_findings_are_marked_as_masked():
    masker = Masker(pii=False, secrets=True)
    masked, _ = masker.mask_text("DB_PASSWORD=Sup3rS3cret!")
    surrogate = masked.split("=", 1)[1]
    findings = [{"username": "svc", "secret": surrogate,
                 "evidence": f"line: {masked}", "note": "", "path": "a.txt"}]
    restore_findings(findings, masker)
    assert findings[0]["secret"] == "Sup3rS3cret!"
    assert findings[0]["masked"] is True
    assert "ENV_PASSWORD" in findings[0]["mask_entities"]


# --------------------------------------------------------------------------- #
# report badge
# --------------------------------------------------------------------------- #
def test_report_marks_pasteguard_in_credentials_and_findings(tmp_path):
    from credshrike.report import build_report_html

    audit = tmp_path / "audit.jsonl"
    audit.write_text("", encoding="utf-8")
    finding = {"severity": "high", "category": "credential", "host": "h",
               "share": "IT", "path": "a.txt", "username": "svc",
               "secret": "Winter2024!", "evidence": "read a.txt", "note": "",
               "masked": True, "mask_entities": ["ENV_PASSWORD"]}
    html = build_report_html(
        context={"principal": "corp\\svc", "auth_type": "password"},
        findings=[finding], scan_results=[], flagged=[], report_md="",
        audit_path=str(audit), masking={"entities": {"ENV_PASSWORD": 1},
                                        "restored": True})
    assert "PasteGuard" in html
    assert "🔒" in html and "ENV_PASSWORD" in html
    assert "originals restored" in html
