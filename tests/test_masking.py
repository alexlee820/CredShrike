"""PasteGuard-style masking: detection, placeholders, restore, integration."""

import json
from types import SimpleNamespace

import pytest

from credshrike.config import Policy
from credshrike.masking import Masker, restore_findings

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SK_KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvbiJ9."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")


def _secret_masker(**kw):
    return Masker(pii=False, secrets=True, **kw)


# --------------------------------------------------------------------------- #
# detection + restore
# --------------------------------------------------------------------------- #
def test_email_ip_and_card_are_masked_then_restored():
    masker = Masker(pii=True, secrets=False)
    text = ("contact alice.smith@example.com from 10.1.2.3, card "
            "4111 1111 1111 1111")
    masked, hits = masker.mask_text(text)
    assert hits == 3
    assert "alice.smith@example.com" not in masked
    assert "example.com" not in masked                 # domain normalised
    assert "@corp.local" in masked                     # realistic email shape
    assert "10.1.2.3" not in masked
    assert "4111 1111 1111 1111" not in masked
    assert "[[IP_ADDRESS_1]]" in masked
    assert "[[CREDIT_CARD_1]]" in masked
    assert masker.restore(masked) == text


def test_checksums_reject_invalid_values():
    masker = Masker(pii=True, secrets=False)
    # Luhn-invalid card, out-of-range IPv4, IBAN with a broken check digit
    text = ("4111 1111 1111 1112 and 999.1.2.3 and "
            "DE89 3704 0044 0532 0130 00 and DE89 3704 0044 0532 0130 01")
    masked, _ = masker.mask_text(text)
    assert "999.1.2.3" in masked                      # not an IP
    assert "4111 1111 1111 1112" in masked            # fails Luhn
    assert "DE89 3704 0044 0532 0130 00" not in masked  # valid IBAN -> masked
    assert "DE89 3704 0044 0532 0130 01" in masked      # bad check digit stays


def test_api_keys_jwt_and_bearer():
    masker = _secret_masker()
    text = f"aws={AWS_KEY}\nopenai={SK_KEY}\nAuthorization: Bearer {JWT}"
    masked, hits = masker.mask_text(text)
    assert hits == 3
    assert AWS_KEY not in masked and SK_KEY not in masked
    assert "[[API_KEY_AWS_1]]" in masked
    assert "aws=" in masked                            # context preserved
    assert "Bearer " in masked                         # only the token masked
    assert "[[BEARER_TOKEN_1]]" in masked or "[[JWT_TOKEN_1]]" in masked
    assert masker.restore(masked) == text


def test_private_key_block_is_masked_as_one_unit():
    masker = _secret_masker()
    block = ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
             "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
             "-----END OPENSSH PRIVATE KEY-----")
    masked, hits = masker.mask_text(f"key file:\n{block}\n")
    assert hits == 1
    assert "b3BlbnNzaC1rZXktdjE" not in masked
    assert "[[OPENSSH_PRIVATE_KEY_1]]" in masked
    assert masker.restore(masked).count("BEGIN OPENSSH") == 1


def test_env_password_masks_value_only():
    masker = _secret_masker()
    text = "DB_PASSWORD=Sup3rS3cret!"
    masked, _ = masker.mask_text(text)
    # the assignment key stays visible; the value becomes a same-length
    # password surrogate (PasteGuard-style), restored later
    assert masked.startswith("DB_PASSWORD=")
    value = masked.split("=", 1)[1]
    assert len(value) == len("Sup3rS3cret!") and value != "Sup3rS3cret!"
    assert masker.restore(masked) == text


def test_password_assignment_and_connection_string():
    masker = _secret_masker()
    text = ("password=Winter2024!\n"
            "postgres://app:dbPassw0rd@db.corp.local:5432/orders")
    masked, _ = masker.mask_text(text)
    assert "Winter2024!" not in masked
    assert "dbPassw0rd" not in masked
    assert "postgres://app:" in masked          # user + scheme preserved
    assert "@db.corp.local:5432/orders" in masked
    assert masker.restore(masked) == text


def test_identical_values_share_one_placeholder():
    masker = Masker(pii=True, secrets=False)
    masked, hits = masker.mask_text("a@x.com then a@x.com again, b@y.com")
    assert hits == 3
    assert masked.count("[[EMAIL_ADDRESS_1]]") == 2
    assert "[[EMAIL_ADDRESS_2]]" in masked


def test_redacted_markers_are_never_masked():
    masker = _secret_masker()
    masked, hits = masker.mask_text("password=[REDACTED] and [[API_KEY_AWS_1]]")
    assert hits == 0 and masked == "password=[REDACTED] and [[API_KEY_AWS_1]]"


def test_allowlist_and_denylist():
    masker = Masker(pii=True, secrets=False,
                    allowlist=[{"pattern": "noreply@corp.local"}],
                    denylist=[{"pattern": r"CUST-\d{6}", "type": "CUSTOMER_ID",
                               "regex": True}])
    masked, _ = masker.mask_text("noreply@corp.local real@corp.local CUST-123456")
    assert "noreply@corp.local" in masked       # allowlisted
    assert "real@corp.local" not in masked
    assert "[[CUSTOMER_ID_1]]" in masked


def test_overlap_priority_private_key_beats_inner_assignment():
    masker = _secret_masker()
    block = ("-----BEGIN RSA PRIVATE KEY-----\n"
             "PASSWORD=NotARealSecret\n"
             "-----END RSA PRIVATE KEY-----")
    masked, hits = masker.mask_text(block)
    assert hits == 1
    assert masked == "[[PEM_PRIVATE_KEY_1]]"


def test_whole_text_is_scanned_past_the_chunk_size():
    masker = _secret_masker(max_scan_chars=1000)
    text = ("A" * 3000) + "\n" + f"key={AWS_KEY}\n"
    masked, hits = masker.mask_text(text)
    assert hits == 1
    assert AWS_KEY not in masked
    assert masker.restore(masked) == text


def test_policy_toggles_and_none_when_disabled():
    assert Masker.from_policy(Policy()) is None
    policy = Policy()
    policy.mask_pii = True
    masker = Masker.from_policy(policy)
    assert masker is not None
    masked, _ = masker.mask_text("x@y.com")
    assert "[[EMAIL_ADDRESS_1]]" in masked
    # secrets off -> AWS key stays
    assert "AKIA" in masker.mask_text(AWS_KEY)[0]


def test_restore_findings_puts_values_back():
    masker = _secret_masker()
    masked, _ = masker.mask_text(f"key={AWS_KEY}")
    findings = [{"username": "svc", "secret": "[[API_KEY_AWS_1]]",
                 "evidence": "saw it", "note": "", "path": "a.txt"}]
    restore_findings(findings, masker)
    assert findings[0]["secret"] == AWS_KEY


def test_show_markers_option():
    masker = _secret_masker(marker_text="[protected]", show_markers=True)
    masked, _ = masker.mask_text(f"key={AWS_KEY}")
    assert masker.restore(masked) == f"key=[protected]{AWS_KEY}"


# --------------------------------------------------------------------------- #
# integration
# --------------------------------------------------------------------------- #
def test_executor_masks_tool_results(tmp_path):
    from credshrike.agent.audit import AuditLog
    from credshrike.agent.executor import ToolExecutor
    from credshrike.agent.session import AgentSession
    from credshrike.credentials import Credential
    from test_agent import FakeSMB

    policy = Policy()
    policy.mask_secrets = True
    credential = Credential.from_args("password", "svc", "corp.local", password="pw")
    session = AgentSession(credential, policy, AuditLog.new_run(str(tmp_path)),
                           hosts=["filesrv01"])
    fake = FakeSMB()
    fake.file_contents = {"creds.txt": f"aws_key={AWS_KEY}\n".encode()}
    session.smb = lambda host: fake
    try:
        out = ToolExecutor(session, policy, session.audit).execute(
            "smb_read_file", {"host": "filesrv01", "share": "IT", "path": "creds.txt"})
        assert not out["is_error"]
        # file bytes travel base64-encoded — decode the payload the model sees
        import base64
        payload = json.loads(out["content"].split("\n")[0])
        decoded = base64.b64decode(payload["content_b64"]).decode()
        assert AWS_KEY not in decoded
        assert "API_KEY_AWS_1" in decoded
        assert session.masked_values >= 1
        # the masker can restore what the model was shown
        assert AWS_KEY in session.masker.restore(decoded)
    finally:
        session.close_smb()


def test_domain_sweep_masks_dump_and_restores_report(tmp_path, monkeypatch):
    from credshrike.agent.orchestrator import run_domain_sweep
    from credshrike.domain.base import ComputerRecord
    from test_agent import FakeSMB

    fake = FakeSMB()
    fake.list_dir = lambda share, path="", max_entries=200: {
        "share": share, "path": path,
        "entries": [{"name": "keys.txt", "is_dir": False, "size": 40}],
        "truncated": False, "total_seen": 1}
    fake.file_contents = {"keys.txt": f"aws={AWS_KEY}\n".encode()}
    import credshrike.agent.session as session_mod
    monkeypatch.setattr(session_mod.AgentSession, "smb", lambda self, host: fake)

    goals = []

    class Msgs:
        def create(self, **kw):
            messages = kw.get("messages", [])
            text = str(messages[-1].get("content", "")) if messages else ""
            if "FILE CHECKLIST" in text:
                goals.append(text)
                return SimpleNamespace(stop_reason="end_turn", content=[
                    SimpleNamespace(type="text",
                                    text="FOUND [[API_KEY_AWS_1]] in keys.txt")])
            if "JSON" in text and "findings" in text.lower():
                return SimpleNamespace(stop_reason="end_turn", content=[
                    SimpleNamespace(type="text", text=json.dumps({"findings": [
                        {"severity": "high", "category": "credential",
                         "host": "ws01.corp.local", "share": "IT",
                         "path": "keys.txt", "username": None,
                         "secret": "[[API_KEY_AWS_1]]",
                         "evidence": "dump", "note": ""}]}))])
            return SimpleNamespace(stop_reason="end_turn", content=[
                SimpleNamespace(type="text", text="Summary: [[API_KEY_AWS_1]]")])

    policy = Policy()
    policy.analysis_mode = "batch"     # this test exercises the batch path
    policy.analysis_triage = False
    policy.mask_secrets = True
    result = run_domain_sweep(
        credential=__import__("credshrike.credentials", fromlist=["Credential"])
        .Credential.from_args("password", "svc", "corp.local", password="pw"),
        policy=policy, audit_dir=str(tmp_path),
        client_factory=lambda: SimpleNamespace(messages=Msgs()),
        echo=lambda l: None,
        source_override=lambda: [ComputerRecord(cn="WS01", dns_name="ws01.corp.local")],
        reachable_check=lambda host: True)

    assert goals, "analysis call never happened"
    # the model never saw the real key
    assert AWS_KEY not in goals[0]
    assert "[[API_KEY_AWS_1]]" in goals[0]
    entry = result["hosts"][0]
    assert entry["status"] == "done"
    assert entry["masked"] >= 1
    # operator-facing report + findings carry the real value again
    assert AWS_KEY in entry["report_md"]
    assert entry["findings"][0]["secret"] == AWS_KEY


def test_mask_cli_roundtrip(tmp_path, capsys):
    """`credshrike mask` masks stdin/file and `--restore` reverses it."""
    from credshrike.cli import main

    source = tmp_path / "input.txt"
    source.write_text(f"mail alice@corp.local key={AWS_KEY}\n", encoding="utf-8")
    mapping = tmp_path / "mapping.json"
    assert main(["mask", str(source), "--mapping", str(mapping)]) == 0
    masked = capsys.readouterr().out
    assert "alice@corp.local" not in masked and AWS_KEY not in masked
    assert "@corp.local" in masked and "[[API_KEY_AWS_1]]" in masked

    masked_file = tmp_path / "masked.txt"
    masked_file.write_text(masked, encoding="utf-8")
    assert main(["mask", str(masked_file), "--restore", str(mapping)]) == 0
    restored = capsys.readouterr().out
    assert "alice@corp.local" in restored and AWS_KEY in restored


# --------------------------------------------------------------------------- #
# GLiNER semantic backend (PERSON / LOCATION)
# --------------------------------------------------------------------------- #
from credshrike.semantic import SemanticSpan, token_windows  # noqa: E402


class FakeSemanticBackend:
    """Stand-in for GlinerBackend: returns canned spans, records calls."""

    def __init__(self, spans):
        self.spans = list(spans)
        self.calls = []

    def detect(self, text, threshold=None):
        self.calls.append((text, threshold))
        return list(self.spans)


def test_semantic_masks_person_and_location():
    text = "Alice Smith met Bob Jones in Berlin."
    backend = FakeSemanticBackend([
        SemanticSpan("PERSON", 0, 11, 0.99),
        SemanticSpan("PERSON", 16, 25, 0.98),
        SemanticSpan("LOCATION", 29, 35, 0.90),
    ])
    masker = Masker(pii=False, secrets=False, semantic_backend=backend,
                    semantic_threshold=0.7)
    masked, hits = masker.mask_text(text)
    assert hits == 3
    # PERSON -> same-length names (initials kept); LOCATION stays a placeholder
    assert "Alice Smith" not in masked and "Bob Jones" not in masked
    assert "Berlin" not in masked and "[[LOCATION_1]]" in masked
    first = masked.split(" met ")[0]
    assert len(first) == len("Alice Smith") and first != "Alice Smith"
    assert first.split()[0][0] == "A"                    # initial preserved
    assert masker.restore(masked) == text
    assert backend.calls and backend.calls[0][1] == 0.7   # threshold forwarded


def test_deterministic_spans_win_over_semantic_overlap():
    text = "Email Alice at alice@corp.local now"
    # GLiNER is greedy: its PERSON span swallows the email
    backend = FakeSemanticBackend([SemanticSpan("PERSON", 6, 31, 0.99)])
    masker = Masker(pii=True, secrets=False, semantic_backend=backend)
    masked, _ = masker.mask_text(text)
    # the email becomes a realistic address; only the uncovered fragment is PERSON
    assert "alice@corp.local" not in masked
    assert "@corp.local" in masked
    assert "Alice" not in masked                  # PERSON fragment is a surrogate
    assert masker.restore(masked).startswith("Email Alice at alice@corp.local")


def test_semantic_longest_span_wins():
    text = "Alice Smith"
    backend = FakeSemanticBackend([
        SemanticSpan("PERSON", 0, 11, 0.95),
        SemanticSpan("LOCATION", 0, 5, 0.99),   # shorter, higher score: loses
    ])
    masker = Masker(pii=False, secrets=False, semantic_backend=backend)
    masked, hits = masker.mask_text(text)
    assert hits == 1 and masked != "Alice Smith" and len(masked) == 11
    assert "LOCATION" not in masked


def test_semantic_backend_alone_is_enough():
    backend = FakeSemanticBackend([SemanticSpan("PERSON", 0, 4, 0.99)])
    masker = Masker(pii=False, secrets=False, semantic_backend=backend)
    masked, hits = masker.mask_text("John was here")
    assert hits == 1 and "John" not in masked
    assert len(masked) == len("John was here")
    assert masker.restore(masked) == "John was here"


def test_masker_from_policy_loads_semantic_backend(monkeypatch):
    import credshrike.semantic as semantic_mod
    fake = FakeSemanticBackend([])
    monkeypatch.setattr(semantic_mod, "get_backend", lambda **kw: fake)
    policy = Policy()
    policy.mask_semantic = True            # semantic alone enables masking
    masker = Masker.from_policy(policy)
    assert masker is not None and masker.semantic_backend is fake


def test_token_windows_cover_whole_text():
    text = " ".join(f"w{i}" for i in range(2000))
    windows = list(token_windows(text, max_tokens=128, overlap=32))
    assert len(windows) > 1
    covered = set()
    for offset, window in windows:
        covered.update(range(offset, offset + len(window)))
    assert covered == set(range(len(text)))
    assert windows[0][0] == 0


def test_token_windows_short_text_is_one_window():
    assert list(token_windows("short text", 384, 64)) == [(0, "short text")]


def test_semantic_backend_fails_closed_with_install_hint(monkeypatch):
    import builtins
    from credshrike.semantic import GlinerBackend
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "gliner" or name.startswith("gliner."):
            raise ImportError("not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="pip install"):
        GlinerBackend().load()


def test_model_cache_root_env_override(monkeypatch, tmp_path):
    from credshrike import semantic as sem
    monkeypatch.setenv("CREDSHRIKE_MODEL_DIR", str(tmp_path))
    assert sem.model_cache_root() == tmp_path


def test_materialize_model_uses_local_dir_and_caches(monkeypatch, tmp_path):
    """Windows-safe path: snapshot_download(local_dir=...) writes real files
    (the default HF cache needs symlink privileges)."""
    import huggingface_hub
    from credshrike import semantic as sem

    monkeypatch.setenv("CREDSHRIKE_MODEL_DIR", str(tmp_path))
    calls = []

    def fake_download(repo_id, local_dir):
        calls.append((repo_id, local_dir))
        (tmp_path / "urchade--gliner_multi_pii-v1" / "gliner_config.json").write_text("{}")

    monkeypatch.setattr(huggingface_hub, "snapshot_download", fake_download)
    target = tmp_path / "urchade--gliner_multi_pii-v1"
    target.mkdir()
    first = sem.materialize_model("urchade/gliner_multi_pii-v1")
    second = sem.materialize_model("urchade/gliner_multi_pii-v1")
    assert first == second == str(target)
    assert calls == [("urchade/gliner_multi_pii-v1", str(target))]   # cached


def test_shared_factory_aligns_same_account_across_contexts():
    """Cross-share/cross-batch alignment: separate Maskers (one placeholder
    namespace per context) built on ONE shared factory must map the same
    account to the same surrogate everywhere, in every form."""
    from credshrike.masking import build_surrogate_factory

    policy = Policy()
    policy.mask_pii = True
    policy.mask_secrets = True
    factory = build_surrogate_factory(policy)

    share_a = Masker.from_policy(policy, shared_factory=factory)
    share_b = Masker.from_policy(policy, shared_factory=factory)
    text_a = "username: jchen\nHACKADAY" + chr(92) + "jchen admin\n"
    text_b = "owner jchen@hackaday.lab\nC:" + chr(92) + "Users" + chr(92) + "jchen" + chr(92) + "k\n"
    masked_a, _ = share_a.mask_text(text_a)
    masked_b, _ = share_b.mask_text(text_b)

    # extract the surrogate local part from each masked form
    import re
    names = set(re.findall(r"([A-Za-z][A-Za-z0-9._-]{3,})", masked_a + " " + masked_b))
    allowed = {"hackaday", "admin", "username", "users", "owner",
               "corp", "local", "corp.local"}
    surrogates = {n for n in names
                  if n.lower() not in allowed and n.lower() != "jchen"}
    # every occurrence across BOTH contexts uses ONE canonical surrogate
    assert len(surrogates) == 1, surrogates

    # restore still returns the real account in each context
    assert "jchen" in share_a.restore(masked_a)
    assert "jchen" in share_b.restore(masked_b)


def test_shared_factory_is_thread_safe():
    import threading
    from credshrike.surrogate import SurrogateFactory

    f = SurrogateFactory(min_len=4)
    results = []
    errors = []

    def worker(i):
        try:
            results.append(f.make(f"svc{i:02d}", "USERNAME", "", {}))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(set(results)) == 12      # distinct accounts, distinct names
