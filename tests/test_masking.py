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
    assert "10.1.2.3" not in masked
    assert "4111 1111 1111 1111" not in masked
    assert "[[EMAIL_ADDRESS_1]]" in masked
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
    assert masked == "DB_PASSWORD=[[ENV_PASSWORD_1]]"
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
    assert "[[EMAIL_ADDRESS_1]]" in masked and "[[API_KEY_AWS_1]]" in masked

    masked_file = tmp_path / "masked.txt"
    masked_file.write_text(masked, encoding="utf-8")
    assert main(["mask", str(masked_file), "--restore", str(mapping)]) == 0
    restored = capsys.readouterr().out
    assert "alice@corp.local" in restored and AWS_KEY in restored
