import pytest

from smbenum.credentials import AuthType, Credential


def test_from_args_password():
    cred = Credential.from_args("password", "jdoe", "corp.local", password="Passw0rd!")
    assert cred.auth_type is AuthType.PASSWORD
    cred.validate()
    assert cred.principal == "corp.local\\jdoe"


def test_from_args_ntlm_split_and_bare():
    cred = Credential.from_args("ntlm", "jdoe", "corp.local", hashes="AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0")
    assert cred.lmhash == "aad3b435b51404eeaad3b435b51404ee"
    assert cred.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"
    bare = Credential.from_args("ntlm", "jdoe", "corp.local", hashes="31D6CFE0D16AE931B73C59D7E0C089C0")
    assert bare.lmhash == "" and bare.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_from_args_bad_hash_rejected():
    with pytest.raises(ValueError, match="hash"):
        Credential.from_args("ntlm", "jdoe", "corp.local", hashes="zz:nothex")


def test_from_args_aes_strips_colons():
    cred = Credential.from_args("aes", "svc$", "corp.local", aes_key="ab:cd:ef" * 10 + "ab")
    assert ":" not in cred.aes_key


def test_validate_missing_material():
    with pytest.raises(ValueError, match="password"):
        Credential.from_args("password", "jdoe", "corp.local").validate()
    with pytest.raises(ValueError, match="ticket"):
        Credential.from_args("ticket", "jdoe", "corp.local").validate()
    with pytest.raises(ValueError, match="realm"):
        Credential.from_args("aes", "jdoe", "", aes_key="ab" * 32).validate()


def test_kerberos_predicate():
    assert Credential.from_args("aes", "u", "d", aes_key="ab" * 32).is_kerberos
    assert Credential.from_args("ticket", "u", "d", ticket="t.ccache").is_kerberos
    assert not Credential.from_args("password", "u", "d", password="x").is_kerberos


def test_redacted_never_leaks_secrets():
    cred = Credential.from_args("ntlm", "jdoe", "corp.local", hashes=":" + "ab" * 16)
    red = cred.redacted()
    assert "abababab" not in str(red)
    assert red["has_nthash"] is True and red["auth_type"] == "ntlm"


def test_from_profile_roundtrip():
    data = {"auth_type": "ticket", "username": "jdoe", "domain": "corp.local",
            "ticket": "/tmp/t.ccache", "kdc": "dc01.corp.local"}
    cred = Credential.from_profile(data)
    assert cred.auth_type is AuthType.TICKET and cred.kdc_host == "dc01.corp.local"
