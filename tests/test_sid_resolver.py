from smbenum.acl import SidResolver
from smbenum.acl.sd_parser import parse_security_descriptor
from test_sd_parser import build_sd, _ace, OWNER, EVERYONE


def test_well_known_sids_resolve_without_any_backend():
    r = SidResolver()
    out = r.resolve_many([EVERYONE, "S-1-5-11", "S-1-5-32-544", "S-1-5-18"])
    assert out[EVERYONE] == "Everyone"
    assert out["S-1-5-11"] == "Authenticated Users"
    assert out["S-1-5-32-544"] == "BUILTIN\\Administrators"
    assert out["S-1-5-18"] == "SYSTEM (LocalSystem)"


def test_domain_rid_names_are_flagged():
    r = SidResolver()
    out = r.resolve_many(["S-1-5-21-1-2-3-512", "S-1-5-21-1-2-3-1104"])
    assert "Domain Admins" in out["S-1-5-21-1-2-3-512"]
    # non-well-known RID without backend: stays unresolved (absent from result)
    assert "S-1-5-21-1-2-3-1104" not in out


def test_static_map_and_remote_layers():
    remote_calls = []

    def remote(sids):
        remote_calls.append(list(sids))
        return {"S-1-5-21-1-2-3-1104": "CORP\\jdoe"}

    r = SidResolver(static_map={"S-1-5-21-1-2-3-1601": "CORP\\sql_svc"}, remote_lookup=remote)
    out = r.resolve_many(["S-1-1-0", "S-1-5-21-1-2-3-1601", "S-1-5-21-1-2-3-1104"])
    assert out["S-1-1-0"] == "Everyone"            # layer 1: no remote call needed
    assert out["S-1-5-21-1-2-3-1601"] == "CORP\\sql_svc"  # layer 2
    assert out["S-1-5-21-1-2-3-1104"] == "CORP\\jdoe"     # layer 3
    assert remote_calls == [["S-1-5-21-1-2-3-1104"]]      # only the unknown went remote


def test_remote_failure_is_non_fatal():
    def boom(sids):
        raise RuntimeError("pipe unavailable")

    r = SidResolver(remote_lookup=boom)
    assert r.resolve("S-1-5-21-1-2-3-1104") == "S-1-5-21-1-2-3-1104"


def test_annotate_adds_names_into_parsed_sd():
    r = SidResolver(remote_lookup=lambda sids: {OWNER: "CORP\\jdoe"})
    sd = parse_security_descriptor(build_sd(
        dacl_aces=[_ace(0, 0, 0x00000089, EVERYONE)]))
    annotated = r.annotate(sd)
    assert annotated["owner_name"] == "CORP\\jdoe"
    ace = annotated["dacl"]["aces"][0]
    assert ace["trustee_name"] == "Everyone"
