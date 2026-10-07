"""Security-descriptor parser tests with synthetic binary fixtures."""

import struct

import pytest

from smbenum.acl import (parse_security_descriptor, sid_to_bytes, parse_sid,
                         effective_ace_list, is_everyone_readable, SDParseError)

OWNER = "S-1-5-21-1111111111-2222222222-3333333333-1104"   # a user
GROUP = "S-1-5-21-1111111111-2222222222-3333333333-513"    # Domain Users
EVERYONE = "S-1-1-0"
ADMINS = "S-1-5-32-544"


def _ace(ace_type: int, flags: int, mask: int, trustee: str) -> bytes:
    body = struct.pack("<I", mask) + sid_to_bytes(trustee)
    return struct.pack("<BBH", ace_type, flags, 4 + len(body)) + body


def build_sd(owner=OWNER, group=GROUP, dacl_aces=(), sacl_aces=(), control_extra=0x0004):
    owner_b = sid_to_bytes(owner)
    group_b = sid_to_bytes(group)
    dacl_aces_b = b"".join(dacl_aces)
    sacl_aces_b = b"".join(sacl_aces)
    dacl = b""
    sacl = b""
    if dacl_aces_b:
        n = len(dacl_aces)
        dacl = struct.pack("<BBHHH", 2, 0, 8 + len(dacl_aces_b), n, 0) + dacl_aces_b
    if sacl_aces_b:
        n = len(sacl_aces)
        sacl = struct.pack("<BBHHH", 2, 0, 8 + len(sacl_aces_b), n, 0) + sacl_aces_b
    control = 0x8000 | control_extra | (0x0004 if dacl else 0) | (0x0010 if sacl else 0)
    owner_off = 20
    group_off = owner_off + len(owner_b)
    sacl_off = group_off + len(group_b) if sacl else 0
    after_sacl = (sacl_off + len(sacl)) if sacl else (group_off + len(group_b))
    dacl_off = after_sacl if dacl else 0
    header = struct.pack("<BBHIIII", 1, 0, control, owner_off, group_off, sacl_off, dacl_off)
    return header + owner_b + group_b + sacl + dacl


def test_sid_roundtrip():
    for sid in (OWNER, EVERYONE, ADMINS, "S-1-5-18"):
        assert parse_sid(sid_to_bytes(sid))["sid"] == sid


def test_parse_minimal_sd_owner_group_only():
    sd = build_sd(dacl_aces=())
    parsed = parse_security_descriptor(sd)
    assert parsed["owner"] == OWNER
    assert parsed["group"] == GROUP
    assert parsed["dacl"] is None
    assert "SELF_RELATIVE" in parsed["control_flags"]


def test_parse_dacl_with_two_aces():
    aces = [
        _ace(0, 0x04, 0x001F01FF, ADMINS),          # allow, inherited, full control
        _ace(1, 0x00, 0x00000089, EVERYONE),        # deny read-ish
    ]
    parsed = parse_security_descriptor(build_sd(dacl_aces=aces))
    dacl = parsed["dacl"]
    assert dacl["ace_count"] == 2
    allow, deny = dacl["aces"]
    assert allow["type_name"] == "ACCESS_ALLOWED" and allow["trustee"] == ADMINS
    assert allow["inherited"] is True
    assert "FILE_ALL_ACCESS" in allow["rights"]
    assert deny["type_name"] == "ACCESS_DENIED" and deny["trustee"] == EVERYONE
    assert deny["inherited"] is False
    assert "FILE_READ_DATA" in deny["rights"] and "FILE_READ_EA" in deny["rights"]


def test_inherit_only_aces_are_filtered_from_effective():
    aces = [
        _ace(0, 0x80 | 0x04, 0x001F01FF, ADMINS),   # inherit-only (applies to children)
        _ace(0, 0x00, 0x00000089, EVERYONE),
    ]
    parsed = parse_security_descriptor(build_sd(dacl_aces=aces))
    effective = effective_ace_list(parsed)
    assert len(effective) == 1 and effective[0]["trustee"] == EVERYONE


def test_everyone_readable_detection():
    readable = [_ace(0, 0, 0x00000089, EVERYONE)]
    not_readable = [_ace(0, 0, 0x00000116, EVERYONE)]  # write-only grant
    assert is_everyone_readable(parse_security_descriptor(build_sd(dacl_aces=readable)))
    assert not is_everyone_readable(parse_security_descriptor(build_sd(dacl_aces=not_readable)))


def test_object_ace_with_guid():
    # OBJECT_TYPE_PRESENT (0x1): GUID(16) + mask + sid
    guid = bytes(range(16))
    body = guid + struct.pack("<I", 0x00000002) + sid_to_bytes(OWNER)
    ace = struct.pack("<BBH", 5, 0x01, 4 + len(body)) + body
    parsed = parse_security_descriptor(build_sd(dacl_aces=[ace]))
    ace_parsed = parsed["dacl"]["aces"][0]
    assert ace_parsed["type_name"] == "ACCESS_DENIED_OBJECT"
    assert ace_parsed["object_type"] == guid.hex()
    assert ace_parsed["trustee"] == OWNER
    assert "FILE_WRITE_DATA" in ace_parsed["rights"]


def test_short_blob_rejected():
    with pytest.raises(SDParseError):
        parse_security_descriptor(b"\x01\x00")


def test_truncated_sid_rejected():
    bad = b"\x01\x05" + b"\x00" * 10  # claims 5 subauths, has ~1
    with pytest.raises(SDParseError):
        parse_sid(bad)
