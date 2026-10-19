"""Self-relative SECURITY_DESCRIPTOR parser (binary layout, no NDR engine).

Layout per [MS-DTYP] 2.4.6 (self-relative form, control bit 0x8000):

    Revision(1) Sbz1(1) Control(2LE) Owner(4) Group(4) Sacl(4) Dacl(4)
    — the last four are byte offsets from the descriptor start, 0 = absent.

    SID: Revision(1)=1 SubAuthCount(1) IdentifierAuthority(6 BE) SubAuths(4LE…)
    ACL: Revision(1) Sbz1(1) AclSize(2LE) AceCount(2LE) Sbz2(2) ACEs…
    ACE header: Type(1) Flags(1) Size(2LE), then type-specific body.

Everything returns plain dicts/lists so results serialize straight to JSON
for the CLI and the LLM tool results.
"""

from __future__ import annotations

import struct
from typing import Optional

from .access_masks import decode_access_mask

SD_CONTROL_FLAGS = {
    0x0001: "OWNER_DEFAULTED",
    0x0002: "GROUP_DEFAULTED",
    0x0004: "DACL_PRESENT",
    0x0008: "DACL_DEFAULTED",
    0x0010: "SACL_PRESENT",
    0x0020: "SACL_DEFAULTED",
    0x0100: "DACL_AUTO_INHERITED",
    0x0200: "SACL_AUTO_INHERITED",
    0x0400: "DACL_PROTECTED",
    0x0800: "SACL_PROTECTED",
    0x1000: "RM_CONTROL_VALID",
    0x8000: "SELF_RELATIVE",
}

ACE_TYPES = {
    0: "ACCESS_ALLOWED",
    1: "ACCESS_DENIED",
    2: "SYSTEM_AUDIT",
    3: "SYSTEM_ALARM",
    4: "ACCESS_ALLOWED_OBJECT",
    5: "ACCESS_DENIED_OBJECT",
    6: "SYSTEM_AUDIT_OBJECT",
    7: "SYSTEM_ALARM_OBJECT",
    8: "ACCESS_ALLOWED_CALLBACK",
    9: "ACCESS_DENIED_CALLBACK",
    10: "ACCESS_ALLOWED_CALLBACK_OBJECT",
    11: "ACCESS_DENIED_CALLBACK_OBJECT",
    12: "SYSTEM_AUDIT_CALLBACK",
    13: "SYSTEM_ALARM_CALLBACK",
    14: "SYSTEM_AUDIT_CALLBACK_OBJECT",
    15: "SYSTEM_ALARM_CALLBACK_OBJECT",
    16: "SYSTEM_MANDATORY_LABEL",
    17: "SYSTEM_RESOURCE_ATTRIBUTE",
    18: "SYSTEM_SCOPED_POLICY_ID",
}

ACE_FLAGS = {
    0x01: "OBJECT_TYPE_PRESENT",
    0x02: "INHERITED_OBJECT_TYPE_PRESENT",
    0x04: "INHERITED",
    0x10: "SUCCESSFUL_ACCESS",
    0x20: "FAILED_ACCESS",
    0x80: "INHERIT_ONLY",
}

# object ACE bodies carry two optional GUIDs before the mask, gated by the
# OBJECT/INHERITED flags above
_OBJECT_ACE_TYPES = {4, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15}


class SDParseError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# primitives
# --------------------------------------------------------------------------- #
def parse_sid(data: bytes, offset: int = 0) -> dict:
    if offset + 8 > len(data):
        raise SDParseError(f"SID header out of bounds at {offset}")
    revision = data[offset]
    sub_count = data[offset + 1]
    if revision != 1:
        raise SDParseError(f"unexpected SID revision {revision} at {offset}")
    if offset + 8 + 4 * sub_count > len(data):
        raise SDParseError(f"SID subauthorities out of bounds at {offset}")
    authority = int.from_bytes(data[offset + 2: offset + 8], "big")
    subs = [struct.unpack_from("<I", data, offset + 8 + 4 * i)[0] for i in range(sub_count)]
    textual = f"S-1-{authority}-" + "-".join(str(s) for s in subs) if subs else f"S-1-{authority}"
    return {"sid": textual, "revision": revision, "authority": authority, "sub_authorities": subs,
            "size": 8 + 4 * sub_count}


def sid_to_bytes(sid: str) -> bytes:
    """Inverse of parse_sid — used by tests to build fixtures."""
    parts = sid.split("-")
    if parts[:2] != ["S", "1"]:
        raise ValueError(f"not an S-1 SID: {sid}")
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = bytes([1, len(subs)]) + authority.to_bytes(6, "big")
    for s in subs:
        out += struct.pack("<I", s)
    return out


def _parse_acl(data: bytes, offset: int, is_dacl: bool) -> Optional[dict]:
    if offset == 0:
        return None
    if offset + 8 > len(data):
        raise SDParseError(f"ACL header out of bounds at {offset}")
    revision, _sbz1 = data[offset], data[offset + 1]
    acl_size, ace_count = struct.unpack_from("<HH", data, offset + 2)
    aces: list[dict] = []
    cursor = offset + 8
    end = offset + (acl_size or len(data) - offset)
    for _ in range(ace_count):
        if cursor + 4 > len(data) or cursor >= end:
            break
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", data, cursor)
        if ace_size < 4 or cursor + ace_size > len(data):
            raise SDParseError(f"ACE {len(aces)} out of bounds at {cursor}")
        body = cursor + 4
        mask, trustee, object_type, inherited_type = None, None, None, None
        if ace_type in _OBJECT_ACE_TYPES:
            body_flags = ace_flags & 0x3
            guid_size = 16
            if body_flags & 0x1:
                object_type = data[body: body + guid_size].hex()
                body += guid_size
            if body_flags & 0x2:
                inherited_type = data[body: body + guid_size].hex()
                body += guid_size
            mask = struct.unpack_from("<I", data, body)[0]
            body += 4
            trustee = parse_sid(data, body)["sid"]
        elif ace_type in (0, 1, 2, 3):  # plain allowed/denied/audit
            mask = struct.unpack_from("<I", data, body)[0]
            trustee = parse_sid(data, body + 4)["sid"]
        else:  # label / resource-attribute ACEs: mask + sid too in practice
            mask = struct.unpack_from("<I", data, body)[0]
            trustee = parse_sid(data, body + 4)["sid"] if body + 8 <= len(data) else None
        aces.append({
            "type": ace_type,
            "type_name": ACE_TYPES.get(ace_type, f"UNKNOWN_{ace_type}"),
            "flags": ace_flags,
            "flag_names": [n for b, n in ACE_FLAGS.items() if ace_flags & b],
            "inherited": bool(ace_flags & 0x04),
            "inherit_only": bool(ace_flags & 0x80),
            "mask": mask,
            "rights": decode_access_mask(mask) if mask is not None else [],
            "trustee": trustee,
            "object_type": object_type,
            "inherited_object_type": inherited_type,
        })
        cursor += ace_size
    return {"revision": revision, "size": acl_size, "ace_count": ace_count, "aces": aces,
            "kind": "dacl" if is_dacl else "sacl"}


# --------------------------------------------------------------------------- #
# top-level
# --------------------------------------------------------------------------- #
def parse_security_descriptor(data: bytes) -> dict:
    """Parse a self-relative SECURITY_DESCRIPTOR blob into a dict tree."""
    if len(data) < 20:
        raise SDParseError(f"security descriptor too short ({len(data)} bytes)")
    revision, _sbz1, control = struct.unpack_from("<BBH", data, 0)
    if revision != 1:
        raise SDParseError(f"unexpected SD revision {revision}")
    owner_off, group_off, sacl_off, dacl_off = struct.unpack_from("<IIII", data, 4)
    result = {
        "revision": revision,
        "control": control,
        "control_flags": [n for b, n in SD_CONTROL_FLAGS.items() if control & b],
        "owner": parse_sid(data, owner_off)["sid"] if owner_off else None,
        "group": parse_sid(data, group_off)["sid"] if group_off else None,
        "dacl": _parse_acl(data, dacl_off, is_dacl=True),
        "sacl": _parse_acl(data, sacl_off, is_dacl=False),
        "size": len(data),
    }
    return result


# --------------------------------------------------------------------------- #
# helpers for consumers
# --------------------------------------------------------------------------- #
def effective_ace_list(parsed: dict) -> list[dict]:
    """The DACL ACEs that actually apply to the object (skip inherit-only)."""
    dacl = parsed.get("dacl")
    if not dacl:
        return []
    return [a for a in dacl["aces"] if not a.get("inherit_only")]


def is_everyone_readable(parsed: dict) -> bool:
    """True if any allow ACE grants read-ish rights to Everyone/S-1-1-0."""
    for ace in effective_ace_list(parsed):
        if ace["trustee"] in ("S-1-1-0", "S-1-5-7") and ace["type_name"] == "ACCESS_ALLOWED" \
                and (ace["mask"] or 0) & 0x00000089:
            return True
    return False
