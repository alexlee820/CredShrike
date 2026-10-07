"""Access-mask bit decoding for file/share security (MS-WSMV/MS-SRVS/MS-FSCC).

Pure data + pure functions — no protocol dependencies.
"""

from __future__ import annotations

# --- file / directory specific rights (MS-FSCC 2.4.3) ---------------------- #
FILE_RIGHTS = {
    0x00000001: ["FILE_READ_DATA", "LIST_DIRECTORY"],
    0x00000002: ["FILE_WRITE_DATA", "CREATE_FILE"],
    0x00000004: ["FILE_APPEND_DATA", "CREATE_SUBDIRECTORY"],
    0x00000008: ["FILE_READ_EA"],
    0x00000010: ["FILE_WRITE_EA"],
    0x00000020: ["FILE_EXECUTE", "TRAVERSE_DIRECTORY"],
    0x00000040: ["FILE_DELETE_CHILD"],
    0x00000080: ["FILE_READ_ATTRIBUTES"],
    0x00000100: ["FILE_WRITE_ATTRIBUTES"],
}

STANDARD_RIGHTS = {
    0x00010000: ["DELETE"],
    0x00020000: ["READ_CONTROL"],
    0x00040000: ["WRITE_DAC"],
    0x00080000: ["WRITE_OWNER"],
    0x00100000: ["SYNCHRONIZE"],
    0x01000000: ["ACCESS_SYSTEM_SECURITY"],
    0x02000000: ["MAXIMUM_ALLOWED"],
}

GENERIC_RIGHTS = {
    0x10000000: ["GENERIC_ALL"],
    0x20000000: ["GENERIC_EXECUTE"],
    0x40000000: ["GENERIC_WRITE"],
    0x80000000: ["GENERIC_READ"],
}

FILE_ALL_ACCESS = 0x001F01FF

# --- share permission bits (MS-SRVS ACCESS_*) ------------------------------ #
SHARE_RIGHTS = {
    0x01: "ACCESS_READ",
    0x02: "ACCESS_WRITE",
    0x04: "ACCESS_CREATE",
    0x08: "ACCESS_EXEC",
    0x10: "ACCESS_DELETE",
    0x20: "ACCESS_ATRIB",
    0x40: "ACCESS_PERM",
    0x7F: "ACCESS_ALL",
}

# friendly grouping used by reports / the agent
RIGHT_GROUPS = {
    "read": 0x00000089,        # READ_DATA|READ_EA|READ_ATTRIBUTES
    "write": 0x00000116,       # WRITE_DATA|APPEND_DATA|WRITE_EA|WRITE_ATTRIBUTES
    "execute": 0x000000A0,     # EXECUTE|READ_ATTRIBUTES
    "delete": 0x00010000,
    "full_control": FILE_ALL_ACCESS,
    "modify_dacl": 0x00040000,
}


def decode_access_mask(mask: int, is_directory: bool = False) -> list[str]:
    """Decode a file-object access mask into right names."""
    if mask == FILE_ALL_ACCESS:
        return ["FILE_ALL_ACCESS"]
    names: list[str] = []
    for bit, right_names in FILE_RIGHTS.items():
        if mask & bit:
            names.append(right_names[1] if is_directory else right_names[0])
    for bit, right_names in {**STANDARD_RIGHTS, **GENERIC_RIGHTS}.items():
        if mask & bit:
            names.extend(right_names)
    leftover = mask & ~sum(list(FILE_RIGHTS) + list(STANDARD_RIGHTS) + list(GENERIC_RIGHTS))
    if leftover:
        names.append(f"0x{leftover:08X}")
    return names


def decode_share_permissions(bits: int) -> list[str]:
    if bits == 0x7F:
        return [SHARE_RIGHTS[0x7F]]
    return [name for bit, name in SHARE_RIGHTS.items() if bits & bit and bit != 0x7F]


def summarize_rights(mask: int) -> list[str]:
    """Collapse a mask into coarse capability labels for quick scanning."""
    labels = []
    if mask & 0x00000001:
        labels.append("read")
    if mask & 0x00000002 or mask & 0x00000004:
        labels.append("write")
    if mask & 0x00000020:
        labels.append("execute")
    if mask & 0x00010000 or mask & 0x00000040:
        labels.append("delete")
    if mask & 0x00040000:
        labels.append("write-dac")
    if mask == FILE_ALL_ACCESS or (mask & 0x000F01FF) == 0x000F01FF:
        labels.append("full")
    return labels or ["none"]
