from credshrike.acl import decode_access_mask, decode_share_permissions, summarize_rights


def test_read_mask_decodes():
    names = decode_access_mask(0x00000089)  # READ_DATA|READ_EA|READ_ATTRIBUTES
    assert "FILE_READ_DATA" in names and "FILE_READ_EA" in names


def test_directory_mask_uses_directory_names():
    names = decode_access_mask(0x00000001, is_directory=True)
    assert names == ["LIST_DIRECTORY"]


def test_full_control_mask():
    assert decode_access_mask(0x001F01FF) == ["FILE_ALL_ACCESS"]


def test_delete_and_generic_bits():
    names = decode_access_mask(0x00010000 | 0x80000000)
    assert "DELETE" in names and "GENERIC_READ" in names


def test_unknown_bits_survive_as_hex():
    names = decode_access_mask(0x04000000)
    assert any(n.startswith("0x") for n in names)


def test_share_permission_bits():
    assert decode_share_permissions(0x7F) == ["ACCESS_ALL"]
    assert decode_share_permissions(0x03) == ["ACCESS_READ", "ACCESS_WRITE"]


def test_summarize_rights():
    assert "read" in summarize_rights(0x00000089)
    assert "write" in summarize_rights(0x00000116)
    assert "delete" in summarize_rights(0x00010000)
    assert summarize_rights(0) == ["none"]
