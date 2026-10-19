"""Scanner tests: tier triage, regex sweep, masking, caps, coverage stats."""

import base64

from smbenum.patterns import classify_file, compile_patterns
from smbenum.scanner import scan_share, mask_line


class FakeScanSMB:
    """Directory tree + file contents for the sweep."""

    def __init__(self, tree: dict, contents: dict):
        self.tree = tree          # path -> [entry names]; root key ""
        self.contents = contents  # path -> bytes
        self.read_calls = []

    def list_dir(self, share, path="", max_entries=200):
        entries = [{"name": ".", "is_dir": True, "size": 0},
                   {"name": "..", "is_dir": True, "size": 0}]   # real servers return these
        for name in self.tree.get(path, []):
            child = f"{path}/{name}" if path else name
            is_dir = child in self.tree
            size = 0 if is_dir else len(self.contents.get(child, b""))
            entries.append({"name": name, "is_dir": is_dir, "size": size})
        return {"share": share, "path": path, "entries": entries,
                "truncated": False, "total_seen": len(entries)}

    def read_file(self, share, path, offset=0, max_bytes=65536):
        self.read_calls.append(path)
        data = self.contents.get(path, b"")[offset: offset + max_bytes]
        return {"share": share, "path": path, "offset": offset, "size": len(data),
                "truncated": False, "content_b64": base64.b64encode(data).decode()}


def _tree():
    # entries: root(3) + Scripts(6) + Photos(2) = 11 entries (2 dirs, 9 files)
    # red: id_rsa_backup.key · yellow: deploy.ps1, backup.sql, readme.txt,
    # users.csv, config.json · untiered: photo.png, helper.cs, pic1.jpg
    return FakeScanSMB(
        tree={"": ["Scripts", "Photos", "readme.txt"],
              "Scripts": ["deploy.ps1", "photo.png", "backup.sql", "helper.cs",
                          "users.csv", "config.json"],
              "Photos": ["pic1.jpg", "id_rsa_backup.key"]},
        contents={
            "Scripts/deploy.ps1": b"$u='svc-scan'\n$password = 'Sup3rS3cret!'\nWrite-Host done\n",
            "Scripts/backup.sql": b"-- dump\npwd=hunter2;\npassword=Tr0ub4dor;\n",
            "readme.txt": b"nothing interesting here\n",
            "Photos/id_rsa_backup.key": b"-----BEGIN RSA PRIVATE KEY-----\nabc\n",
            # structured data: NO keyword matches, but the AI must read these
            "Scripts/users.csv": b"username,password,role\nalex,P@ssw0rd,admin\nsvc,Sup3rS3cret!,svc\n",
            "Scripts/config.json": b'{"db_user": "root", "db_pass": "toor123"}\n',
        })


# --------------------------------------------------------------------------- #
# triage
# --------------------------------------------------------------------------- #
def test_classify_tiers():
    assert classify_file("passwords.txt") == "red"        # name substring
    assert classify_file("id_rsa") == "red"
    assert classify_file("unattend.xml") == "red"
    assert classify_file("key.ppk") == "red"
    assert classify_file("deploy.ps1") == "yellow"        # extension
    assert classify_file("photo.png") is None             # not in any tier
    assert classify_file("helper.cs") is None
    assert classify_file("deploy.ps1", tiers=("red",)) is None  # tier selection


def test_mask_line():
    # "abc123" spans offsets 11..17 in "password = abc123"
    assert mask_line("password = abc123", 11, 17) == "password = ***"
    assert mask_line("no group here", -1, -1) == "no group here"


# --------------------------------------------------------------------------- #
# sweep
# --------------------------------------------------------------------------- #
def test_scan_finds_and_masks_secrets():
    result = scan_share(_tree(), "IT")
    paths = {m["path"] for m in result["matches"]}
    assert "Scripts/deploy.ps1" in paths
    assert "Scripts/backup.sql" in paths
    assert "Photos/id_rsa_backup.key" in paths            # private_key_block pattern
    assert "readme.txt" not in paths
    # secrets are masked in snippets, context kept
    joined = " ".join(m["snippet"] for m in result["matches"])
    assert "Sup3rS3cret" not in joined and "hunter2" not in joined
    assert "***" in joined
    # line numbers point at the hits
    dep = [m for m in result["matches"]
           if m["path"] == "Scripts/deploy.ps1"
           and m["pattern"] == "password_assignment"][0]
    assert dep["line"] == 2


def test_scan_respects_tiers_and_depth():
    fake = _tree()
    result = scan_share(fake, "IT", tiers=("red",))   # only red-tier files opened
    opened = set(fake.read_calls)
    assert "Scripts/deploy.ps1" not in opened          # yellow not opened in red-only sweep
    assert opened == {"Photos/id_rsa_backup.key"}      # the only red-tier file
    assert result["stats"]["files_skipped_notier"] == 8  # deselected-tier + untiered

    fake2 = _tree()
    scan_share(fake2, "IT", depth=0)                   # depth 0: no subdirectories
    assert all("/" not in p for p in fake2.read_calls)


def test_scan_caps_and_stats():
    fake = _tree()
    result = scan_share(fake, "IT", max_files=1)
    assert result["truncated"] and "max_files" in result["stop_reason"]
    assert result["stats"]["files_scanned"] == 1
    # stats reflect the walk
    full = scan_share(_tree(), "IT")
    assert full["stats"]["dirs_walked"] == 3            # root + Scripts + Photos
    assert full["stats"]["files_seen"] == 11            # all entries incl. dirs
    assert full["stats"]["files_scanned"] == 6          # red + yellow + data files
    assert full["stats"]["bytes_scanned"] > 0
    assert not full["truncated"]


def test_scan_event_stream():
    events = []
    scan_share(_tree(), "IT", on_event=lambda k, d: events.append((k, d)))
    kinds = [k for k, _ in events]
    assert "walk" in kinds and "scan" in kinds and "done" in kinds
    hits = [d for k, d in events if k == "hit"]
    assert any(h["pattern"] == "password_assignment" for h in hits)


def test_custom_patterns_merge_and_override():
    patterns = compile_patterns(extra={"svc_account": r"\bsvc-[a-z]+\b"})
    names = [p["name"] for p in patterns]
    assert "password_assignment" in names and "svc_account" in names
    fake = _tree()
    result = scan_share(fake, "IT", patterns=patterns)
    assert any(m["pattern"] == "svc_account" and "svc-scan" in m["snippet"]
               for m in result["matches"])


def test_scan_skips_dot_dotdot_pseudo_entries():
    # FakeScanSMB now returns ./.. like a real server; the sweep must not
    # descend into them (no 'a/./../..' paths, no walk errors)
    events = []
    result = scan_share(_tree(), "IT", on_event=lambda k, d: events.append((k, d)))
    walk_paths = [d["path"] for k, d in events if k == "walk"]
    assert all("/." not in p and "/.." not in p for p in walk_paths)
    assert not any(k == "walk_error" for k, _ in events)
    # counts unchanged by the pseudo entries (stats identical to before)
    assert result["stats"]["files_seen"] == 11 and result["stats"]["dirs_walked"] == 3


def test_scan_match_paging():
    # the tree yields 5 hits (backup.sql's password= matches two patterns);
    # page size 2 -> 2/2/1 across three pages, next_skip chained then null
    page1 = scan_share(_tree(), "IT", max_matches_returned=2)
    assert page1["matches_total"] == 5 and len(page1["matches"]) == 2
    assert page1["matches_skip"] == 0 and page1["next_skip"] == 2
    page2 = scan_share(_tree(), "IT", max_matches_returned=2, skip_matches=2)
    assert len(page2["matches"]) == 2 and page2["next_skip"] == 4
    page3 = scan_share(_tree(), "IT", max_matches_returned=2, skip_matches=4)
    assert len(page3["matches"]) == 1 and page3["next_skip"] is None


def test_data_files_surfaced_even_without_regex_hits():
    # users.csv / config.json carry credentials but NO regex keyword matches:
    # they must appear in data_files so the AI reads them itself
    result = scan_share(_tree(), "IT")
    data_paths = {d["path"] for d in result["data_files"]}
    assert data_paths == {"Scripts/users.csv", "Scripts/config.json"}
    csv_entry = next(d for d in result["data_files"] if d["path"].endswith("users.csv"))
    assert csv_entry["size"] > 0 and csv_entry["tier"] == "yellow"
    # and their content produced no masked matches (proving regex blindness)
    assert not any(m["path"].endswith((".csv", ".json")) for m in result["matches"])


# --------------------------------------------------------------------------- #
# full-content dump (custom-goal mode: EVERY file, no tier filtering)
# --------------------------------------------------------------------------- #
from smbenum.scanner import dump_share


def test_dump_includes_all_formats():
    result = dump_share(_tree(), "IT", page_chars=100000)
    paths = {f["path"] for f in result["files"]}
    # untiered files that the tier sweep would NEVER open are all here
    assert {"Scripts/photo.png", "Scripts/helper.cs", "Photos/pic1.jpg"} <= paths
    # content is decoded text, head_truncated flags big heads
    entry = next(f for f in result["files"] if f["path"] == "Scripts/users.csv")
    assert "alex,P@ssw0rd" in entry["content"] and not entry["head_truncated"]
    assert result["files_total"] == 9 and result["next_skip"] is None


def test_dump_paging_and_per_file_head():
    fake = FakeScanSMB(tree={"": ["big.bin"]},
                       contents={"big.bin": b"A" * 5000})
    result = dump_share(fake, "IT", per_file_bytes=1000, page_chars=2000)
    entry = result["files"][0]
    assert len(entry["content"]) == 1000 and entry["head_truncated"] is True
    assert entry["size"] == 5000

    # page_chars packing: many files split across pages via next_skip chain
    fake2 = FakeScanSMB(tree={"": [f"f{i}.txt" for i in range(6)]},
                        contents={f"f{i}.txt": b"x" * 900 for i in range(6)})
    page1 = dump_share(fake2, "IT", page_chars=2000)   # ~2 files per page
    assert len(page1["files"]) == 2 and page1["next_skip"] == 2
    page2 = dump_share(fake2, "IT", page_chars=2000, skip_files=2)
    assert page2["files_skip"] == 2 and page2["next_skip"] == 4
    last = dump_share(fake2, "IT", page_chars=2000, skip_files=4)
    assert len(last["files"]) == 2 and last["next_skip"] is None


def test_net_use_credential_pattern():
    result = scan_share(FakeScanSMB(
        tree={"": ["b.bat"]},
        contents={"b.bat": b"net use \\FILE01\CTF$ /user:HACKADAY\jchen Welcome1\r\n"}),
        "IT")
    hit = next(m for m in result["matches"] if m["pattern"] == "net_use_credential")
    assert "Welcome1" not in hit["snippet"] and "***" in hit["snippet"]
