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
            entries.append({"name": name, "is_dir": is_dir, "size": 10})
        return {"share": share, "path": path, "entries": entries,
                "truncated": False, "total_seen": len(entries)}

    def read_file(self, share, path, offset=0, max_bytes=65536):
        self.read_calls.append(path)
        data = self.contents.get(path, b"")
        return {"share": share, "path": path, "offset": 0, "size": len(data),
                "truncated": False, "content_b64": base64.b64encode(data).decode()}


def _tree():
    # entries: root(3) + Scripts(4) + Photos(2) = 9 entries (2 dirs, 7 files)
    # red file: Photos/id_rsa_backup.key (.key)
    # yellow files: deploy.ps1, backup.sql, readme.txt
    # untiered: photo.png, helper.cs, pic1.jpg
    return FakeScanSMB(
        tree={"": ["Scripts", "Photos", "readme.txt"],
              "Scripts": ["deploy.ps1", "photo.png", "backup.sql", "helper.cs"],
              "Photos": ["pic1.jpg", "id_rsa_backup.key"]},
        contents={
            "Scripts/deploy.ps1": b"$u='svc-scan'\n$password = 'Sup3rS3cret!'\nWrite-Host done\n",
            "Scripts/backup.sql": b"-- dump\npwd=hunter2;\npassword=Tr0ub4dor;\n",
            "readme.txt": b"nothing interesting here\n",
            "Photos/id_rsa_backup.key": b"-----BEGIN RSA PRIVATE KEY-----\nabc\n",
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
    assert result["stats"]["files_skipped_notier"] == 6  # deselected-tier + untiered

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
    assert full["stats"]["files_seen"] == 9             # all entries incl. dirs
    assert full["stats"]["files_scanned"] == 4          # red + yellow files
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
    assert result["stats"]["files_seen"] == 9 and result["stats"]["dirs_walked"] == 3


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
