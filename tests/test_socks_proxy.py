"""Tests for credshrike.socks_proxy — URL parsing, socket shim, patching."""
import socket as real_socket

import pytest

from credshrike.socks_proxy import (
    PATCH_TARGETS,
    SocksSettings,
    _SocksSocketModule,
    apply_socks_proxy,
    clear_socks_proxy,
    parse_socks_url,
    socks_active,
)


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

def test_parse_socks5h_with_auth():
    s = parse_socks_url("socks5h://user:p%40ss@127.0.0.1:1080")
    assert s.scheme == "socks5h"
    assert (s.host, s.port) == ("127.0.0.1", 1080)
    assert s.rdns is True
    assert s.username == "user"
    assert s.password == "p@ss"  # %40 decoded


def test_parse_socks5_local_dns():
    s = parse_socks_url("socks5://10.0.0.1:9050")
    assert s.rdns is False
    assert s.username is None


def test_parse_socks4_and_http_connect():
    assert parse_socks_url("socks4://h:1").scheme == "socks4"
    assert parse_socks_url("http://proxy.corp:3128").scheme == "http"


def test_parse_bare_host_port_defaults_to_socks5h():
    assert parse_socks_url("127.0.0.1:1080").scheme == "socks5h"


@pytest.mark.parametrize("bad", [
    "", "   ", "ssh://x:1", "socks5://", "socks5://host", "socks5://host:0",
    "socks5://host:70000",
])
def test_parse_rejects_bad_urls(bad):
    with pytest.raises(ValueError):
        parse_socks_url(bad)


# ---------------------------------------------------------------------------
# socket shim (unit-tested against a fake PySocks — no network, no real socks)
# ---------------------------------------------------------------------------

class FakeSockSocket:
    created = []

    def __init__(self, family=real_socket.AF_INET, type=real_socket.SOCK_STREAM,
                 proto=0):
        self.family, self.type, self.proto = family, type, proto
        self.proxy = None
        self.connected = None
        self.timeout = None
        FakeSockSocket.created.append(self)

    def set_proxy(self, *args):
        self.proxy = args

    def settimeout(self, t):
        self.timeout = t

    def connect(self, addr):
        self.connected = addr


class FakeSocks:
    SOCKS5, SOCKS4, HTTP = 1, 4, 3

    class socksocket(FakeSockSocket):
        pass


@pytest.fixture()
def shim():
    settings = SocksSettings(scheme="socks5h", host="127.0.0.1", port=1080,
                             rdns=True, username="u", password="p")
    FakeSockSocket.created = []
    return _SocksSocketModule(settings, FakeSocks)


def test_shim_tcp_socket_is_proxied(shim):
    s = shim.socket()
    assert isinstance(s, FakeSockSocket)
    assert s.proxy == (FakeSocks.SOCKS5, "127.0.0.1", 1080, True, "u", "p")


def test_shim_udp_and_fileno_stay_direct(shim):
    udp = shim.socket(real_socket.AF_INET, real_socket.SOCK_DGRAM)
    assert not isinstance(udp, FakeSockSocket)
    assert udp.type == real_socket.SOCK_DGRAM
    udp.close()
    # fd-backed sockets cannot be proxied either — use a real fd so
    # Windows close() semantics stay valid
    holder = real_socket.socket()
    try:
        fd = shim.socket(real_socket.AF_INET, real_socket.SOCK_STREAM, 0,
                         fileno=holder.fileno())
        assert not isinstance(fd, FakeSockSocket)
        fd.detach()  # hand the fd back without closing
    finally:
        holder.close()


def test_shim_create_connection(shim):
    s = shim.create_connection(("fs01.corp.local", 445), timeout=7)
    assert s.connected == ("fs01.corp.local", 445)
    assert s.timeout == 7
    assert s.proxy is not None


def test_shim_getaddrinfo_passthrough_when_remote_dns(shim):
    res = shim.getaddrinfo("fs01.corp.local", 445, 0, real_socket.SOCK_STREAM)
    af, socktype, proto, canon, addr = res[0]
    assert af == real_socket.AF_INET
    # hostname handed to the proxy unresolved
    assert addr == ("fs01.corp.local", 445)


def test_shim_getaddrinfo_local_dns_delegates(shim):
    # socks5 (rdns=False): real resolution — a loopback literal works offline
    shim._settings = SocksSettings(scheme="socks5", host="127.0.0.1", port=1080,
                                   rdns=False)
    res = shim.getaddrinfo("127.0.0.1", 445, 0, real_socket.SOCK_STREAM)
    assert res[0][4] == ("127.0.0.1", 445)


def test_shim_falls_through_to_real_socket_module(shim):
    assert shim.error is real_socket.error
    assert shim.AF_INET == real_socket.AF_INET
    assert shim.gaierror is real_socket.gaierror


# ---------------------------------------------------------------------------
# module patching
# ---------------------------------------------------------------------------

def _importable_targets():
    """PATCH_TARGETS minus modules this impacket build cannot import
    (this dev box's impacket 0.10 has a half-broken krb5 package)."""
    import importlib
    out = []
    for name in PATCH_TARGETS:
        try:
            importlib.import_module(name)
            out.append(name)
        except ImportError:
            continue
    assert out, "no patch targets importable at all"
    return out


def test_apply_patches_targets_and_clear_restores():
    import importlib
    targets = _importable_targets()
    before = {name: importlib.import_module(name).socket for name in targets}
    try:
        settings = apply_socks_proxy("socks5h://127.0.0.1:1080")
        assert settings.port == 1080
        assert socks_active()
        for name in targets:
            patched = importlib.import_module(name).socket
            assert patched is not before[name]
            # a TCP socket from the patched module carries the proxy config
            s = patched.socket()
            assert s.proxy[1:3] == ("127.0.0.1", 1080)
    finally:
        clear_socks_proxy()
    for name in targets:
        assert importlib.import_module(name).socket is before[name]
    assert not socks_active()


def test_apply_is_idempotent():
    apply_socks_proxy("socks5://127.0.0.1:1080")
    try:
        apply_socks_proxy("socks5h://127.0.0.1:1081")
        import credshrike.agent.orchestrator as orch
        # second apply replaced the shim, still exactly one socket symbol
        assert hasattr(orch.socket, "socket")
    finally:
        clear_socks_proxy()


def test_apply_rejects_bad_url_without_patching():
    with pytest.raises(ValueError):
        apply_socks_proxy("not-a-proxy")
    assert not socks_active()


# ---------------------------------------------------------------------------
# wiring: policy key, CLI override, web override
# ---------------------------------------------------------------------------

def test_policy_has_socks_proxy_default():
    from credshrike.config import Policy
    assert Policy().socks_proxy == ""


def test_agent_flag_overrides_policy():
    from credshrike.agent.cli_agent import _load_policy
    from credshrike.cli import build_parser

    ns = build_parser().parse_args(["agent", "--socks-proxy", "socks5h://10.0.0.9:1080"])
    policy = _load_policy(ns)
    assert policy.socks_proxy == "socks5h://10.0.0.9:1080"


def test_web_override_sets_policy():
    from credshrike.config import Policy
    from credshrike.webapp import _apply_policy_overrides
    policy = Policy()
    _apply_policy_overrides(policy, {"socks_proxy": "socks5://10.1.2.3:1080"})
    assert policy.socks_proxy == "socks5://10.1.2.3:1080"
    # empty form field keeps the policy default
    policy2 = Policy()
    _apply_policy_overrides(policy2, {"socks_proxy": ""})
    assert policy2.socks_proxy == ""
