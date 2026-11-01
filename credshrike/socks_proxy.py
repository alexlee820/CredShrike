"""Route SMB/LDAP/ADWS/Kerberos traffic through a SOCKS proxy — LLM direct.

Why not proxychains: it tunnels the whole process (LD_PRELOAD on connect()),
so the Anthropic SDK / httpx calls to the AI provider also traverse the pivot.
They fail outright when the pivot has no internet egress, and egress from the
client network when it does. Instead we swap the ``socket`` symbol inside the
network-protocol modules only — impacket (SMB via nmb, LDAP, Kerberos), the
vendored ADWS client and the orchestrator reachability probe — leaving the
LLM transport untouched.

Supported URLs::

    socks5://[user:pass@]host:port     local DNS resolution
    socks5h://[user:pass@]host:port    hostname resolved AT the proxy
    socks4://[user:pass@]host:port
    http://[user:pass@]host:port       HTTP CONNECT proxy

With ``socks5h`` the shim also passes ``getaddrinfo`` through, so impacket's
resolve-then-connect flow hands the hostname to the proxy instead of
requiring local DNS for the target domain. Non-TCP sockets (NetBIOS UDP name
service) and anything else asking the shim for attributes they need keep
using the real socket module.

Standalone check::

    python -m credshrike.socks_proxy socks5h://127.0.0.1:1080 10.0.0.5 445
"""
from __future__ import annotations

import dataclasses
import socket as _socket
from typing import Any, Optional
from urllib.parse import unquote, urlparse

# Modules whose ``socket`` symbol gets swapped. All outbound target-network
# traffic of CredShrike is created through one of these.
PATCH_TARGETS = (
    "impacket.nmb",                    # SMB2/3 + NetBIOS sessions (445/139)
    "impacket.ldap.ldap",              # LDAP (389/636)
    "impacket.krb5.kerberosv5",        # Kerberos TCP
    "credshrike.domain.adws.adws_client",   # ADWS net.tcp (9389)
    "credshrike.agent.orchestrator",   # SMB reachability probe
)

_SCHEMES = ("socks5", "socks5h", "socks4", "http")


@dataclasses.dataclass(frozen=True)
class SocksSettings:
    scheme: str
    host: str
    port: int
    rdns: bool
    username: Optional[str] = None
    password: Optional[str] = None
    url: str = ""

    def describe(self) -> str:
        auth = f"{self.username}:***@" if self.username else ""
        return f"{self.scheme}://{auth}{self.host}:{self.port}"


def parse_socks_url(url: str) -> SocksSettings:
    """Parse and validate a proxy URL. Raises ValueError on bad input."""
    raw = (url or "").strip()
    if not raw:
        raise ValueError("empty socks proxy url")
    parsed = urlparse(raw if "://" in raw else f"socks5h://{raw}")
    scheme = parsed.scheme.lower()
    if scheme not in _SCHEMES:
        raise ValueError(
            f"unsupported proxy scheme {scheme!r} (expected one of: {', '.join(_SCHEMES)})")
    host = parsed.hostname
    if not host:
        raise ValueError(f"proxy url has no host: {url!r}")
    port = parsed.port
    if port is None or not (1 <= port <= 65535):
        raise ValueError(f"proxy url has no valid port: {url!r}")
    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    return SocksSettings(
        scheme=scheme, host=host, port=port,
        # socks5h = resolve at the proxy (curl convention); socks5 = local
        rdns=(scheme == "socks5h"),
        username=username, password=password, url=raw,
    )


class _SocksSocketModule:
    """Impersonates the ``socket`` module for the patched protocol modules.

    ``socket()`` returns a PySocks ``socksocket`` pre-configured with the
    proxy (TCP only — datagram sockets stay direct); ``create_connection``
    and, with remote DNS, ``getaddrinfo`` are reimplemented on top of it;
    every other attribute falls through to the real socket module.
    """

    def __init__(self, settings: SocksSettings, socks_mod) -> None:
        self._settings = settings
        self._socks = socks_mod

    # -- proxy type ------------------------------------------------------
    def _proxy_type(self) -> int:
        return {
            "socks5": self._socks.SOCKS5,
            "socks5h": self._socks.SOCKS5,
            "socks4": self._socks.SOCKS4,
            "http": self._socks.HTTP,
        }[self._settings.scheme]

    # -- factories -------------------------------------------------------
    def socket(self, family=_socket.AF_INET, type=_socket.SOCK_STREAM,
               proto=0, fileno=None):
        if fileno is not None or type == _socket.SOCK_DGRAM:
            # fd-backed or UDP sockets (NetBIOS name service) stay direct:
            # SOCKS cannot carry them and these paths are never proxied.
            return _socket.socket(family, type, proto, fileno)
        s = self._socks.socksocket(family, type, proto)
        s.set_proxy(self._proxy_type(), self._settings.host, self._settings.port,
                    self._settings.rdns, self._settings.username, self._settings.password)
        return s

    def create_connection(self, address, timeout=None, source_address=None):
        host, port = address
        s = self.socket()
        if timeout is not None:
            s.settimeout(timeout)
        if source_address:
            s.bind(source_address)
        s.connect((host, port))
        return s

    def getaddrinfo(self, host, port, family=0, type=0, proto=0, flags=0):
        """socks5h: hand the hostname to the proxy instead of resolving here.

        impacket resolves before connecting and then connects to the resolved
        sockaddr — passing the original host through in the sockaddr keeps
        the name resolution at the proxy, where the target domain is
        actually reachable.
        """
        if not self._settings.rdns or flags or family not in (0, _socket.AF_INET, _socket.AF_INET6):
            return _socket.getaddrinfo(host, port, family, type, proto, flags)
        af = _socket.AF_INET6 if _is_v6_literal(host) else _socket.AF_INET
        socktype = type or _socket.SOCK_STREAM
        return [(af, socktype, _socket.IPPROTO_TCP, "", (host, port))]

    # -- everything else: the real socket module --------------------------
    def __getattr__(self, name: str) -> Any:
        return getattr(_socket, name)


def _is_v6_literal(host: str) -> bool:
    return ":" in host and host.strip("[]").count(":")


# ---------------------------------------------------------------------------
# apply / clear
# ---------------------------------------------------------------------------

_originals: dict = {}   # module name -> original socket symbol (for restore)


def apply_socks_proxy(url: str) -> SocksSettings:
    """Patch the protocol modules. Returns the parsed settings.

    Idempotent per module; raises RuntimeError when PySocks is missing and
    ValueError when the URL is malformed.
    """
    settings = parse_socks_url(url)
    try:
        import socks  # PySocks
    except ImportError as exc:  # pragma: no cover - depends on install
        raise RuntimeError(
            "--socks-proxy / socks_proxy is set but PySocks is not installed "
            "(pip install PySocks)") from exc

    import importlib
    shim = _SocksSocketModule(settings, socks)
    for name in PATCH_TARGETS:
        try:
            mod = importlib.import_module(name)
        except ImportError:
            continue  # e.g. optional transport not installed
        if name not in _originals:
            _originals[name] = mod.__dict__.get("socket", _socket)
        mod.socket = shim
    return settings


def clear_socks_proxy() -> None:
    """Restore the original socket symbols (used by tests)."""
    import importlib
    for name, original in _originals.items():
        try:
            mod = importlib.import_module(name)
            mod.socket = original
        except ImportError:
            pass
    _originals.clear()


def socks_active() -> bool:
    return bool(_originals)


if __name__ == "__main__":  # standalone smoke check: python -m ... host port
    import sys
    proxy_url, target_host, target_port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    settings = apply_socks_proxy(proxy_url)
    print(f"proxy {settings.describe()} → {target_host}:{target_port} ...")
    from credshrike.agent import orchestrator  # patched module
    s = orchestrator.socket.create_connection((target_host, target_port), timeout=8)
    peer = s.getpeername()
    s.close()
    print(f"connected via proxy, peer={peer}")
