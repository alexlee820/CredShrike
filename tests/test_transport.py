"""Tests for the enumeration transport seam (credshrike/transport.py)."""
import pytest

from credshrike.smb_session import ImpacketTransport, SMBSession
from credshrike.transport import (EnumerationTransport,
                                  TransportUnsupported)


def test_impacket_transport_satisfies_the_interface():
    """ImpacketTransport IS an EnumerationTransport — the seam callers hold."""
    assert issubclass(ImpacketTransport, EnumerationTransport)
    assert issubclass(ImpacketTransport, SMBSession)   # behavior unchanged


def test_cached_session_is_a_transport():
    from credshrike.inventory_cache import CachedSMBSession
    assert issubclass(CachedSMBSession, EnumerationTransport)


def test_interface_is_abstract_and_narrow():
    """A transport MUST implement the four core methods; the interface has
    no write/create/delete/execute surface for anyone to implement."""
    class Empty(EnumerationTransport):
        pass
    with pytest.raises(TypeError):
        Empty()          # abstract methods unimplemented

    abstract = EnumerationTransport.__abstractmethods__
    assert abstract == frozenset({"list_shares", "list_dir", "read_file",
                                  "stat"})
    for forbidden in ("write", "create", "delete", "execute", "upload",
                      "shell", "run"):
        assert not hasattr(EnumerationTransport, forbidden)


def test_optional_capabilities_default_to_unsupported():
    class Bare(EnumerationTransport):
        def list_shares(self): return []
        def list_dir(self, share, path="", max_entries=500): return {}
        def read_file(self, share, path, offset=0, max_bytes=1): return {}
        def stat(self, share, path): return {}

    t = Bare()
    for method, args in (("get_security", ("IT", "a.txt")),
                         ("get_share_security", ("IT",)),
                         ("effective_access", ("IT", "a.txt"))):
        with pytest.raises(TransportUnsupported):
            getattr(t, method)(*args)


def test_impacket_shadows_the_optional_defaults():
    """SMBSession's real implementations win over the ABC's defaults — no
    behavior change for the impacket path."""
    assert (ImpacketTransport.get_security
            is SMBSession.get_security)
    assert (ImpacketTransport.get_share_security
            is SMBSession.get_share_security)
    assert (ImpacketTransport.effective_access
            is SMBSession.effective_access)


def test_lifecycle_defaults_are_noop_for_connectionless_transports():
    class Bare(EnumerationTransport):
        def list_shares(self): return []
        def list_dir(self, share, path="", max_entries=500): return {}
        def read_file(self, share, path, offset=0, max_bytes=1): return {}
        def stat(self, share, path): return {}

    with Bare() as t:      # connect()/close() context manager works
        assert t.host == Bare.host if hasattr(Bare, "host") else True
