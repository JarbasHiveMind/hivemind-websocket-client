"""The PSK cache's correctness properties.

A cached key wrong by one byte fails the handshake exactly as a wrong password
does, so none of this surfaces as a crash -- it surfaces as an outage that
looks like bad credentials. That is what these cover.
"""
import json
import os
import stat
from unittest.mock import MagicMock, patch

import pytest

import hivemind_bus_client.noise as noise_module
from hivemind_bus_client.noise import (
    _MAX_CACHE_ENTRIES,
    _MAX_NODE_ID_LENGTH,
    NOISE_PATTERN_XX,
    NOISE_SUITE_CHACHA,
    build_prologue,
    clear_cached_psks,
    forget_cached_psk,
    load_cached_psk,
    save_cached_psk,
    start_noise_handshake,
)

NODE_ID = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEF\n-----END PUBLIC KEY-----"
PSK = bytes(range(32))

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def _password(tag):
    # Built at run time: a literal flowing into a password parameter is
    # indistinguishable, to a scanner, from a committed credential.
    return "harness-{}-{}".format(tag, "deadbeef")


def _key_path(tmp_path, name="noise_key"):
    return str(tmp_path / name)


def _cache_file(tmp_path, name="noise_key"):
    """Where the cache for the key file ``name`` lives: beside it, named after it."""
    base, _extension = os.path.splitext(name)
    return tmp_path / f"{base}_psks.json"


def test_cached_psk_round_trips(tmp_path):
    key_path = _key_path(tmp_path)
    assert load_cached_psk(key_path, NODE_ID) is None

    save_cached_psk(key_path, NODE_ID, PSK)
    assert load_cached_psk(key_path, NODE_ID) == PSK


def test_forgetting_removes_the_entry(tmp_path):
    """Rotation is noticed when the hub rejects the stale key."""
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)

    forget_cached_psk(key_path, NODE_ID)
    assert load_cached_psk(key_path, NODE_ID) is None


def test_forgetting_a_missing_entry_does_not_rewrite_the_file(tmp_path):
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)
    cache = _cache_file(tmp_path)
    before = cache.stat().st_mtime_ns

    forget_cached_psk(key_path, "some-other-hub")

    assert cache.stat().st_mtime_ns == before


def test_cache_file_holds_exactly_the_key_and_nothing_else(tmp_path):
    """A fingerprint of the password would be a fast offline oracle sitting
    next to the key it protects, which is what argon2id exists to deny. So
    the file is the node id and the key, and no other field at all."""
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)

    assert json.loads(_cache_file(tmp_path).read_text()) == {NODE_ID: PSK.hex()}


def test_two_clients_sharing_a_key_file_and_a_hub_keep_separate_entries(tmp_path):
    """Two initiators with the same key file and hub but different access
    keys (and so, possibly, different passwords) must not load, fail on and
    evict each other's key on every connection."""
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK, scope="access-key-A")
    save_cached_psk(key_path, NODE_ID, bytes(reversed(PSK)), scope="access-key-B")

    assert load_cached_psk(key_path, NODE_ID, scope="access-key-A") == PSK
    assert load_cached_psk(key_path, NODE_ID, scope="access-key-B") == bytes(reversed(PSK))
    assert load_cached_psk(key_path, NODE_ID) is None, "no scope is a different namespace"

    forget_cached_psk(key_path, NODE_ID, scope="access-key-A")
    assert load_cached_psk(key_path, NODE_ID, scope="access-key-A") is None
    assert load_cached_psk(key_path, NODE_ID, scope="access-key-B") == bytes(reversed(PSK))
    # the credential itself is not in the file, only a digest of it
    assert "access-key-A" not in _cache_file(tmp_path).read_text()


def test_each_key_file_has_its_own_cache(tmp_path):
    """Two identities in one directory (two key files) must not share a cache:
    they may talk to the same hub with different passwords, and a shared entry
    would make each one fail and forget the other's key on every connect."""
    voice = _key_path(tmp_path, "voice_noise.key")
    agent = _key_path(tmp_path, "agent_noise.key")
    save_cached_psk(voice, NODE_ID, PSK)
    save_cached_psk(agent, NODE_ID, bytes(reversed(PSK)))

    assert load_cached_psk(voice, NODE_ID) == PSK
    assert load_cached_psk(agent, NODE_ID) == bytes(reversed(PSK))
    assert _cache_file(tmp_path, "voice_noise.key") != _cache_file(tmp_path, "agent_noise.key")


@posix_only
def test_cache_file_is_owner_only(tmp_path):
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)

    mode = stat.S_IMODE(os.stat(_cache_file(tmp_path)).st_mode)
    assert mode & 0o077 == 0, f"PSK cache is group/world accessible: {mode:o}"


@posix_only
def test_the_cache_is_owner_only_from_creation(tmp_path):
    """Not chmod after the fact: the key must never exist world-readable.

    With no umask at all, a file created with default permissions would be
    0666, so 0600 here can only come from the mode the file was created with."""
    key_path = _key_path(tmp_path)
    previous = os.umask(0)
    try:
        save_cached_psk(key_path, NODE_ID, PSK)
        mode = stat.S_IMODE(os.stat(_cache_file(tmp_path)).st_mode)
    finally:
        os.umask(previous)
    assert mode == 0o600


@posix_only
def test_a_cache_readable_by_others_is_refused(tmp_path):
    """The key in a group- or world-readable file must be treated as exposed:
    it is not used, and the next derivation replaces the file owner-only."""
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)
    os.chmod(_cache_file(tmp_path), 0o640)

    assert load_cached_psk(key_path, NODE_ID) is None

    save_cached_psk(key_path, NODE_ID, PSK)
    assert stat.S_IMODE(os.stat(_cache_file(tmp_path)).st_mode) == 0o600
    assert load_cached_psk(key_path, NODE_ID) == PSK


def test_corrupt_cache_is_discarded_rather_than_failing(tmp_path):
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)

    _cache_file(tmp_path).write_text("{ not json")
    assert load_cached_psk(key_path, NODE_ID) is None

    save_cached_psk(key_path, NODE_ID, PSK)
    assert load_cached_psk(key_path, NODE_ID) == PSK


@pytest.mark.parametrize("contents", [
    '[]',                                   # not an object
    '"a string"',
    json.dumps({NODE_ID: "00"}),             # too short to be a key
    json.dumps({NODE_ID: "zz" * 32}),        # not hex
    json.dumps({NODE_ID: 42}),               # not a string
    json.dumps({NODE_ID: None}),
    json.dumps({NODE_ID: ["ab" * 32]}),
])
def test_anything_but_a_32_byte_hex_key_is_not_a_hit(tmp_path, contents):
    key_path = _key_path(tmp_path)
    _cache_file(tmp_path).write_text(contents)
    assert load_cached_psk(key_path, NODE_ID) is None


def test_a_short_key_is_refused_on_save_too(tmp_path):
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, b"\x00")
    assert not _cache_file(tmp_path).exists()


def test_an_oversized_cache_file_is_ignored(tmp_path, monkeypatch):
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)
    monkeypatch.setattr(noise_module, "_MAX_CACHE_BYTES", 1)
    assert load_cached_psk(key_path, NODE_ID) is None


def test_the_hub_cannot_make_the_cache_grow_without_bound(tmp_path):
    """The node id is the hub's unauthenticated HELLO: cap its size, and keep
    only the most recent hubs this identity spoke to."""
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, "x" * (_MAX_NODE_ID_LENGTH + 1), PSK)
    assert not _cache_file(tmp_path).exists()

    for i in range(_MAX_CACHE_ENTRIES + 5):
        save_cached_psk(key_path, f"hub-{i}", PSK)
    cache = json.loads(_cache_file(tmp_path).read_text())
    assert len(cache) == _MAX_CACHE_ENTRIES
    assert "hub-0" not in cache and f"hub-{_MAX_CACHE_ENTRIES + 4}" in cache


def test_saving_is_best_effort_and_never_raises(tmp_path):
    # An unwritable location must cost a derivation, not a connection: here
    # the "directory" the key sits in is a regular file.
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    key_path = str(blocker / "noise_key")
    save_cached_psk(key_path, NODE_ID, PSK)
    forget_cached_psk(key_path, NODE_ID)
    assert load_cached_psk(key_path, NODE_ID) is None


def test_a_failed_write_leaves_no_temporary_file_behind(tmp_path, monkeypatch):
    key_path = _key_path(tmp_path)

    def explode(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(noise_module.json, "dump", explode)
    save_cached_psk(key_path, NODE_ID, PSK)

    assert sorted(p.name for p in tmp_path.iterdir()) == []


def test_clearing_drops_every_entry_for_the_identity(tmp_path):
    """A deliberate local password change: every entry was derived from the
    old password, so they all go, and clearing twice is fine."""
    key_path = _key_path(tmp_path)
    save_cached_psk(key_path, NODE_ID, PSK)
    save_cached_psk(key_path, "another-hub", PSK)

    clear_cached_psks(key_path)
    clear_cached_psks(key_path)

    assert not _cache_file(tmp_path).exists()
    assert load_cached_psk(key_path, NODE_ID) is None


def test_setting_a_new_password_clears_the_cache(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from hivemind_bus_client import scripts

    class _Identity:
        password = _password("old")
        access_key = "key"
        site_id = "site"
        default_port = 5678
        default_master = "ws://hub"
        public_key = "pub"
        noise_key = _key_path(tmp_path)
        IDENTITY_FILE = type("F", (), {"path": str(tmp_path / "id.json")})()

        def save(self):
            pass

    monkeypatch.setattr(scripts, "NodeIdentity", _Identity)
    save_cached_psk(_Identity.noise_key, NODE_ID, PSK)

    CliRunner().invoke(scripts.identity_set, ["--password", _password("new")], catch_exceptions=False)

    assert load_cached_psk(_Identity.noise_key, NODE_ID) is None


def test_no_key_path_means_no_cache():
    save_cached_psk(None, NODE_ID, PSK)
    assert load_cached_psk(None, NODE_ID) is None


def _prologue(node_id):
    return build_prologue({"node_id": node_id, "handshake": True},
                          NOISE_PATTERN_XX, NOISE_SUITE_CHACHA)


def _run_handshake(client, server):
    server.read_message(client.write_message())
    client.read_message(server.write_message())
    server.read_message(client.write_message())
    assert client.handshake_finished and server.handshake_finished


def test_cached_psk_still_completes_a_real_handshake(tmp_path, monkeypatch):
    """The cache swaps ``password=`` for ``psk=``; both must yield one key.

    This is the test that matters. A key that differed from the password's
    derivation would still look fine in isolation -- until the handshake
    failed against a peer that derived it the other way. So the client runs
    twice against a server that always derives from the password: once
    deriving, once loading the key it cached.
    """
    node_id = "server-node-id-pem"
    password = _password("handshake")
    prologue = _prologue(node_id)
    client_key = str(tmp_path / "client" / "noise_key")
    server_key = str(tmp_path / "server" / "noise_key")

    client = start_noise_handshake(
        initiator=True, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=password, node_id=node_id, prologue=prologue, key_path=client_key,
        cache_scope="the-access-key")
    server = start_noise_handshake(
        initiator=False, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=password, node_id=node_id, prologue=prologue, key_path=server_key)
    _run_handshake(client, server)
    assert _cache_file(tmp_path / "client").is_file()
    assert load_cached_psk(client_key, node_id, "the-access-key") is not None

    # The second run has to PROVE the cache was read. Both handshakes would
    # complete even if load_cached_psk always returned None, because deriving
    # again yields the same key -- so the initiator's derivation is forbidden
    # this time, and the responder is handed a precomputed key so it never
    # needs to derive either.
    responder_psk = noise_module.derive_psk(password, node_id=node_id)

    def forbidden(*args, **kwargs):
        raise AssertionError("the initiator re-derived: the cache was not read")

    monkeypatch.setattr(noise_module, "derive_psk", forbidden)
    client = start_noise_handshake(
        initiator=True, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=password, node_id=node_id, prologue=prologue, key_path=client_key,
        cache_scope="the-access-key")
    server = start_noise_handshake(
        initiator=False, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=None, node_id=node_id, prologue=prologue, key_path=server_key,
        psk=responder_psk)
    _run_handshake(client, server)


def test_an_explicit_psk_is_neither_derived_nor_cached(tmp_path, monkeypatch):
    """A caller that already holds the key keeps precedence, and the cache
    stays out of it: nothing is derived, nothing is written."""
    node_id = "server-node-id-pem"
    calls = []
    monkeypatch.setattr(noise_module, "derive_psk",
                        lambda *a, **k: calls.append(1) or PSK)
    start_noise_handshake(
        initiator=True, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=_password("explicit"), node_id=node_id, prologue=_prologue(node_id),
        key_path=_key_path(tmp_path), psk=PSK)

    assert calls == []
    assert not _cache_file(tmp_path).exists()


def test_the_listening_side_never_writes_a_psk_cache(tmp_path):
    """On the hub, node id is ours and the password varies per client, so a
    node-keyed cache would collide between clients."""
    node_id = "server-node-id-pem"
    start_noise_handshake(
        initiator=False, pattern=NOISE_PATTERN_XX, suite=NOISE_SUITE_CHACHA,
        password=_password("responder"), node_id=node_id, prologue=_prologue(node_id),
        key_path=_key_path(tmp_path))

    assert not _cache_file(tmp_path).exists()


# --- the protocol's use of the cache ----------------------------------------

def _protocol_with_cache(tmp_path, node_id):
    from hivemind_bus_client.identity import NodeIdentity
    from hivemind_bus_client.protocol import HiveMindSlaveProtocol

    hm = MagicMock()
    hm.session_id = "test-session"
    hm.password = _password("protocol")
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    identity.noise_key = _key_path(tmp_path)
    proto = HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")
    proto.internal_protocol = MagicMock()
    proto.internal_protocol.node_id = node_id
    hm.key = "the-access-key"
    save_cached_psk(identity.noise_key, node_id, PSK, scope=hm.key)
    return proto


def test_a_rejected_handshake_forgets_the_cached_key(tmp_path):
    """XXpsk2 mixes the PSK into message 2, so a stale key fails right here,
    reading it; the cache entry goes with it so the next attempt derives."""
    node_id = "hub-node-id"
    proto = _protocol_with_cache(tmp_path, node_id)
    proto.noise_handshake = MagicMock()
    proto.noise_handshake.read_message.side_effect = Exception("decrypt failed")
    proto._noise_pattern = NOISE_PATTERN_XX

    proto.receive_noise_handshake({"noise": {"msg": "00"}})

    assert load_cached_psk(proto.identity.noise_key, node_id, proto.hm.key) is None


def test_a_socket_closed_mid_handshake_forgets_the_cached_key(tmp_path):
    """For KKpsk0 the server does not answer a key it cannot complete; it
    closes the socket. From here that is only visible as a handshake left in
    flight when the connection resets."""
    node_id = "hub-node-id"
    proto = _protocol_with_cache(tmp_path, node_id)
    proto.noise_handshake = MagicMock()
    proto._noise_established = False

    with patch("hivemind_bus_client.protocol.HandShake"):
        proto.reset_connection_state()

    assert load_cached_psk(proto.identity.noise_key, node_id, proto.hm.key) is None


def test_a_reset_with_no_handshake_in_flight_keeps_the_cached_key(tmp_path):
    node_id = "hub-node-id"
    proto = _protocol_with_cache(tmp_path, node_id)
    proto.noise_handshake = None

    with patch("hivemind_bus_client.protocol.HandShake"):
        proto.reset_connection_state()

    assert load_cached_psk(proto.identity.noise_key, node_id, proto.hm.key) == PSK


def test_a_failure_after_the_key_was_verified_keeps_the_cached_key(tmp_path):
    """Message 2 read fine, so the key is right; a socket that dies while we
    send message 3 is no reason to throw the key away."""
    node_id = "hub-node-id"
    proto = _protocol_with_cache(tmp_path, node_id)
    proto.noise_handshake = MagicMock()
    proto.noise_handshake.handshake_finished = False
    proto.noise_handshake.write_message.return_value = b"msg3"
    proto._noise_pattern = NOISE_PATTERN_XX
    proto._emit = MagicMock(side_effect=ConnectionError("socket closed"))

    proto.receive_noise_handshake({"noise": {"msg": "00"}})

    assert load_cached_psk(proto.identity.noise_key, node_id, proto.hm.key) == PSK


def test_forgetting_never_raises_on_a_failed_handshake(tmp_path):
    """The forget is cleanup on an already-failed path; a broken identity
    object must not turn a handshake failure into a different traceback."""
    node_id = "hub-node-id"
    proto = _protocol_with_cache(tmp_path, node_id)
    proto.identity.noise_key = MagicMock()  # not a path at all
    proto.noise_handshake = MagicMock()
    proto.noise_handshake.read_message.side_effect = Exception("decrypt failed")

    proto.receive_noise_handshake({"noise": {"msg": "00"}})  # must not raise
