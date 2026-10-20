"""A node has one identity, and connecting somewhere must not rewrite it.

One keypair, one Noise static key, one set of pinned peer keys, used in both
directions. Credentials are not part of that: they say how to reach one
particular master, and a node that both serves clients and connects upstream
holds its own access key and password as well as its master's.

Copying the master's credentials onto the identity overwrote the node's own —
and the first Noise handshake persists the file, because pinning a peer key
saves it. Every downstream client then failed against credentials the node no
longer had.
"""
from unittest.mock import patch

import pytest
from json_database import JsonStorageXDG

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity


@pytest.fixture
def node_identity(tmp_path):
    """An identity as a node holds it: its own credentials and its own name."""
    store = JsonStorageXDG("_identity", subfolder="hivemind")
    store.path = str(tmp_path / "_identity.json")
    identity = NodeIdentity(identity_file=store)
    identity.name = "kitchen-node"
    identity.access_key = "node-own-access-key"
    identity.password = "node-own-password"
    identity.default_master = "ws://127.0.0.1"
    identity.default_port = 5678
    identity.site_id = "kitchen"
    identity.create_keys()
    identity.save()
    return identity


def _client(identity, **kwargs):
    with patch.object(HiveMessageBusClient, "connect"):
        return HiveMessageBusClient(identity=identity, **kwargs)


def test_upstream_credentials_do_not_replace_the_nodes_own(node_identity):
    _client(node_identity, key="master-issued-key", password="master-issued-password",
            host="ws://10.0.0.1", port=5680)

    assert node_identity.access_key == "node-own-access-key"
    assert node_identity.password == "node-own-password"


def test_the_node_keeps_its_name(node_identity):
    """The default useragent would otherwise rename the node to
    'HiveMessageBusClientV0.0.1' — the name its own clients know it by."""
    _client(node_identity, key="k", password="p", host="ws://10.0.0.1")

    assert node_identity.name == "kitchen-node"


def test_the_node_keeps_its_own_master_and_port(node_identity):
    _client(node_identity, key="k", password="p", host="ws://10.0.0.1", port=5680)

    assert node_identity.default_master == "ws://127.0.0.1"
    assert node_identity.default_port == 5678


def test_the_client_still_uses_the_credentials_it_was_given(node_identity):
    client = _client(node_identity, key="master-issued-key",
                     password="master-issued-password", host="ws://10.0.0.1")

    assert client.key == "master-issued-key"
    assert client.password == "master-issued-password"


def test_credentials_still_fall_back_to_the_identity(node_identity):
    """A CLI client legitimately keeps its credentials in its identity file."""
    client = _client(node_identity)

    assert client.key == "node-own-access-key"
    assert client.password == "node-own-password"


def test_the_keypair_is_shared_by_both_directions(node_identity):
    """One identity means the node presents the same public key whether it is
    answering a client or dialling its master."""
    declared = node_identity.public_key
    client = _client(node_identity, key="k", password="p", host="ws://10.0.0.1")

    assert client.identity.public_key == declared
    assert client.identity.private_key == node_identity.private_key


def test_a_site_set_on_the_client_is_what_gets_reported(node_identity):
    """`client.site_id = x` before connect must reach the protocol, and must
    not be silently replaced by whatever the identity file happens to say."""
    from unittest.mock import MagicMock, patch as _patch

    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    client.identity = node_identity
    client._site_id = "living-room"
    client.share_bus = False
    client.protocol = None

    captured = {}

    class _Protocol:
        def __init__(self, hm, **kwargs):
            captured.update(kwargs)

        def bind(self, bus):
            pass

    with _patch("hivemind_bus_client.protocol.HiveMindSlaveProtocol", _Protocol), \
            _patch.object(HiveMessageBusClient, "run_in_thread"), \
            _patch.object(HiveMessageBusClient, "wait_for_handshake"):
        client.connect(MagicMock())

    assert captured["site_id"] == "living-room"


def _connect_capturing_site(client_cls, node_identity, preset, passed):
    """Drive `connect()` on any of the three clients and report what the
    protocol was told, plus what the identity looks like afterwards.

    The three clients are separate implementations of the same contract, so
    each one needs its own pin: the first version of this fix corrected the
    websocket client alone and left the other two writing to the identity.
    """
    import asyncio
    import inspect
    from unittest.mock import MagicMock

    client = client_cls.__new__(client_cls)
    client.identity = node_identity
    client._site_id = preset
    client.share_bus = False
    client.protocol = None
    # A closed local port, so the socket attempt that follows the site
    # decision is refused immediately instead of hanging on an unroutable
    # address.
    client._host = "ws://127.0.0.1"
    client._port = 1
    client._access_key = "k"
    client._password = "p"
    client._name = "node"

    class _Protocol:
        """Passed in via connect(protocol=...), so no patching is needed and
        the site decision is observed exactly where the client makes it."""
        site_id = None
        identity = None

        def bind(self, bus):
            pass

    stub = _Protocol()
    # Both clients open a real socket past the point we care about, and the
    # site decision is already made by then.
    try:
        result = client.connect(MagicMock(), protocol=stub, site_id=passed)
        if inspect.iscoroutine(result):
            # The async client's connect is a coroutine; calling it without
            # awaiting would run none of this and pass vacuously.
            asyncio.run(asyncio.wait_for(result, timeout=5))
    except Exception:
        pass
    return stub.site_id, node_identity.site_id


@pytest.mark.parametrize("client_name", ["http", "async"])
def test_no_client_writes_the_site_back_onto_the_identity(node_identity, client_name):
    """`site_id` is connection-scoped. Writing it onto the identity rewrites
    the node's own site, and the first Noise pin persists that to disk."""
    if client_name == "http":
        from hivemind_bus_client.http_client import HiveMindHTTPClient as cls
    else:
        from hivemind_bus_client.async_client import AsyncHiveMessageBusClient as cls

    _connect_capturing_site(cls, node_identity, preset=None,
                            passed="somewhere-else")

    assert node_identity.site_id == "kitchen"


@pytest.mark.parametrize("client_name", ["http", "async"])
def test_no_client_ignores_a_site_set_before_connect(node_identity, client_name):
    """`client.site_id = x` before connect must reach the protocol rather than
    being silently replaced by whatever the identity file happens to say."""
    if client_name == "http":
        from hivemind_bus_client.http_client import HiveMindHTTPClient as cls
    else:
        from hivemind_bus_client.async_client import AsyncHiveMessageBusClient as cls

    reported, _ = _connect_capturing_site(cls, node_identity,
                                          preset="living-room", passed=None)

    assert reported == "living-room"


def test_connecting_does_not_rewrite_the_nodes_site(node_identity):
    from unittest.mock import MagicMock, patch as _patch

    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    client.identity = node_identity
    client._site_id = None
    client.share_bus = False
    client.protocol = None

    with _patch("hivemind_bus_client.protocol.HiveMindSlaveProtocol", MagicMock()), \
            _patch.object(HiveMessageBusClient, "run_in_thread"), \
            _patch.object(HiveMessageBusClient, "wait_for_handshake"):
        client.connect(MagicMock(), site_id="somewhere-else")

    assert node_identity.site_id == "kitchen"
