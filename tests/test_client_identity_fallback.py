"""A client built without ``identity=`` presents the shared identity, and says so.

HIVEMIND-CRYPTO-1 §2: two applications of one user MUST NOT present the same
identifier or the same static key pair. The sync client, the async client,
the HTTP client and the slave protocol each fell back to ``NodeIdentity()``,
the shared ``~/.config/hivemind/_identity.json``, silently. The fallback
stays (ruling A: the default moves after the consumers), and every site now
logs one WARNING that names §2 and ``identity=NodeIdentity(app_name=...)``.
A client that is given an identity logs nothing.
"""
from unittest.mock import MagicMock, patch

import pytest

from hivemind_bus_client.identity import NodeIdentity

CREDS = {"key": "sat-key", "password": "correct-horse-battery-staple-92",
         "host": "ws://hub", "port": 5678}


def _own_identity():
    identity = MagicMock(spec=NodeIdentity)
    identity.password = CREDS["password"]
    identity.access_key = CREDS["key"]
    identity.default_master = CREDS["host"]
    identity.default_port = CREDS["port"]
    identity.site_id = "site"
    return identity


def test_the_helper_warns_with_the_clause_and_the_fix_and_returns_the_shared_identity():
    from hivemind_bus_client.identity import shared_identity_for
    with patch("hivemind_bus_client.identity.LOG.warning") as warning, \
         patch("hivemind_bus_client.identity.NodeIdentity") as ctor:
        result = shared_identity_for("HiveMessageBusClient")
    assert result is ctor.return_value
    ctor.assert_called_once_with()
    message = warning.call_args.args[0]
    assert "HiveMessageBusClient" in message
    assert "HIVEMIND-CRYPTO-1 §2" in message
    assert 'identity=NodeIdentity(app_name="<your-app>")' in message


def _sync(identity=None):
    from hivemind_bus_client.client import HiveMessageBusClient
    with patch.object(HiveMessageBusClient, "connect", return_value=None):
        return HiveMessageBusClient(identity=identity, **CREDS)


def _async(identity=None):
    from hivemind_bus_client.async_client import AsyncHiveMessageBusClient
    return AsyncHiveMessageBusClient(identity=identity, **CREDS)


def _http(identity=None):
    from hivemind_bus_client.http_client import HiveMindHTTPClient
    return HiveMindHTTPClient(identity=identity, **CREDS)


def _protocol(identity=None):
    from hivemind_bus_client.protocol import HiveMindSlaveProtocol
    hm = MagicMock()
    hm.identity = identity
    protocol = HiveMindSlaveProtocol(hm=hm)
    with patch("hivemind_bus_client.protocol.HandShake"):
        protocol.bind(bus=MagicMock())
    return protocol


@pytest.mark.parametrize("build", [_sync, _async, _http, _protocol],
                         ids=["sync", "async", "http", "protocol"])
def test_without_an_identity_each_client_warns_once_and_uses_the_shared_one(build):
    shared = _own_identity()
    with patch("hivemind_bus_client.identity.LOG.warning") as warning, \
         patch("hivemind_bus_client.identity.NodeIdentity", return_value=shared):
        client = build()
    assert client.identity is shared
    assert warning.call_count == 1
    assert "HIVEMIND-CRYPTO-1 §2" in warning.call_args.args[0]


@pytest.mark.parametrize("build", [_sync, _async, _http, _protocol],
                         ids=["sync", "async", "http", "protocol"])
def test_with_an_identity_each_client_keeps_it_and_logs_nothing(build):
    own = _own_identity()
    with patch("hivemind_bus_client.identity.LOG.warning") as warning, \
         patch("hivemind_bus_client.identity.NodeIdentity") as ctor:
        client = build(own)
    assert client.identity is own
    ctor.assert_not_called()
    warning.assert_not_called()
