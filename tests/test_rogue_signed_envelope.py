"""A pubkey envelope with a bad signature must not set a session key.

The client pins the hub key in ``mpubkey`` and calls
``HandShake.receive_and_verify``. Before poorman-handshake 2.0.2a1 that call
returned silently on a bad signature. The client then read ``secret`` (all
zero bytes, from ``bytes(32)``), installed it as ``crypto_key`` and set
``handshake_event``. Version 2.0.2a1 raises ``InvalidSignatureError``, and the
client drops the envelope with an ERROR line. The dependency floor must name
that version.
"""
import threading
from unittest.mock import MagicMock, patch

import pytest
from poorman_handshake import HandShake

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol


@pytest.fixture(scope="module")
def keys():
    return {"client": HandShake(), "hub": HandShake(), "rogue": HandShake()}


def _protocol(client_handshake, pinned):
    proto = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
    proto.hm = MagicMock()
    proto.hm.crypto_key = None
    proto.hm.handshake_event = threading.Event()
    proto.hm.session_id = "sess"
    proto.identity = MagicMock(public_key="PUB")
    proto.site_id = "site"
    proto.binarize = False
    proto.mpubkey = pinned
    proto.noise_handshake = None
    proto._noise_established = False
    proto._server_handshake_payload = None
    proto._legacy_handshake_started = True
    proto._emit = MagicMock()
    proto.handshake = client_handshake
    proto.pswd_handshake = None
    return proto


def _reply(envelope):
    return HiveMessage(HiveMessageType.HANDSHAKE, {"envelope": envelope})


def test_a_rogue_signed_envelope_sets_no_key(keys):
    proto = _protocol(keys["client"], keys["hub"].pubkey)
    keys["client"].secret = None
    envelope = keys["rogue"].generate_handshake(keys["client"].pubkey)
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_reply(envelope))
    assert proto.hm.crypto_key is None
    assert not proto.hm.handshake_event.is_set()
    assert log.error.called


def test_a_hub_signed_envelope_sets_the_key(keys):
    proto = _protocol(keys["client"], keys["hub"].pubkey)
    keys["client"].secret = None
    envelope = keys["hub"].generate_handshake(keys["client"].pubkey)
    proto.handle_handshake(_reply(envelope))
    assert proto.hm.crypto_key is not None
    assert proto.hm.crypto_key != bytes(32)
    assert proto.hm.handshake_event.is_set()
