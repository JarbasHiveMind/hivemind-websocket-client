"""A HANDSHAKE request after the session key is set is refused.

``handle_handshake`` started a legacy handshake for any HANDSHAKE request,
also after ``handshake_event`` was set. A peer that can send one frame on the
session then starts a second handshake: the client sends a new HANDSHAKE, and
the envelope that answers it replaces the session key.

#253 drops a cleartext request after the handshake. A request that arrives
encrypted under the session key still reached this path. The protocol must
refuse it on the sync, async and HTTP clients.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from hivemind_bus_client.encryption import (SupportedCiphers, SupportedEncodings,
                                            encrypt_as_json)
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol

from tests.test_client import _make_client
from tests.test_async_client import _bare_client
from tests.test_http_client_noise_transport import _client as _http_client

KEY = "a" * 32
REQUEST = {"password": True, "binarize": False,
           "encodings": [SupportedEncodings.JSON_HEX],
           "ciphers": [SupportedCiphers.AES_GCM]}


def _sync():
    return _make_client(crypto_key=KEY, password="upright collar icefall")


def _async():
    c = _bare_client()
    c.crypto_key = KEY
    c._password = "upright collar icefall"
    return c


def _http():
    c = _http_client()
    c.crypto_key = KEY
    c._password = "upright collar icefall"
    return c


def _wire(client, done):
    """Attach a real protocol to *client* and set the handshake state."""
    proto = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
    proto.hm = client
    proto.identity = MagicMock(public_key="PUB")
    proto.site_id = "site"
    proto.binarize = False
    proto.mpubkey = ""
    proto.noise_handshake = None
    proto._noise_established = False
    proto._server_handshake_payload = None
    proto._legacy_handshake_started = False
    proto.handshake = MagicMock(pubkey="CLIENTPUB", secret=None)
    proto.pswd_handshake = None
    proto._emit = MagicMock()
    proto._should_use_noise = MagicMock(return_value=False)
    client.protocol = proto
    client.cipher = SupportedCiphers.AES_GCM
    client.json_encoding = SupportedEncodings.JSON_HEX
    client._handle_hive_protocol = proto.handle_handshake
    if done:
        if isinstance(client.handshake_event, MagicMock):
            client.handshake_event.is_set.return_value = True
        else:
            client.handshake_event.set()
    return proto


CLIENTS = pytest.mark.parametrize("make", [_sync, _async, _http],
                                  ids=["sync", "async", "http"])


def _encrypted_request():
    inner = json.dumps({"msg_type": HiveMessageType.HANDSHAKE, "payload": REQUEST})
    return encrypt_as_json(KEY, inner, cipher=SupportedCiphers.AES_GCM,
                           encoding=SupportedEncodings.JSON_HEX)


@CLIENTS
def test_an_encrypted_request_after_the_key_is_refused(make):
    client = make()
    proto = _wire(client, done=True)
    with patch("hivemind_bus_client.protocol.LOG") as log:
        client.on_message(_encrypted_request())
    proto._emit.assert_not_called()
    assert proto.pswd_handshake is None
    assert not proto._legacy_handshake_started
    assert client.crypto_key == KEY
    assert log.error.called


@CLIENTS
def test_a_request_before_the_handshake_still_starts_one(make):
    client = make()
    proto = _wire(client, done=False)
    proto.handle_handshake(HiveMessage(HiveMessageType.HANDSHAKE, dict(REQUEST)))
    sent = proto._emit.call_args[0][0]
    assert sent.msg_type == HiveMessageType.HANDSHAKE
    assert proto._legacy_handshake_started
