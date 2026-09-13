"""HIVEMIND-CRYPTO-1 §3.5: no cleartext after the key exists.

A legacy (pre-Noise) session keys every message with ``crypto_key`` once the
handshake completes. Before this fix, all three clients logged
"Message was unencrypted" at DEBUG and then dispatched the frame, so any party
that can put a frame on the connection could deliver a plaintext message to
the application.

A legacy hub still sends HELLO and HANDSHAKE in cleartext before the handshake
completes, even when a key is already set (hivemind-core before the Noise-only
change: ``send`` encrypts every type except those two). So a cleartext frame is
accepted only when it is HELLO or HANDSHAKE and the handshake is not complete.
Everything else is dropped and logged at ERROR.
"""
import json
from threading import Event
from unittest.mock import MagicMock, patch

from hivemind_bus_client.message import HiveMessageType

from tests.test_client import _make_client
from tests.test_async_client import _bare_client
from tests.test_http_client_noise_transport import _client as _http_client

KEY = "a" * 32


def _wire(msg_type, payload=None):
    return json.dumps({"msg_type": msg_type, "payload": payload or {}})


def _bus_frame():
    return _wire(HiveMessageType.BUS,
                 {"type": "injected.plaintext", "data": {}, "context": {}})


# --- sync websocket client ---------------------------------------------------

def _sync(handshake_done):
    client = _make_client(crypto_key=KEY)
    client._handle_hive_protocol = MagicMock()
    if handshake_done:
        client.handshake_event.set()
    return client


def test_sync_plaintext_bus_frame_after_the_handshake_is_dropped():
    client = _sync(handshake_done=True)
    with patch("hivemind_bus_client.client.LOG") as log:
        client.on_message(_bus_frame())
    client._handle_hive_protocol.assert_not_called()
    assert log.error.called


def test_sync_plaintext_handshake_after_the_handshake_is_dropped():
    client = _sync(handshake_done=True)
    client.on_message(_wire(HiveMessageType.HANDSHAKE, {"envelope": "00" * 24}))
    client._handle_hive_protocol.assert_not_called()


def test_sync_plaintext_hello_before_the_handshake_is_still_accepted():
    client = _sync(handshake_done=False)
    client.on_message(_wire(HiveMessageType.HELLO, {"node_id": "hub"}))
    dispatched = client._handle_hive_protocol.call_args[0][0]
    assert dispatched.msg_type == HiveMessageType.HELLO


def test_sync_plaintext_bus_frame_before_the_handshake_is_dropped():
    client = _sync(handshake_done=False)
    client.on_message(_bus_frame())
    client._handle_hive_protocol.assert_not_called()


def test_sync_without_a_key_plaintext_is_unchanged():
    client = _make_client()
    client._handle_hive_protocol = MagicMock()
    client.on_message(_bus_frame())
    client._handle_hive_protocol.assert_called_once()


# --- async websocket client --------------------------------------------------

def _async(handshake_done):
    bus = _bare_client()
    bus.crypto_key = KEY
    bus.handshake_event = MagicMock()
    bus.handshake_event.is_set.return_value = handshake_done
    bus._handle_hive_protocol = MagicMock()
    return bus


def test_async_plaintext_bus_frame_after_the_handshake_is_dropped():
    bus = _async(handshake_done=True)
    bus.on_message(_bus_frame())
    bus._handle_hive_protocol.assert_not_called()


def test_async_plaintext_hello_before_the_handshake_is_still_accepted():
    bus = _async(handshake_done=False)
    bus.on_message(_wire(HiveMessageType.HELLO, {"node_id": "hub"}))
    assert bus._handle_hive_protocol.call_args[0][0].msg_type == HiveMessageType.HELLO


# --- HTTP client ---------------------------------------------------------------

def _http(handshake_done):
    c = _http_client()
    c.crypto_key = KEY
    if handshake_done:
        c.handshake_event.set()
    return c


def test_http_plaintext_bus_frame_after_the_handshake_is_dropped():
    c = _http(handshake_done=True)
    c.on_message(_bus_frame())
    c._handle_hive_protocol.assert_not_called()


def test_http_plaintext_hello_before_the_handshake_is_still_accepted():
    c = _http(handshake_done=False)
    c.on_message(_wire(HiveMessageType.HELLO, {"node_id": "hub"}))
    assert c._handle_hive_protocol.call_args[0][0].msg_type == HiveMessageType.HELLO
