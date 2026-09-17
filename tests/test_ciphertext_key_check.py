"""A keyed legacy session tests the parsed frame for a "ciphertext" key.

The clients tested ``"ciphertext" in message`` while ``message`` was still the
raw JSON text. A cleartext frame that only has the word "ciphertext" in a
value, for example ``{"msg_type": "bus", "x": "ciphertext"}``, then went to
``decrypt_from_json`` and raised (sync KeyError, async InvalidCipher, HTTP
AttributeError) before ``unencrypted_frame_allowed`` was consulted.

Each client must parse the frame first and then check for the key. A frame
that does not parse to a JSON object, or that is cleartext on a keyed session,
is dropped with an ERROR line, and nothing raises.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from hivemind_bus_client.encryption import (SupportedCiphers, SupportedEncodings,
                                            encrypt_as_json)
from hivemind_bus_client.message import HiveMessageType

from tests.test_client import _make_client
from tests.test_async_client import _bare_client
from tests.test_http_client_noise_transport import _client as _http_client

KEY = "a" * 32

WORD_IN_VALUE = json.dumps({"msg_type": HiveMessageType.BUS,
                            "x": "ciphertext",
                            "payload": {"type": "x", "data": {}, "context": {}}})
WORD_IN_HELLO = json.dumps({"msg_type": HiveMessageType.HELLO,
                            "payload": {"note": "ciphertext"}})
NOT_AN_OBJECT = json.dumps(["ciphertext"])
NOT_JSON = "ciphertext, but not JSON"


def _sync(done):
    c = _make_client(crypto_key=KEY)
    c._handle_hive_protocol = MagicMock()
    if done:
        c.handshake_event.set()
    return c, "hivemind_bus_client.client.LOG"


def _async(done):
    c = _bare_client()
    c.crypto_key = KEY
    c.handshake_event = MagicMock()
    c.handshake_event.is_set.return_value = done
    c._handle_hive_protocol = MagicMock()
    return c, "hivemind_bus_client.async_client.LOG"


def _http(done):
    c = _http_client()
    c.crypto_key = KEY
    if done:
        c.handshake_event.set()
    return c, "hivemind_bus_client.http_client.LOG"


CLIENTS = pytest.mark.parametrize("make", [_sync, _async, _http],
                                  ids=["sync", "async", "http"])


@CLIENTS
@pytest.mark.parametrize("frame", [WORD_IN_VALUE, NOT_AN_OBJECT, NOT_JSON],
                         ids=["word-in-value", "json-array", "not-json"])
def test_a_frame_without_the_key_is_dropped_not_raised(make, frame):
    client, log_path = make(done=True)
    with patch(log_path) as log:
        client.on_message(frame)
    client._handle_hive_protocol.assert_not_called()
    assert log.error.called


@CLIENTS
def test_a_cleartext_hello_with_the_word_is_accepted_before_the_handshake(make):
    client, _ = make(done=False)
    client.on_message(WORD_IN_HELLO)
    msg = client._handle_hive_protocol.call_args[0][0]
    assert msg.msg_type == HiveMessageType.HELLO


@CLIENTS
def test_a_real_encrypted_frame_still_decrypts(make):
    client, _ = make(done=True)
    client.cipher = SupportedCiphers.AES_GCM
    client.json_encoding = SupportedEncodings.JSON_HEX
    inner = json.dumps({"msg_type": HiveMessageType.BUS,
                        "payload": {"type": "ok", "data": {}, "context": {}}})
    frame = encrypt_as_json(KEY, inner, cipher=client.cipher,
                            encoding=client.json_encoding)
    client.on_message(frame)
    msg = client._handle_hive_protocol.call_args[0][0]
    assert msg.msg_type == HiveMessageType.BUS
