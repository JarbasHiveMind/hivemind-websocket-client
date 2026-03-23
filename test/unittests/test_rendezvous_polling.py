"""Unit tests for HiveMessageBusClient rendezvous polling."""

import json
import time
import urllib.error
from threading import Event
from unittest.mock import MagicMock, patch

import pytest

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_SERVER_PUBKEY = "-----BEGIN PUBLIC KEY-----\nSERVER\n-----END PUBLIC KEY-----"


def _make_client(rendezvous_urls=None, poll_interval=60.0):
    """Build a HiveMessageBusClient with rendezvous attrs, bypassing network init."""
    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    client._rendezvous_urls = list(rendezvous_urls) if rendezvous_urls else []
    client._rendezvous_poll_interval = poll_interval
    client._rendezvous_stop_event = Event()
    client._rendezvous_thread = None
    # Pre-populate server pubkey cache so tests don't need a real GET /pubkey
    client._rendezvous_server_pubkeys = {"http://r1.example.com": _FAKE_SERVER_PUBKEY}
    client.identity = MagicMock()
    client.identity.public_key = "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----"
    client.identity.private_key = "/fake/key.pem"
    return client


def _intercom_serialised() -> str:
    return HiveMessage(HiveMessageType.INTERCOM, {"data": "hello"}).serialize()


def _mock_urlopen_ctx(messages):
    """Return a mock context manager that yields a JSON response with *messages*."""
    body = json.dumps({"status": "ok", "messages": messages}).encode()
    resp = MagicMock()
    resp.read.return_value = body
    ctx = MagicMock()
    ctx.__enter__ = MagicMock(return_value=resp)
    ctx.__exit__ = MagicMock(return_value=False)
    return ctx


# ---------------------------------------------------------------------------
# _start_rendezvous_polling / _stop_rendezvous_polling
# ---------------------------------------------------------------------------

def test_start_polling_spawns_thread():
    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._start_rendezvous_polling()
    assert client._rendezvous_thread is not None
    assert client._rendezvous_thread.is_alive()
    client._stop_rendezvous_polling()


def test_start_polling_no_urls_does_nothing():
    client = _make_client()
    client._start_rendezvous_polling()
    assert client._rendezvous_thread is None


def test_start_polling_idempotent():
    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._start_rendezvous_polling()
    first_thread = client._rendezvous_thread
    client._start_rendezvous_polling()  # second call must be a no-op
    assert client._rendezvous_thread is first_thread
    client._stop_rendezvous_polling()


def test_stop_polling_clears_thread():
    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._start_rendezvous_polling()
    client._stop_rendezvous_polling()
    assert client._rendezvous_thread is None


def test_stop_polling_without_start_is_safe():
    client = _make_client()
    client._stop_rendezvous_polling()  # must not raise


def test_stop_polling_missing_attrs_is_safe():
    """_stop_rendezvous_polling must not raise if attrs are absent (bare __new__ path)."""
    client = HiveMessageBusClient.__new__(HiveMessageBusClient)
    client._stop_rendezvous_polling()  # must not raise


# ---------------------------------------------------------------------------
# _poll_rendezvous — uses lazy `from hivemind_rendezvous.auth import sign_ownership`
# so we patch that module directly.
# ---------------------------------------------------------------------------

_PATCH_URLOPEN = "hivemind_bus_client.client.urllib.request.urlopen"
_PATCH_LOAD = "hivemind_bus_client.client.load_RSA_key"
_PATCH_SIGN = "hivemind_rendezvous.auth.sign_ownership"


@patch(_PATCH_URLOPEN)
@patch(_PATCH_LOAD)
def test_poll_retrieves_and_injects(mock_load_key, mock_urlopen):
    mock_load_key.return_value = MagicMock()
    mock_urlopen.return_value = _mock_urlopen_ctx([_intercom_serialised()])

    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._handle_hive_protocol = MagicMock()

    with patch(_PATCH_SIGN, return_value="fakesig"):
        client._poll_rendezvous("http://r1.example.com")

    client._handle_hive_protocol.assert_called_once()
    injected: HiveMessage = client._handle_hive_protocol.call_args[0][0]
    assert injected.msg_type == HiveMessageType.INTERCOM


@patch(_PATCH_URLOPEN)
@patch(_PATCH_LOAD)
def test_poll_empty_messages_no_inject(mock_load_key, mock_urlopen):
    mock_load_key.return_value = MagicMock()
    mock_urlopen.return_value = _mock_urlopen_ctx([])

    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._handle_hive_protocol = MagicMock()

    with patch(_PATCH_SIGN, return_value="fakesig"):
        client._poll_rendezvous("http://r1.example.com")

    client._handle_hive_protocol.assert_not_called()


@patch(_PATCH_URLOPEN)
@patch(_PATCH_LOAD)
def test_poll_http_error_logged_not_raised(mock_load_key, mock_urlopen):
    mock_load_key.return_value = MagicMock()
    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="http://r1.example.com/retrieve", code=401,
        msg="Unauthorized", hdrs=None, fp=None,
    )

    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._handle_hive_protocol = MagicMock()

    with patch(_PATCH_SIGN, return_value="fakesig"):
        client._poll_rendezvous("http://r1.example.com")  # must not raise

    client._handle_hive_protocol.assert_not_called()


@patch(_PATCH_URLOPEN)
@patch(_PATCH_LOAD)
def test_poll_connection_error_logged_not_raised(mock_load_key, mock_urlopen):
    mock_load_key.return_value = MagicMock()
    mock_urlopen.side_effect = OSError("connection refused")

    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._handle_hive_protocol = MagicMock()

    with patch(_PATCH_SIGN, return_value="fakesig"):
        client._poll_rendezvous("http://r1.example.com")  # must not raise

    client._handle_hive_protocol.assert_not_called()


@patch(_PATCH_URLOPEN)
@patch(_PATCH_LOAD)
def test_poll_multiple_messages_all_injected(mock_load_key, mock_urlopen):
    mock_load_key.return_value = MagicMock()
    payloads = [_intercom_serialised(), _intercom_serialised()]
    mock_urlopen.return_value = _mock_urlopen_ctx(payloads)

    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._handle_hive_protocol = MagicMock()

    with patch(_PATCH_SIGN, return_value="fakesig"):
        client._poll_rendezvous("http://r1.example.com")

    assert client._handle_hive_protocol.call_count == 2


# ---------------------------------------------------------------------------
# _rendezvous_poll_loop — stop event integration
# ---------------------------------------------------------------------------

def test_poll_loop_stops_on_event():
    """The poll loop must exit promptly when the stop event is set."""
    client = _make_client(rendezvous_urls=["http://r1.example.com"])
    client._poll_rendezvous = MagicMock()
    client._rendezvous_poll_interval = 0.1

    client._start_rendezvous_polling()
    time.sleep(0.25)
    client._stop_rendezvous_polling()

    assert client._rendezvous_thread is None
