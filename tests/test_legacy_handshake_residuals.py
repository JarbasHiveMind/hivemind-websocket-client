"""Legacy (pre-Noise) handshake: an envelope may only answer this client's HANDSHAKE.

Two holes a security review found in the legacy receive path, both before
this change:

1. A client holding a pre-shared crypto_key that never sent its own HANDSHAKE
   accepted a cleartext HANDSHAKE envelope and replaced its key. Anyone who can
   write on the socket before the handshake (the hub, or an active man in the
   middle on ws://) could install a key of their own choosing.
2. A malformed envelope raised out of handle_handshake (for example
   ValueError: Ciphertext with incorrect length), which drops the connection
   from inside the websocket library's thread.
"""
import threading
from unittest.mock import MagicMock, patch

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol

PRESHARED = "a" * 32


def _protocol(crypto_key=None, password=False):
    proto = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
    proto.hm = MagicMock()
    proto.hm.crypto_key = crypto_key
    proto.hm.handshake_event = threading.Event()
    proto.hm.session_id = "sess"
    proto.identity = MagicMock(public_key="PUB")
    proto.site_id = "site"
    proto.binarize = False
    proto.mpubkey = ""
    proto.noise_handshake = None
    proto._noise_established = False
    proto._server_handshake_payload = None
    proto._emit = MagicMock()
    proto.handshake = MagicMock(pubkey="CLIENTPUB", secret=None)
    proto.pswd_handshake = MagicMock(secret=b"derived-from-password") if password else None
    return proto


def _envelope(value="ab" * 32):
    return HiveMessage(HiveMessageType.HANDSHAKE, {"envelope": value})


def test_a_preshared_key_is_not_replaced_by_an_envelope_the_client_did_not_ask_for():
    proto = _protocol(crypto_key=PRESHARED)
    proto.handshake.secret = b"attacker-chosen-key"
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_envelope())
    assert proto.hm.crypto_key == PRESHARED
    assert not proto.hm.handshake_event.is_set()
    assert log.error.called


def test_an_envelope_that_answers_this_clients_handshake_still_sets_the_key():
    proto = _protocol(crypto_key=PRESHARED, password=True)
    proto._legacy_start_handshake({})          # this client sends its HANDSHAKE first
    proto.handle_handshake(_envelope())
    assert proto.hm.crypto_key == b"derived-from-password"
    assert proto.hm.handshake_event.is_set()


def test_a_client_without_a_key_still_completes_a_pubkey_handshake():
    proto = _protocol(crypto_key=None)
    proto.handshake.secret = b"k" * 32
    proto.handle_handshake(_envelope())
    assert proto.hm.crypto_key == b"k" * 32
    assert proto.hm.handshake_event.is_set()


def test_a_malformed_envelope_is_dropped_instead_of_raising():
    proto = _protocol(crypto_key=None, password=True)
    proto._legacy_start_handshake({})
    proto.pswd_handshake.receive_and_verify.side_effect = ValueError("Ciphertext with incorrect length.")
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_envelope("00" * 32))   # must not raise
    assert proto.hm.crypto_key is None
    assert not proto.hm.handshake_event.is_set()
    assert log.error.called
    # the ERROR line names the exception type only, not the envelope
    assert "00" * 32 not in str(log.error.call_args)


def test_the_timed_retry_does_not_open_the_window_for_an_envelope():
    # wait_for_handshake calls start_handshake after 5 s without an answer;
    # a peer that holds its envelope back past that retry must still be refused
    proto = _protocol(crypto_key=PRESHARED)
    proto.handshake.secret = b"attacker-chosen-key"
    proto.start_handshake()
    assert proto._emit.called                  # the retry still resends HANDSHAKE
    proto.handle_handshake(_envelope())
    assert proto.hm.crypto_key == PRESHARED
    assert not proto.hm.handshake_event.is_set()


def test_a_second_envelope_does_not_replace_the_key_of_a_completed_handshake():
    proto = _protocol(crypto_key=None, password=True)
    proto._legacy_start_handshake({})
    proto.handle_handshake(_envelope())
    assert proto.hm.crypto_key == b"derived-from-password"
    proto.pswd_handshake.secret = b"attacker-chosen-key"
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_envelope())
    assert proto.hm.crypto_key == b"derived-from-password"
    assert log.error.called


def test_the_handshake_payload_is_not_written_to_the_log():
    proto = _protocol(crypto_key=None, password=True)
    proto._legacy_start_handshake({})
    marker = "cd" * 50_000
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_envelope(marker))
    lines = [str(c) for m in (log.info, log.debug, log.error, log.warning)
             for c in m.call_args_list]
    assert lines
    assert not any(marker[:64] in line for line in lines)
    assert max(len(line) for line in lines) < 500


def test_a_malformed_pubkey_envelope_is_dropped_instead_of_raising():
    proto = _protocol(crypto_key=None)
    proto.handshake.receive_handshake.side_effect = ValueError("Ciphertext with incorrect length.")
    proto.handle_handshake(_envelope("00" * 32))       # must not raise
    assert proto.hm.crypto_key is None
    assert not proto.hm.handshake_event.is_set()
