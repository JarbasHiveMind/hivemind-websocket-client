"""A repeated HANDSHAKE offer must not abort an in-flight Noise handshake.

Dispatching on the presence of a "noise" key alone sent the server's OFFER
(noise.patterns/noise.suites) to receive_noise_handshake(), which reads
payload["noise"]["msg"] -- KeyError -> "malformed Noise envelope" -> the
handshake is aborted and the genuine reply arriving right behind it is
discarded.

Transports may legitimately redeliver the offer. hivemind-http-protocol
queues messages per access key and re-sends HELLO + offer from
handle_new_client() whenever /connect finds no cached connection for that
key, so a failed attempt leaves an offer queued for the next one and the
failure becomes permanent.
"""

from unittest.mock import MagicMock

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol

OFFER = {"max_protocol_version": 3, "binarize": False,
         "noise": {"patterns": ["XXpsk2"], "suites": ["25519_ChaChaPoly_SHA256"]}}
REPLY = {"noise": {"msg": "ab12cd34"}}


def _protocol():
    proto = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
    proto.receive_noise_handshake = MagicMock()
    proto.start_noise_handshake = MagicMock()
    proto._should_use_noise = MagicMock(return_value=True)
    proto.noise_handshake = None
    proto._server_handshake_payload = None
    return proto


def _msg(payload):
    return HiveMessage(HiveMessageType.HANDSHAKE, payload)


def test_the_offer_starts_the_handshake_when_nothing_is_in_flight():
    proto = _protocol()
    proto.handle_handshake(_msg(OFFER))
    proto.start_noise_handshake.assert_called_once()
    proto.receive_noise_handshake.assert_not_called()


def test_a_repeated_offer_mid_handshake_is_ignored():
    proto = _protocol()
    proto.noise_handshake = object()
    proto.handle_handshake(_msg(OFFER))
    # not mistaken for the reply, and not restarted either
    proto.receive_noise_handshake.assert_not_called()
    proto.start_noise_handshake.assert_not_called()


def test_the_genuine_noise_reply_is_still_delivered():
    proto = _protocol()
    proto.noise_handshake = object()
    proto.handle_handshake(_msg(REPLY))
    proto.receive_noise_handshake.assert_called_once_with(REPLY)


def test_a_reply_arriving_after_a_repeated_offer_still_gets_through():
    """The exact live sequence: offer, duplicate offer, then the real reply."""
    proto = _protocol()
    proto.handle_handshake(_msg(OFFER))
    proto.noise_handshake = object()          # handshake now in flight
    proto.handle_handshake(_msg(OFFER))       # duplicate -> must be dropped
    proto.handle_handshake(_msg(REPLY))       # real reply -> must land
    proto.receive_noise_handshake.assert_called_once_with(REPLY)


def test_a_handshake_frame_after_the_session_is_established_is_ignored():
    """A stray HANDSHAKE retry from the peer must not restart a live session."""
    proto = _protocol()
    proto._noise_established = True
    proto.handle_handshake(_msg(OFFER))
    proto.receive_noise_handshake.assert_not_called()
    proto.start_noise_handshake.assert_not_called()
    # the established flag itself is untouched by the stray frame
    assert proto._noise_established is True


def test_established_guard_and_in_flight_offer_guard_are_both_applied():
    """Neither guard subsumes the other: established wins first, then the
    msg-less repeated offer is dropped while a handshake is in flight, and
    only the genuine reply is ever handed to receive_noise_handshake."""
    proto = _protocol()

    # not established yet, no handshake in flight: the offer starts one
    proto.handle_handshake(_msg(OFFER))
    proto.start_noise_handshake.assert_called_once()

    # handshake now in flight: a repeated msg-less offer is dropped, the
    # in-flight handshake object is left untouched
    proto.noise_handshake = in_flight = object()
    proto.handle_handshake(_msg(OFFER))
    proto.receive_noise_handshake.assert_not_called()
    assert proto.noise_handshake is in_flight

    # the genuine reply completes the in-flight handshake
    proto.handle_handshake(_msg(REPLY))
    proto.receive_noise_handshake.assert_called_once_with(REPLY)

    # session now established: a further stray HANDSHAKE frame is ignored
    proto.receive_noise_handshake.reset_mock()
    proto._noise_established = True
    proto.handle_handshake(_msg(OFFER))
    proto.receive_noise_handshake.assert_not_called()
    assert proto._noise_established is True
