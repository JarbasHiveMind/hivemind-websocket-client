"""A password envelope that fails verification is refused by name.

PasswordHandShake.receive_and_verify returns False for a wrong password or
for this client's own envelope sent back to it. The client ignored that
result and read ``secret``. The key was not set only because ``secret``
raised TypeError on an empty salt. A refusal must not depend on that side
effect: it must check the result and say why the envelope was dropped.
"""
import threading
import warnings
from unittest.mock import MagicMock, patch

from poorman_handshake import PasswordHandShake

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol

RIGHT = "upright collar icefall sixpaned lantern"
WRONG = "copper meadow twilight fennel orbit"


def _handshake(password):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        return PasswordHandShake(password, min_bits=0)


def _protocol():
    proto = HiveMindSlaveProtocol.__new__(HiveMindSlaveProtocol)
    proto.hm = MagicMock()
    proto.hm.crypto_key = None
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
    proto.pswd_handshake = _handshake(RIGHT)
    return proto


def _reply(envelope):
    return HiveMessage(HiveMessageType.HANDSHAKE, {"envelope": envelope})


def _errors(log):
    return " ".join(str(c.args[0]) for c in log.error.call_args_list)


def test_a_wrong_password_envelope_is_refused_by_name():
    proto = _protocol()
    proto._legacy_start_handshake({})
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_reply(_handshake(WRONG).generate_handshake()))
    assert proto.hm.crypto_key is None
    assert not proto.hm.handshake_event.is_set()
    assert "password verification failed" in _errors(log)
    assert "TypeError" not in _errors(log)


def test_the_clients_own_envelope_sent_back_is_refused_by_name():
    proto = _protocol()
    proto._legacy_start_handshake({})
    own = proto._emit.call_args[0][0].payload["envelope"]
    with patch("hivemind_bus_client.protocol.LOG") as log:
        proto.handle_handshake(_reply(own))
    assert proto.hm.crypto_key is None
    assert "password verification failed" in _errors(log)


def test_the_right_password_still_sets_the_key():
    proto = _protocol()
    proto._legacy_start_handshake({})
    server = _handshake(RIGHT)
    proto.handle_handshake(_reply(server.generate_handshake()))
    assert proto.hm.crypto_key == proto.pswd_handshake.secret
    assert proto.hm.crypto_key is not None
