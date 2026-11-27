"""Residuals from the review of #250.

1. A client that refuses the server for a pinned-key mismatch must stop and
   name ``hivemind-client forget-server``. It used to reconnect every few
   seconds forever and log the same refusal each time.
2. ``close()`` after a good KKpsk0 session must not log "KKpsk0 failed".
   ``close()`` and the socket close callback both reset the connection state,
   on two threads. The second reset could see the established flag cleared
   while the KKpsk0 pattern was still set.
"""
import asyncio
from unittest.mock import MagicMock, patch

from hivemind_bus_client.async_client import AsyncHiveMessageBusClient
from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.protocol import HiveMindSlaveProtocol


def _protocol() -> HiveMindSlaveProtocol:
    hm = MagicMock()
    hm.session_id = "test-session"
    hm.password = "test-node-horse-battery-staple-92"
    hm.config.host = "hive.example"
    hm.config.port = 5678
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    return HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")


def _mismatch(proto: HiveMindSlaveProtocol) -> None:
    proto.identity.get_pinned_noise_key.return_value = b"pinned-key"
    proto._noise_pattern = "XXpsk2"
    proto.noise_handshake = MagicMock()
    proto.noise_handshake.read_message.return_value = b""
    proto.noise_handshake.handshake_finished = True
    with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
        transport_cls.return_value.remote_static_key = b"other-key"
        proto.receive_noise_handshake({"noise": {"msg": (b"x" * 16).hex()}})


class TestPinMismatchStopsTheClient:
    def test_the_protocol_latches_a_refusal_that_names_forget_server(self):
        proto = _protocol()
        _mismatch(proto)
        proto.hm.latch_refusal.assert_called_once()
        reason = proto.hm.latch_refusal.call_args.args[0]
        assert "hivemind-client forget-server" in reason
        proto.identity.pin_noise_key.assert_not_called()
        proto.identity.forget_noise_key.assert_not_called()

    def test_a_good_key_latches_nothing(self):
        proto = _protocol()
        proto.identity.get_pinned_noise_key.return_value = b"pinned-key"
        proto._noise_pattern = "XXpsk2"
        proto._emit = MagicMock()
        proto.noise_handshake = MagicMock()
        proto.noise_handshake.read_message.return_value = b""
        proto.noise_handshake.handshake_finished = True
        with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
            transport_cls.return_value.remote_static_key = b"pinned-key"
            proto.receive_noise_handshake({"noise": {"msg": (b"x" * 16).hex()}})
        proto.hm.latch_refusal.assert_not_called()

    def test_the_sync_client_stops_reconnecting(self):
        node = object.__new__(HiveMessageBusClient)
        node._auth_rejected = None
        node.emitter = MagicMock()
        node.close = MagicMock()
        node.latch_refusal("key mismatch, run 'hivemind-client forget-server'")
        assert "forget-server" in node._auth_rejected
        node.close.assert_called_once()
        node.emitter.emit.assert_called_once_with(
            "auth_rejected", node._auth_rejected)

    def test_the_async_client_wakes_wait_for_handshake(self):
        bus = AsyncHiveMessageBusClient.__new__(AsyncHiveMessageBusClient)
        bus._auth_rejected = None
        bus._auth_rejected_event = asyncio.Event()
        bus.emitter = MagicMock()
        bus.latch_refusal("key mismatch, run 'hivemind-client forget-server'")
        assert "forget-server" in bus._auth_rejected
        assert bus._auth_rejected_event.is_set()


class TestCloseAfterAGoodKKSession:
    @patch("hivemind_bus_client.protocol.HandShake")
    def test_a_second_reset_during_the_first_logs_no_kk_failure(self, handshake_cls):
        proto = _protocol()
        proto._noise_pattern = "KKpsk0"
        proto._noise_established = True
        proto.identity.get_pinned_noise_key.return_value = b"pinned-key"

        # the socket close callback runs while close() loads the RSA key
        handshake_cls.side_effect = lambda *a, **kw: (
            proto.reset_connection_state() if handshake_cls.call_count == 1
            else MagicMock())

        with patch("hivemind_bus_client.protocol.LOG") as log:
            proto.reset_connection_state()

        warnings = " ".join(str(c.args[0]) for c in log.warning.call_args_list)
        assert "KKpsk0 failed" not in warnings
        assert not proto.kk_attempt_failed()
        assert proto._xx_retry_pin_id is None
