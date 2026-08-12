"""Tests for hivemind_bus_client.protocol — HiveMindSlaveProtocol handlers."""
import time
from unittest.mock import MagicMock, patch
import pytest

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.protocol import CascadeAggregator, HiveMindSlaveProtocol
from hivemind_bus_client.hive_map import HiveMapper, NodeInfo
from hivemind_bus_client.identity import NodeIdentity
from poorman_handshake.symmetric.strength import WeakPasswordError


def _make_protocol() -> HiveMindSlaveProtocol:
    """Create a minimal HiveMindSlaveProtocol with mocked dependencies."""
    hm = MagicMock()
    hm.session_id = "test-session"
    identity = MagicMock(spec=NodeIdentity)
    identity.name = "test-node"
    identity.password = "test-node-horse-battery-staple-92"
    proto = HiveMindSlaveProtocol(hm=hm, identity=identity, site_id="living-room")
    return proto


class TestHandshakeInitialization:
    def test_bind_defers_legacy_password_validation(self):
        """Binding must not construct a handshake that may never be used."""
        proto = _make_protocol()
        proto.identity.password = "sat123"
        bus = MagicMock()

        with patch("hivemind_bus_client.protocol.HandShake"):
            proto.bind(bus)

        assert proto.pswd_handshake is None

    def test_legacy_password_handshake_still_rejects_weak_password(self):
        """The negotiated legacy path must retain its strength policy."""
        proto = _make_protocol()
        proto.identity.password = "sat123"
        message = HiveMessage(HiveMessageType.HANDSHAKE,
                              {"password": True})

        with patch.object(proto, "_should_use_noise", return_value=False):
            with pytest.raises(WeakPasswordError):
                proto.handle_handshake(message)

    def test_pubkey_envelope_logs_asymmetric_handshake_key_size(self):
        """Pubkey fallback must not dereference the absent password handshake."""
        proto = _make_protocol()
        proto.handshake = MagicMock(secret=b"k" * 32)
        message = HiveMessage(HiveMessageType.HANDSHAKE,
                              {"envelope": "pubkey-envelope"})

        with patch.object(proto, "receive_handshake") as receive:
            with patch("hivemind_bus_client.protocol.LOG.debug") as debug:
                proto.handle_handshake(message)

        receive.assert_called_once_with("pubkey-envelope")
        debug.assert_any_call("Key size: 256bit")


class TestConnectionState:
    @patch("hivemind_bus_client.protocol.HandShake")
    def test_reset_discards_partial_handshake(self, handshake_cls):
        proto = _make_protocol()
        proto.internal_protocol = MagicMock()
        proto.internal_protocol.node_id = "old-master"
        proto.pswd_handshake = MagicMock()
        proto.mpubkey = "old-key"
        proto.noise_handshake = MagicMock()
        proto._noise_pattern = "XXpsk2"
        proto._server_hello_payload = {"node_id": "old-master"}
        proto._server_handshake_payload = {"noise": {"patterns": ["XXpsk2"]}}

        proto.reset_connection_state()

        handshake_cls.assert_called_once_with(proto.identity.private_key)
        assert proto.handshake is handshake_cls.return_value
        assert proto.pswd_handshake is None
        assert proto.mpubkey == ""
        assert proto.noise_handshake is None
        assert proto._noise_pattern is None
        assert proto._server_hello_payload is None
        assert proto._server_handshake_payload is None
        assert proto.internal_protocol.node_id == ""


class TestNoiseHandshakePinning:
    """CRYPTO-1 §3.4.5 — a completed XX-path handshake against a static key
    that contradicts a pinned key must abort; a matching or TOFU-absent pin
    must not.
    """

    def _make_protocol_at_noise_msg2(self, remote_static_key: bytes,
                                      handshake_finished: bool = True):
        proto = _make_protocol()
        proto.noise_handshake = MagicMock()
        proto.noise_handshake.read_message.return_value = b""
        proto.noise_handshake.handshake_finished = handshake_finished
        proto._noise_pattern = "XXpsk2"
        proto.hm.config.host = "hive.example"
        proto.hm.config.port = 5678
        message = HiveMessage(HiveMessageType.HANDSHAKE,
                              {"noise": {"msg": (b"x" * 16).hex()}})
        return proto, message

    def test_pinned_key_contradicted_aborts_session(self):
        """The XX-path guard: a static key that differs from the pin is a
        possible MITM and must be rejected, not silently accepted.
        """
        remote_key = b"r" * 32
        proto, message = self._make_protocol_at_noise_msg2(remote_key)
        proto.identity.get_pinned_noise_key.return_value = b"p" * 32

        with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
            transport_cls.return_value.remote_static_key = remote_key
            with patch("hivemind_bus_client.protocol.LOG.error") as error:
                proto.receive_noise_handshake(message)

        assert proto.hm.noise_transport is None
        proto.hm.handshake_event.set.assert_not_called()
        # the transport-level close: the reconnect loop must survive
        proto.hm.close_connection.assert_called_once()
        proto.hm.close.assert_not_called()
        proto.identity.pin_noise_key.assert_not_called()
        assert any("pin" in call.args[0].lower() and "mismatch" in call.args[0].lower()
                   for call in error.call_args_list)

    def test_mismatch_message_says_how_to_recover(self):
        """The pin also trips on a legitimate rebuild of the master, so the
        log line must name the way out instead of only shouting MITM.
        """
        remote_key = b"r" * 32
        proto, message = self._make_protocol_at_noise_msg2(remote_key)
        proto.identity.get_pinned_noise_key.return_value = b"p" * 32

        with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
            transport_cls.return_value.remote_static_key = remote_key
            with patch("hivemind_bus_client.protocol.LOG.error") as error:
                proto.receive_noise_handshake(message)

        logged = " ".join(call.args[0] for call in error.call_args_list)
        assert "forget-server" in logged

    def test_malformed_envelope_also_keeps_reconnecting(self):
        """Every abort reason is repairable from the other side, so none of
        them may stop the reconnect loop.
        """
        proto = _make_protocol()
        message = HiveMessage(HiveMessageType.HANDSHAKE, {"noise": {}})

        proto.receive_noise_handshake(message)

        proto.hm.close_connection.assert_called_once()
        proto.hm.close.assert_not_called()

    def test_pinned_key_matches_completes_handshake(self):
        """A pin that matches the negotiated static key is the expected,
        non-fatal case: the session must be established normally.
        """
        remote_key = b"p" * 32
        proto, message = self._make_protocol_at_noise_msg2(remote_key)
        proto.identity.get_pinned_noise_key.return_value = remote_key
        proto.identity.public_key = "pub"
        proto.hm.session_id = "test-session"
        proto.site_id = "living-room"

        with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
            transport_cls.return_value.remote_static_key = remote_key
            proto.receive_noise_handshake(message)

        assert proto.hm.noise_transport is transport_cls.return_value
        proto.hm.handshake_event.set.assert_called_once()
        proto.hm.close_connection.assert_not_called()
        proto.identity.pin_noise_key.assert_not_called()

    def test_no_pin_tofu_pins_new_key(self):
        """First-connection TOFU: no prior pin means the negotiated static
        key is trusted and stored for future comparisons.
        """
        remote_key = b"n" * 32
        proto, message = self._make_protocol_at_noise_msg2(remote_key)
        proto.identity.get_pinned_noise_key.return_value = None
        proto.identity.public_key = "pub"
        proto.hm.session_id = "test-session"
        proto.site_id = "living-room"

        with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
            transport_cls.return_value.remote_static_key = remote_key
            proto.receive_noise_handshake(message)

        assert proto.hm.noise_transport is transport_cls.return_value
        proto.hm.handshake_event.set.assert_called_once()
        proto.hm.close_connection.assert_not_called()
        proto.identity.pin_noise_key.assert_called_once_with(
            proto._noise_pin_id, remote_key)


class TestHandlePing:
    def test_sends_responsive_ping(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "other"})
        proto.handle_ping(inner)

        proto.hm.emit.assert_called_once()
        sent = proto.hm.emit.call_args[0][0]
        assert sent.msg_type == HiveMessageType.PROPAGATE
        inner_sent = sent.payload
        assert isinstance(inner_sent, HiveMessage)
        assert inner_sent.msg_type == HiveMessageType.PING
        payload = inner_sent.payload
        assert payload["flood_id"] == "abc"
        assert payload["peer"] == "test-node::test-session"
        assert payload["site_id"] == "living-room"

    def test_duplicate_flood_id_ignored(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "other"})
        proto.handle_ping(inner)
        proto.hm.emit.reset_mock()

        # Second call with same flood_id
        proto.handle_ping(inner)
        proto.hm.emit.assert_not_called()

    def test_empty_flood_id_ignored(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "", "peer": "other"})
        proto.handle_ping(inner)
        proto.hm.emit.assert_not_called()

    def test_flood_id_set_capped(self):
        """When seen flood IDs reach max_size, oldest entries are evicted."""
        proto = _make_protocol()
        mapper = proto.hive_mapper or HiveMapper()
        proto.hive_mapper = mapper
        # Pre-fill with 1000 flood IDs
        for i in range(1000):
            mapper.check_flood_id(str(i))
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "new", "peer": "other"})
        proto.handle_ping(inner)
        proto.hm.emit.assert_called_once()  # "new" was not seen, so ping sent

    def test_different_flood_ids_both_processed(self):
        proto = _make_protocol()
        for fid in ["flood1", "flood2"]:
            inner = HiveMessage(HiveMessageType.PING, {"flood_id": fid, "peer": "other"})
            proto.handle_ping(inner)
        assert proto.hm.emit.call_count == 2


class TestHandleQuery:
    def _make_protocol_with_bus(self):
        proto = _make_protocol()
        proto.internal_protocol = MagicMock()
        proto.internal_protocol.node_id = "master-1"
        proto.internal_protocol.bus = MagicMock()
        return proto

    def test_bus_payload_dispatches_to_handle_bus(self):
        """QUERY with inner BUS payload should call handle_bus."""
        proto = self._make_protocol_with_bus()
        inner_bus = HiveMessage(HiveMessageType.BUS,
                                {"type": "speak", "data": {"utterance": "hello"}, "context": {}})
        query_msg = HiveMessage(HiveMessageType.QUERY, payload=inner_bus)

        with patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_query(query_msg)
            mock_bus.assert_called_once()
            # the QUERY wraps an inner BUS HiveMessage; handle_bus gets that, not the wrapper
            called = mock_bus.call_args[0][0]
            assert called.msg_type == HiveMessageType.BUS

    def test_intercom_payload_dispatches_to_handle_intercom(self):
        """QUERY with inner INTERCOM payload should call handle_intercom."""
        proto = self._make_protocol_with_bus()
        inner_bus = HiveMessage(HiveMessageType.BUS,
                                {"type": "speak", "data": {}, "context": {}})
        inner_intercom = HiveMessage(HiveMessageType.INTERCOM, payload=inner_bus)
        query_msg = HiveMessage(HiveMessageType.QUERY, payload=inner_intercom)

        with patch.object(proto, 'handle_intercom') as mock_intercom:
            proto.handle_query(query_msg)
            mock_intercom.assert_called_once_with(query_msg)

    def test_invalid_inner_type_raises(self):
        """QUERY with non-BUS/INTERCOM inner payload should raise AssertionError."""
        proto = self._make_protocol_with_bus()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        query_msg = HiveMessage(HiveMessageType.QUERY, payload=inner)

        with pytest.raises(AssertionError):
            proto.handle_query(query_msg)


def _make_cascade_msg(utterance: str = "hello") -> HiveMessage:
    """Helper to build a CASCADE(BUS) message."""
    inner = HiveMessage(HiveMessageType.BUS,
                        {"type": "speak", "data": {"utterance": utterance}, "context": {}})
    return HiveMessage(HiveMessageType.CASCADE, payload=inner)


class TestCascadeAggregator:
    def test_single_response_emitted_on_timeout(self):
        """A single response should be emitted after timeout."""
        emitted = []
        agg = CascadeAggregator(
            timeout=0.05,
            select_callback=lambda rs: rs[0],
            emit_callback=emitted.append,
        )
        msg = _make_cascade_msg("one")
        agg.add_response(msg)
        assert emitted == []
        time.sleep(0.15)
        assert len(emitted) == 1
        assert emitted[0] is msg

    def test_multiple_responses_passed_to_select(self):
        """All buffered responses should be passed to the select callback."""
        collected = []

        def select_cb(responses):
            collected.extend(responses)
            return responses[-1]  # pick last

        emitted = []
        agg = CascadeAggregator(
            timeout=0.05,
            select_callback=select_cb,
            emit_callback=emitted.append,
        )
        msg1 = _make_cascade_msg("one")
        msg2 = _make_cascade_msg("two")
        agg.add_response(msg1)
        agg.add_response(msg2)
        time.sleep(0.15)
        assert len(collected) == 2
        assert emitted[0] is msg2

    def test_early_resolution_with_expected_responses(self):
        """Resolves immediately when expected_responses count is reached."""
        emitted = []
        agg = CascadeAggregator(
            timeout=10.0,  # very long — should NOT wait this long
            select_callback=lambda rs: rs[0],
            emit_callback=emitted.append,
            expected_responses=2,
        )
        agg.add_response(_make_cascade_msg("one"))
        assert emitted == []
        agg.add_response(_make_cascade_msg("two"))
        # should resolve synchronously, no need to wait
        assert len(emitted) == 1

    def test_late_responses_ignored_after_resolve(self):
        """Responses arriving after resolution are discarded."""
        emitted = []
        agg = CascadeAggregator(
            timeout=10.0,
            select_callback=lambda rs: rs[0],
            emit_callback=emitted.append,
            expected_responses=1,
        )
        agg.add_response(_make_cascade_msg("one"))
        assert len(emitted) == 1
        agg.add_response(_make_cascade_msg("late"))
        assert len(emitted) == 1  # still 1

    def test_cancel_prevents_emission(self):
        """Cancelling the aggregator should prevent any emission."""
        emitted = []
        agg = CascadeAggregator(
            timeout=0.05,
            select_callback=lambda rs: rs[0],
            emit_callback=emitted.append,
        )
        agg.add_response(_make_cascade_msg("one"))
        agg.cancel()
        time.sleep(0.15)
        assert emitted == []

    def test_select_returning_none_skips_emit(self):
        """If select_callback returns None, nothing is emitted."""
        emitted = []
        agg = CascadeAggregator(
            timeout=10.0,
            select_callback=lambda rs: None,
            emit_callback=emitted.append,
            expected_responses=1,
        )
        agg.add_response(_make_cascade_msg("one"))
        assert emitted == []


class TestHandleCascade:
    def _make_protocol_with_bus(self):
        proto = _make_protocol()
        proto.internal_protocol = MagicMock()
        proto.internal_protocol.node_id = "master-1"
        proto.internal_protocol.bus = MagicMock()
        proto.cascade_timeout = 0.05  # fast for tests
        return proto

    def test_buffers_and_emits_after_timeout(self):
        """handle_cascade should buffer responses and emit via aggregator."""
        proto = self._make_protocol_with_bus()
        msg = _make_cascade_msg("hi")

        with patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_cascade(msg)
            mock_bus.assert_not_called()  # not yet — buffered
            time.sleep(0.15)
            mock_bus.assert_called_once()

    def test_custom_select_callback(self):
        """User-provided cascade_select_callback should be used."""
        proto = self._make_protocol_with_bus()
        proto.cascade_select_callback = lambda rs: rs[-1]  # pick last

        msg1 = _make_cascade_msg("first")
        msg2 = _make_cascade_msg("second")

        with patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_cascade(msg1)
            proto.handle_cascade(msg2)
            time.sleep(0.15)
            mock_bus.assert_called_once()
            selected = mock_bus.call_args[0][0]
            # the aggregator emits the selected (last) response's inner BUS, not the wrapper
            assert selected.msg_type == HiveMessageType.BUS
            assert selected.payload.data["utterance"] == "second"

    def test_early_resolve_with_hive_mapper(self):
        """With hive_mapper set, resolves early when all nodes responded."""
        proto = self._make_protocol_with_bus()
        proto.cascade_timeout = 10.0  # long timeout — should resolve early
        mapper = HiveMapper()
        mapper.nodes = {"peer1": NodeInfo(peer="peer1"), "peer2": NodeInfo(peer="peer2")}
        proto.hive_mapper = mapper

        with patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_cascade(_make_cascade_msg("one"))
            mock_bus.assert_not_called()
            proto.handle_cascade(_make_cascade_msg("two"))
            mock_bus.assert_called_once()  # resolved immediately

    def test_invalid_inner_type_raises(self):
        """CASCADE with non-BUS/INTERCOM inner payload should raise AssertionError."""
        proto = self._make_protocol_with_bus()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        cascade_msg = HiveMessage(HiveMessageType.CASCADE, payload=inner)

        with pytest.raises(AssertionError):
            proto.handle_cascade(cascade_msg)


class TestHandlePropagate:
    def test_ping_dispatched(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "abc", "peer": "x"})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)

        with patch.object(proto, 'handle_ping') as mock_ping:
            proto.handle_propagate(outer)
            mock_ping.assert_called_once()
            called_with = mock_ping.call_args[0][0]
            assert called_with.msg_type == HiveMessageType.PING
            assert called_with.payload == {"flood_id": "abc", "peer": "x"}


class TestUnhandledInnerPayloadType:
    """MSG-1 §3: a node MUST forward or ignore a payload type it does not
    handle, and MUST NOT reject the connection. The old code asserted the
    inner type, which crashed the handler (and vanished under "python -O")."""

    def test_propagate_with_unhandled_inner_type_is_ignored(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.HELLO, {"whatever": 1})
        outer = HiveMessage(HiveMessageType.PROPAGATE, inner)

        with patch.object(proto, 'handle_ping') as mock_ping, \
                patch.object(proto, 'handle_intercom') as mock_intercom, \
                patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_propagate(outer)  # must not raise
            mock_ping.assert_not_called()
            mock_intercom.assert_not_called()
            mock_bus.assert_not_called()

    def test_broadcast_with_unhandled_inner_type_is_ignored(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.HELLO, {"whatever": 1})
        outer = HiveMessage(HiveMessageType.BROADCAST, inner)

        with patch.object(proto, 'handle_intercom') as mock_intercom, \
                patch.object(proto, 'handle_bus') as mock_bus:
            proto.handle_broadcast(outer)  # must not raise
            mock_intercom.assert_not_called()
            mock_bus.assert_not_called()

    def test_propagate_wrong_outer_type_is_dropped(self):
        proto = _make_protocol()
        inner = HiveMessage(HiveMessageType.PING, {"flood_id": "a"})
        outer = HiveMessage(HiveMessageType.BROADCAST, inner)
        with patch.object(proto, 'handle_ping') as mock_ping:
            proto.handle_propagate(outer)  # must not raise
            mock_ping.assert_not_called()


class TestNoiseKKFallback:
    """A KKpsk0 failure must not lock the node out.

    KK is chosen on the strength of having pinned the *server's* key, which
    says nothing about whether the server still holds this node's static key.
    When they diverge — identity recreated, or one access key used from a
    second useragent — KK fails on every attempt and the client used to retry
    KK forever.
    """

    def _protocol_failing_handshake(self, pattern: str, pinned):
        proto = _make_protocol()
        proto.noise_handshake = MagicMock()
        proto.noise_handshake.read_message.side_effect = Exception("decrypt failed")
        proto._noise_pattern = pattern
        proto.hm.config.host = "hive.example"
        proto.hm.config.port = 5678
        proto.identity.get_pinned_noise_key.return_value = pinned
        message = HiveMessage(HiveMessageType.HANDSHAKE,
                              {"noise": {"msg": (b"x" * 16).hex()}})
        return proto, message

    def test_failed_kk_drops_the_stale_pin(self):
        proto, message = self._protocol_failing_handshake("KKpsk0", b"pinned-key")
        proto.receive_noise_handshake(message.payload)
        proto.identity.forget_noise_key.assert_called_once_with(proto._noise_pin_id)

    def test_failed_xx_keeps_the_pin(self):
        # XX failing says nothing about the pin, and dropping it there would
        # discard the only MITM signal the node has
        proto, message = self._protocol_failing_handshake("XXpsk2", b"pinned-key")
        proto.receive_noise_handshake(message.payload)
        proto.identity.forget_noise_key.assert_not_called()

    def test_failed_kk_without_a_pin_forgets_nothing(self):
        proto, message = self._protocol_failing_handshake("KKpsk0", None)
        proto.receive_noise_handshake(message.payload)
        proto.identity.forget_noise_key.assert_not_called()

    def test_a_completed_handshake_contradicting_the_pin_keeps_it(self):
        # the genuine MITM signal: the handshake succeeded but the static key
        # is not the pinned one. That must still refuse, and must NOT drop the
        # pin, or an attacker could clear it by presenting a wrong key.
        proto = _make_protocol()
        proto.noise_handshake = MagicMock()
        proto.noise_handshake.read_message.return_value = b""
        proto.noise_handshake.handshake_finished = True
        proto._noise_pattern = "KKpsk0"
        proto.hm.config.host = "hive.example"
        proto.hm.config.port = 5678
        proto.identity.get_pinned_noise_key.return_value = b"pinned-key"
        message = HiveMessage(HiveMessageType.HANDSHAKE,
                              {"noise": {"msg": (b"x" * 16).hex()}})
        with patch("hivemind_bus_client.protocol.NoiseTransport") as transport_cls:
            transport_cls.return_value.remote_static_key = b"different-key"
            proto.receive_noise_handshake(message.payload)
        proto.identity.forget_noise_key.assert_not_called()
        assert proto.hm.noise_transport is None

    @patch("hivemind_bus_client.protocol.HandShake")
    def test_a_closed_socket_mid_kk_drops_the_pin(self, _handshake_cls):
        """The server closes rather than answering a KK it cannot complete,
        so the client never reaches receive_noise_handshake. The disconnect
        path has to be what recovers, or the node loops on KK forever."""
        proto = _make_protocol()
        proto._noise_pattern = "KKpsk0"
        proto._noise_established = False
        proto.identity.get_pinned_noise_key.return_value = b"pinned-key"
        proto.hm.config.host = "hive.example"
        proto.hm.config.port = 5678

        proto.reset_connection_state()

        proto.identity.forget_noise_key.assert_called_once_with("hive.example:5678")

    @patch("hivemind_bus_client.protocol.HandShake")
    def test_a_normal_disconnect_after_a_good_session_keeps_the_pin(self, _handshake_cls):
        proto = _make_protocol()
        proto._noise_pattern = "KKpsk0"
        proto._noise_established = True
        proto.identity.get_pinned_noise_key.return_value = b"pinned-key"
        proto.hm.config.host = "hive.example"
        proto.hm.config.port = 5678

        proto.reset_connection_state()

        proto.identity.forget_noise_key.assert_not_called()
