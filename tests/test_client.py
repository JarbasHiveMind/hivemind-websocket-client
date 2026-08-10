"""Tests for hivemind_bus_client.client — BinaryDataCallbacks, Waiters, HiveMessageBusClient."""
import ssl
import unittest
from collections import Counter
from threading import Event
from unittest.mock import MagicMock, patch

from ovos_bus_client.message import Message
from websocket import WebSocketConnectionClosedException

from hivemind_bus_client.client import (
    BinaryDataCallbacks,
    HiveMessageBusClient,
    HiveMessageWaiter,
    HivePayloadWaiter,
)
from hivemind_bus_client.message import (
    HiveMessage,
    HiveMessageType,
    HiveMindBinaryPayloadType,
)
from hivemind_bus_client.noise import NoiseTransportFailed


class TestBinaryDataCallbacks(unittest.TestCase):
    def test_handle_receive_tts_does_not_raise(self):
        cb = BinaryDataCallbacks()
        cb.handle_receive_tts(b"\x00\x01", "hello", "en", "test.wav")

    def test_handle_receive_file_does_not_raise(self):
        cb = BinaryDataCallbacks()
        cb.handle_receive_file(b"\x00\x01", "test.bin")


class TestHiveMessageWaiter(unittest.TestCase):
    def test_init_registers_handler(self):
        bus = MagicMock()
        waiter = HiveMessageWaiter(bus, HiveMessageType.PING)
        bus.on.assert_called_once_with(HiveMessageType.PING, waiter._handler)

    def test_handler_sets_event(self):
        bus = MagicMock()
        waiter = HiveMessageWaiter(bus, HiveMessageType.PING)
        msg = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        waiter._handler(msg)
        self.assertIs(waiter.received_msg, msg)
        self.assertTrue(waiter.response_event.is_set())

    def test_wait_returns_message_and_removes_handler(self):
        bus = MagicMock()
        waiter = HiveMessageWaiter(bus, HiveMessageType.PING)
        msg = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        waiter._handler(msg)
        result = waiter.wait(timeout=0.1)
        self.assertIs(result, msg)
        bus.remove.assert_called_once_with(HiveMessageType.PING, waiter._handler)

    def test_wait_returns_none_on_timeout(self):
        bus = MagicMock()
        waiter = HiveMessageWaiter(bus, HiveMessageType.PING)
        result = waiter.wait(timeout=0.01)
        self.assertIsNone(result)


class TestHivePayloadWaiter(unittest.TestCase):
    def test_filters_by_payload_type(self):
        bus = MagicMock()
        waiter = HivePayloadWaiter(bus, payload_type="speak", message_type=HiveMessageType.BUS)

        # Matching payload
        inner_msg = Message("speak", {"utterance": "hi"})
        outer = HiveMessage(HiveMessageType.BUS, inner_msg)
        waiter._handler(outer)
        self.assertIsNotNone(waiter.received_msg)

    def test_ignores_non_matching_payload(self):
        bus = MagicMock()
        waiter = HivePayloadWaiter(bus, payload_type="speak", message_type=HiveMessageType.BUS)

        inner_msg = Message("recognizer_loop:utterance", {"utterances": ["hi"]})
        outer = HiveMessage(HiveMessageType.BUS, inner_msg)
        waiter._handler(outer)
        self.assertIsNone(waiter.received_msg)


def _make_client(**kwargs):
    """Create HiveMessageBusClient without actually connecting or starting threads."""
    from ovos_utils.fakebus import FakeBus
    from pyee import EventEmitter

    defaults = {
        "key": "test-key",
        "password": "test-pass",
        "port": 5678,
        "host": "ws://localhost",
        "internal_bus": FakeBus(),
        "websocket_ping_interval": None,
        "websocket_ping_timeout": None,
    }
    defaults.update(kwargs)

    # Bypass OVOSBusClient.__init__ which starts websocket threads
    client = object.__new__(HiveMessageBusClient)
    client.bin_callbacks = defaults.pop("bin_callbacks", BinaryDataCallbacks())
    from hivemind_bus_client.encryption import SupportedCiphers, SupportedEncodings
    client.json_encoding = SupportedEncodings.JSON_HEX
    client.cipher = SupportedCiphers.AES_GCM
    client.identity = None
    client._password = defaults["password"]
    client._access_key = defaults["key"]
    client._name = defaults.get("useragent", "")
    client._port = defaults["port"]
    client._host = defaults["host"]
    client.init_identity()
    client.crypto_key = defaults.get("crypto_key")
    client.noise_transport = None
    client.allow_self_signed = True
    client.share_bus = False
    client.handshake_event = Event()
    client.protocol = None
    client._init_worker_lifecycle()
    client.websocket_ping_interval = defaults["websocket_ping_interval"]
    client.websocket_ping_timeout = defaults["websocket_ping_timeout"]
    client.compress = True
    client.binarize = True
    client.internal_bus = defaults["internal_bus"]
    client.emitter = MagicMock(spec=EventEmitter)
    client.connected_event = Event()
    client.started_running = False
    client.session_id = "test-session-id"
    client.client = MagicMock()
    client.retry = 5
    return client


class TestHiveMessageBusClientProperties(unittest.TestCase):
    def test_useragent(self):
        client = _make_client(useragent="my-agent")
        self.assertEqual(client.useragent, "my-agent")

    def test_useragent_setter(self):
        client = _make_client()
        client.useragent = "new-agent"
        self.assertEqual(client.useragent, "new-agent")

    def test_password_property(self):
        client = _make_client()
        self.assertEqual(client.password, "test-pass")

    def test_key_property(self):
        client = _make_client()
        self.assertEqual(client.key, "test-key")

    def test_site_id_property(self):
        client = _make_client()
        client.site_id = "kitchen"
        self.assertEqual(client.site_id, "kitchen")

    def test_password_setter(self):
        client = _make_client()
        client.password = "new-pass"
        self.assertEqual(client.password, "new-pass")

    def test_key_setter(self):
        client = _make_client()
        client.key = "new-key"
        self.assertEqual(client.key, "new-key")


class TestHiveMessageBusClientOnError(unittest.TestCase):
    @patch("ovos_bus_client.client.client.MessageBusClient.on_error")
    def test_on_error_clears_handshake(self, mock_super_error):
        client = _make_client()
        client.connected_event.set()
        client.handshake_event.set()
        client.crypto_key = "some-key"
        client.noise_transport = MagicMock()
        error = Exception("test")
        client.on_error(error)
        self.assertFalse(client.connected_event.is_set())
        self.assertFalse(client.handshake_event.is_set())
        self.assertIsNone(client.crypto_key)
        self.assertIsNone(client.noise_transport)
        mock_super_error.assert_not_called()
        client.emitter.emit.assert_called_once_with("error", error)
        client.client.close.assert_called_once_with()

    def test_on_error_isolates_listener_failure_and_closes_socket(self):
        client = _make_client()
        client.emitter.emit.side_effect = RuntimeError("listener failed")

        client.on_error(Exception("websocket failed"))

        client.client.close.assert_called_once_with()

    def test_on_error_keeps_expected_reconnect_failures_internal(self):
        for error in (
                WebSocketConnectionClosedException(),
                ConnectionRefusedError(),
                ConnectionResetError(),
        ):
            with self.subTest(error=type(error).__name__):
                client = _make_client()

                client.on_error(error)

                client.emitter.emit.assert_not_called()
                client.client.close.assert_called_once_with()

    def test_on_error_ignores_non_exception_callback(self):
        client = _make_client()
        client.connected_event.set()
        client.handshake_event.set()
        client.crypto_key = "some-key"
        client.on_error(MagicMock())
        self.assertTrue(client.connected_event.is_set())
        self.assertTrue(client.handshake_event.is_set())
        self.assertEqual(client.crypto_key, "some-key")
        client.client.close.assert_not_called()

    def test_on_close_clears_handshake(self):
        client = _make_client()
        client.protocol = MagicMock()
        client.connected_event.set()
        client.handshake_event.set()
        client.crypto_key = "some-key"
        client.noise_transport = MagicMock()
        client.on_close()
        self.assertFalse(client.connected_event.is_set())
        self.assertFalse(client.handshake_event.is_set())
        self.assertIsNone(client.crypto_key)
        self.assertIsNone(client.noise_transport)
        client.protocol.reset_connection_state.assert_called_once_with()
        client.emitter.emit.assert_called_once_with("close")

    def test_close_stops_reconnect_and_closes_socket(self):
        client = _make_client()
        client.started_running = True
        client.connected_event.set()
        client.handshake_event.set()
        client.close()
        self.assertTrue(client._stop_event.is_set())
        # The worker owns this flag and clears it from _run_forever's finally
        # block after it has actually stopped.
        self.assertTrue(client.started_running)
        self.assertFalse(client.connected_event.is_set())
        self.assertFalse(client.handshake_event.is_set())
        client.client.close.assert_called_once_with()

    @patch("hivemind_bus_client.client.Thread")
    def test_run_in_thread_honors_close_before_worker_starts(self, mock_thread):
        client = _make_client()

        thread = client.run_in_thread()
        worker = mock_thread.call_args.kwargs["target"]
        worker_args = mock_thread.call_args.kwargs["args"]
        client.close()
        worker(*worker_args)

        self.assertIs(thread, mock_thread.return_value)
        mock_thread.assert_called_once_with(
            target=client._run_worker,
            args=worker_args,
            daemon=True,
        )
        thread.start.assert_called_once_with()
        client.client.run_forever.assert_not_called()
        self.assertFalse(client.started_running)
        self.assertIsNone(client._worker_token)
        self.assertIsNone(client._worker_thread)

    @patch("hivemind_bus_client.client.Thread")
    def test_duplicate_run_in_thread_is_rejected_while_stopping(
            self, mock_thread):
        client = _make_client()

        client.run_in_thread()
        worker = mock_thread.call_args.kwargs["target"]
        worker_args = mock_thread.call_args.kwargs["args"]
        client.close()

        with self.assertRaisesRegex(RuntimeError, "already running"):
            client.run_in_thread()

        self.assertTrue(client._stop_event.is_set())
        mock_thread.assert_called_once()

        # Once the original worker has observed close() and exited, an
        # explicit restart may claim a fresh lifecycle.
        worker(*worker_args)
        self.assertIsNone(client._worker_token)

    @patch("hivemind_bus_client.client.Thread")
    def test_run_forever_is_rejected_while_thread_worker_is_active(
            self, mock_thread):
        client = _make_client()

        client.run_in_thread()
        worker = mock_thread.call_args.kwargs["target"]
        worker_args = mock_thread.call_args.kwargs["args"]

        with self.assertRaisesRegex(RuntimeError, "already running"):
            client.run_forever()

        mock_thread.assert_called_once()
        client.close()
        worker(*worker_args)

    def test_live_worker_rejects_duplicate_start_until_exit(self):
        client = _make_client()
        worker_entered = Event()
        release_worker = Event()

        def _block_socket(**kwargs):
            worker_entered.set()
            release_worker.wait(timeout=1)

        client.client.run_forever.side_effect = _block_socket
        thread = client.run_in_thread()
        self.assertTrue(worker_entered.wait(timeout=1))

        with self.assertRaisesRegex(RuntimeError, "already running"):
            client.run_in_thread()

        client.close()
        release_worker.set()
        thread.join(timeout=1)

        self.assertFalse(thread.is_alive())
        self.assertIsNone(client._worker_token)
        self.assertIsNone(client._worker_thread)

    @patch("hivemind_bus_client.client.Thread")
    def test_worker_start_failure_releases_lifecycle(self, mock_thread):
        client = _make_client()
        mock_thread.return_value.start.side_effect = RuntimeError(
            "thread start failed"
        )

        with self.assertRaisesRegex(RuntimeError, "thread start failed"):
            client.run_in_thread()

        self.assertTrue(client._stop_event.is_set())
        self.assertIsNone(client._worker_token)
        self.assertIsNone(client._worker_thread)


class TestHiveMessageBusClientOnMessage(unittest.TestCase):
    def test_invalid_noise_frame_reconnects_instead_of_stopping(self):
        client = _make_client()
        client.noise_transport = MagicMock()
        client.noise_transport.decrypt_frame.side_effect = NoiseTransportFailed(
            "invalid frame"
        )

        client.on_message(b"invalid")

        client.noise_transport.decrypt_frame.assert_called_once_with(b"invalid")
        client.client.close.assert_called_once_with()
        self.assertFalse(client._stop_event.is_set())


class TestHiveMessageBusClientKeepalive(unittest.TestCase):
    def test_keepalive_options_default(self):
        client = _make_client()
        self.assertEqual(
            client._websocket_keepalive_options(),
            {"ping_interval": 25.0, "ping_timeout": 10.0},
        )

    def test_keepalive_options_explicit(self):
        client = _make_client(websocket_ping_interval=15, websocket_ping_timeout=5)
        self.assertEqual(
            client._websocket_keepalive_options(),
            {"ping_interval": 15.0, "ping_timeout": 5.0},
        )

    def test_keepalive_options_from_env(self):
        client = _make_client()
        with patch.dict(
            "os.environ",
            {
                "HIVEMIND_WEBSOCKET_CLIENT_PING_INTERVAL": "30",
                "HIVEMIND_WEBSOCKET_CLIENT_PING_TIMEOUT": "12",
            },
        ):
            self.assertEqual(
                client._websocket_keepalive_options(),
                {"ping_interval": 30.0, "ping_timeout": 12.0},
            )

    def test_keepalive_options_disable_interval(self):
        client = _make_client(websocket_ping_interval=0)
        self.assertEqual(client._websocket_keepalive_options(), {"ping_interval": 0})

    def test_keepalive_options_adjusts_timeout(self):
        client = _make_client(websocket_ping_interval=10, websocket_ping_timeout=10)
        self.assertEqual(
            client._websocket_keepalive_options(),
            {"ping_interval": 10.0, "ping_timeout": 5.0},
        )

    def test_run_forever_passes_keepalive(self):
        client = _make_client()
        client.allow_self_signed = False
        client.client.run_forever.side_effect = (
            lambda **kwargs: client._stop_event.set()
        )
        client.run_forever()
        client.client.run_forever.assert_called_once_with(
            ping_interval=25.0, ping_timeout=10.0
        )

    def test_run_forever_passes_keepalive_and_ssl_options(self):
        client = _make_client()
        client.client.run_forever.side_effect = (
            lambda **kwargs: client._stop_event.set()
        )
        client.run_forever()
        kwargs = client.client.run_forever.call_args.kwargs
        self.assertEqual(kwargs["ping_interval"], 25.0)
        self.assertEqual(kwargs["ping_timeout"], 10.0)
        self.assertEqual(kwargs["sslopt"]["cert_reqs"], ssl.CERT_NONE)

    def test_run_forever_reconnects_after_websocket_returns(self):
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 0
        first_socket = client.client
        second_socket = MagicMock()
        second_socket.run_forever.side_effect = (
            lambda **kwargs: client._stop_event.set()
        )
        client.create_client = MagicMock(return_value=second_socket)

        client.run_forever()

        first_socket.run_forever.assert_called_once_with(
            ping_interval=25.0, ping_timeout=10.0
        )
        client.create_client.assert_called_once_with()
        second_socket.run_forever.assert_called_once_with(
            ping_interval=25.0, ping_timeout=10.0
        )
        client.emitter.emit.assert_called_once_with("reconnecting")
        self.assertEqual(client.retry, 2)

    def test_run_forever_jitters_the_wait_but_not_the_retry_series(self):
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 5
        client._stop_event.wait = MagicMock(return_value=True)
        client.client.run_forever.side_effect = lambda **kwargs: None

        client.run_forever()

        # the wait delay must have been jittered away from the raw retry value
        waited_delay = client._stop_event.wait.call_args.args[0]
        self.assertNotEqual(waited_delay, 5)
        self.assertGreaterEqual(waited_delay, 5 * 0.5)
        self.assertLessEqual(waited_delay, 5 * 1.5)
        # the stored retry value is untouched by jitter: reconnect loop broke
        # out on wait() returning True, so the exponential bump never ran
        self.assertEqual(client.retry, 5)

    def test_reconnect_wait_delay_varies_across_calls(self):
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 10
        waited_delays = []

        def fake_wait(delay):
            waited_delays.append(delay)
            return len(waited_delays) >= 5

        client._stop_event.wait = fake_wait
        second_socket = MagicMock()
        client.create_client = MagicMock(return_value=second_socket)

        client.run_forever()

        self.assertEqual(len(waited_delays), 5)
        self.assertTrue(len(set(waited_delays)) > 1)
        for delay in waited_delays:
            self.assertGreaterEqual(delay, 0)

    def test_retry_series_stays_clean_exponential_regardless_of_jitter(self):
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 1
        observed_retries = []

        def fake_wait(delay):
            observed_retries.append(client.retry)
            return len(observed_retries) >= 7

        client._stop_event.wait = fake_wait
        client.create_client = MagicMock(return_value=MagicMock())

        client.run_forever()

        self.assertEqual(observed_retries, [1, 2, 4, 8, 16, 32, 60])

    def test_wait_stays_jittered_at_the_retry_ceiling(self):
        # A sustained outage parks every satellite at retry=60. Clamping the
        # jittered wait would pile half of the delays onto exactly 60s and
        # re-synchronize the fleet, so the delays must stay spread out over
        # the full [30, 90] window with no repeated value.
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 60
        waited_delays = []

        def fake_wait(delay):
            waited_delays.append(delay)
            return len(waited_delays) >= 500

        client._stop_event.wait = fake_wait
        client.create_client = MagicMock(return_value=MagicMock())

        client.run_forever()

        self.assertEqual(len(waited_delays), 500)
        for delay in waited_delays:
            self.assertGreaterEqual(delay, 30)
            self.assertLessEqual(delay, 90)
        # no probability atom: a continuous distribution repeats no value
        most_common = max(Counter(waited_delays).values())
        self.assertEqual(most_common, 1)
        # and it really spans the window rather than hugging one end
        self.assertLess(min(waited_delays), 40)
        self.assertGreater(max(waited_delays), 80)

    def test_stop_event_still_interrupts_reconnect_wait_promptly(self):
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 5
        real_wait = client._stop_event.wait

        def stop_immediately(delay):
            client._stop_event.set()
            return real_wait(0)

        client._stop_event.wait = stop_immediately
        client.create_client = MagicMock()

        client.run_forever()

        self.assertTrue(client._stop_event.is_set())
        client.create_client.assert_not_called()

    def test_reconnecting_listener_failure_does_not_stop_worker(self):
        client = _make_client()
        client.allow_self_signed = False
        client.retry = 0
        client.emitter.emit.side_effect = RuntimeError("listener failed")
        second_socket = MagicMock()
        second_socket.run_forever.side_effect = (
            lambda **kwargs: client._stop_event.set()
        )
        client.create_client = MagicMock(return_value=second_socket)

        client.run_forever()

        client.emitter.emit.assert_called_once_with("reconnecting")
        client.create_client.assert_called_once_with()
        second_socket.run_forever.assert_called_once_with(
            ping_interval=25.0, ping_timeout=10.0
        )

    def test_run_forever_does_not_reconnect_after_close(self):
        client = _make_client()
        client.allow_self_signed = False
        client.client.run_forever.side_effect = (
            lambda **kwargs: client.close()
        )
        client.create_client = MagicMock()

        client.run_forever()

        client.create_client.assert_not_called()


class TestHiveMessageBusClientOn(unittest.TestCase):
    def test_on_mycroft_event_registers_on_internal_bus(self):
        client = _make_client()
        client.internal_bus = MagicMock()
        fn = MagicMock()
        client.on("speak", fn)
        client.internal_bus.on.assert_called_with("speak", fn)

    def test_on_hive_event_registers_on_emitter(self):
        client = _make_client()
        fn = MagicMock()
        client.on(HiveMessageType.PING, fn)
        client.emitter.on.assert_called_with(HiveMessageType.PING, fn)

    def test_remove_mycroft_event(self):
        client = _make_client()
        client.internal_bus = MagicMock()
        fn = MagicMock()
        client.remove("speak", fn)
        client.internal_bus.remove.assert_called_with("speak", fn)

    def test_remove_hive_event(self):
        client = _make_client()
        fn = MagicMock()
        client.remove(HiveMessageType.PING, fn)
        client.emitter.remove_listener.assert_called_with(HiveMessageType.PING, fn)


class TestHandleHiveProtocol(unittest.TestCase):
    def test_bus_message_emitted_to_internal_bus(self):
        client = _make_client()
        client.internal_bus = MagicMock()
        msg = HiveMessage(HiveMessageType.BUS, Message("speak", {"utterance": "hi"}))
        client._handle_hive_protocol(msg)
        self.assertTrue(client.internal_bus.emit.called)

    def test_non_bus_message_emitted_to_emitter(self):
        client = _make_client()
        msg = HiveMessage(HiveMessageType.PING, {"flood_id": "x"})
        client._handle_hive_protocol(msg)
        client.emitter.emit.assert_called()


class TestHandleBinary(unittest.TestCase):
    def test_tts_audio_callback(self):
        cb = MagicMock()
        client = _make_client(bin_callbacks=cb)
        msg = HiveMessage(HiveMessageType.BINARY, b"\x00\x01",
                          bin_type=HiveMindBinaryPayloadType.TTS_AUDIO,
                          metadata={"lang": "en", "utterance": "hi", "file_name": "tts.wav"})
        client._handle_binary(msg)
        cb.handle_receive_tts.assert_called_once_with(b"\x00\x01", "hi", "en", "tts.wav")

    def test_file_callback(self):
        cb = MagicMock()
        client = _make_client(bin_callbacks=cb)
        msg = HiveMessage(HiveMessageType.BINARY, b"\x00\x01",
                          bin_type=HiveMindBinaryPayloadType.FILE,
                          metadata={"file_name": "data.bin"})
        client._handle_binary(msg)
        cb.handle_receive_file.assert_called_once_with(b"\x00\x01", "data.bin")

    def test_undefined_binary_no_callback(self):
        cb = MagicMock()
        client = _make_client(bin_callbacks=cb)
        msg = HiveMessage(HiveMessageType.BINARY, b"\x00\x01",
                          bin_type=HiveMindBinaryPayloadType.UNDEFINED)
        client._handle_binary(msg)
        cb.handle_receive_tts.assert_not_called()
        cb.handle_receive_file.assert_not_called()


class TestEmitFraming(unittest.TestCase):
    """INTERCOM has no WIRE-1 binary code, so it must go out as text."""

    def _client_with_binarize(self):
        client = _make_client()
        client.crypto_key = None
        client.protocol = MagicMock(binarize=True)
        client.binarize = True
        client.connected_event.set()
        client.handshake_event.set()
        client.client = MagicMock()
        return client

    def test_intercom_sent_as_text_frame(self):
        client = self._client_with_binarize()
        client.emit(HiveMessage(HiveMessageType.INTERCOM,
                                payload={"ciphertext": "deadbeef"}))
        sent = client.client.send.call_args
        self.assertIsInstance(sent.args[0], str)
        self.assertIn("intercom", sent.args[0])

    def test_shared_bus_still_sent_as_binary_frame(self):
        client = self._client_with_binarize()
        client.emit(HiveMessage(HiveMessageType.SHARED_BUS,
                                payload=Message("speak", {"utterance": "hi"})))
        sent = client.client.send.call_args
        self.assertIsInstance(sent.args[0], bytes)


class TestBuildUrl(unittest.TestCase):
    def test_ssl_url(self):
        url = HiveMessageBusClient.build_url("mykey", host="example.com", port=5678, ssl=True)
        self.assertTrue(url.startswith("wss://"))
        self.assertIn("example.com:5678", url)
        self.assertIn("authorization=", url)

    def test_no_ssl_url(self):
        url = HiveMessageBusClient.build_url("mykey", ssl=False)
        self.assertTrue(url.startswith("ws://"))


if __name__ == "__main__":
    unittest.main()


class TestEmitBinType:
    """A HiveMessage carries its own bin_type; emit must not discard it."""

    def _emitted_frame(self, message, **kw):
        from unittest.mock import MagicMock, patch
        from hivemind_bus_client.client import HiveMessageBusClient
        c = object.__new__(HiveMessageBusClient)
        c.connected_event = MagicMock(is_set=lambda: True)
        c.protocol = MagicMock(binarize=True)
        c.binarize = True
        c.compress = False
        c.noise_transport = None
        c.crypto_key = None
        c.client = MagicMock()
        c.identity = MagicMock(site_id="t")
        with patch("hivemind_bus_client.client.get_bitstring") as gb:
            gb.return_value = MagicMock(bytes=b"")
            c.emit(message, **kw)
        return gb.call_args.kwargs

    def test_message_bin_type_reaches_the_wire(self):
        from hivemind_bus_client.message import (
            HiveMessage, HiveMessageType, HiveMindBinaryPayloadType)
        m = HiveMessage(HiveMessageType.BINARY, payload=b"\x00" * 8,
                        bin_type=HiveMindBinaryPayloadType.RAW_AUDIO)
        assert self._emitted_frame(m)["binary_type"] == \
            HiveMindBinaryPayloadType.RAW_AUDIO

    def test_explicit_argument_still_wins(self):
        from hivemind_bus_client.message import (
            HiveMessage, HiveMessageType, HiveMindBinaryPayloadType)
        m = HiveMessage(HiveMessageType.BINARY, payload=b"\x00" * 8,
                        bin_type=HiveMindBinaryPayloadType.RAW_AUDIO)
        got = self._emitted_frame(
            m, binary_type=HiveMindBinaryPayloadType.FILE)
        assert got["binary_type"] == HiveMindBinaryPayloadType.FILE
