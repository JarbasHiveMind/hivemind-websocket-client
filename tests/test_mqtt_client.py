"""Tests for hivemind_bus_client.mqtt_client — HiveMindMQTTClient."""
import json
import unittest
from threading import Event
from unittest.mock import MagicMock, patch, call

from ovos_bus_client.message import Message
from ovos_utils.fakebus import FakeBus

from hivemind_bus_client.encryption import SupportedEncodings, SupportedCiphers
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType, HiveMindBinaryPayloadType
from hivemind_bus_client.mqtt_client import HiveMindMQTTClient


# ---------------------------------------------------------------------------
# Factory — bypasses Thread.start(), paho connect, and HandShake I/O
# ---------------------------------------------------------------------------

def _make_client(**kwargs) -> HiveMindMQTTClient:
    """Instantiate HiveMindMQTTClient without starting threads or connecting."""
    defaults = dict(
        key="test-access-key",
        password="test-password",
        broker_host="mqtt.example.com",
        broker_port=1883,
        hub_id="test-hub",
        topic_prefix="hivemind",
        internal_bus=FakeBus(),
    )
    defaults.update(kwargs)

    client = object.__new__(HiveMindMQTTClient)

    # threading.Thread state
    import threading
    threading.Thread.__init__(client, daemon=True)

    client.bin_callbacks = defaults.pop("bin_callbacks", MagicMock())
    client.json_encoding = SupportedEncodings.JSON_HEX
    client.cipher = SupportedCiphers.AES_GCM
    client.server_key = None
    client.identity = None
    client._password = defaults["password"]
    client._access_key = defaults["key"]
    client._name = defaults.get("useragent", "HiveMindMQTTClientV1.0")
    client._port = None
    client._host = None
    client.init_identity()
    client.crypto_key = defaults.get("crypto_key")
    client.allow_self_signed = True
    client.share_bus = False
    client.handshake_event = Event()
    client.compress = True
    client.binarize = True

    client._broker_host = defaults["broker_host"]
    client._broker_port = defaults["broker_port"]
    client._hub_id = defaults.get("hub_id", "hivemind-hub")
    client._topic_prefix = defaults.get("topic_prefix", "hivemind")
    client._qos = defaults.get("qos", 1)
    client._tls = False
    client._tls_ca_certs = None
    client._tls_certfile = None
    client._tls_keyfile = None
    client._broker_username = None
    client._broker_password = None

    client._mqtt = MagicMock()
    client.internal_bus = defaults["internal_bus"]
    client.session_id = "test-session-id"
    client.stopped = Event()
    client.connected = Event()
    client._handlers = {}
    client._agent_handlers = {}
    client.protocol = MagicMock()
    client.protocol.binarize = False
    return client


# ---------------------------------------------------------------------------
# Topic scheme
# ---------------------------------------------------------------------------

class TestTopicScheme(unittest.TestCase):
    def setUp(self):
        self.client = _make_client()

    def test_c2s_topic(self):
        self.assertEqual(
            self.client._c2s_topic(),
            "hivemind/test-hub/c2s/test-access-key",
        )

    def test_s2c_topic(self):
        self.assertEqual(
            self.client._s2c_topic(),
            "hivemind/test-hub/s2c/test-access-key",
        )

    def test_status_topic(self):
        self.assertEqual(
            self.client._status_topic(),
            "hivemind/test-hub/status/test-access-key",
        )

    def test_satellite_id_equals_access_key(self):
        self.assertEqual(self.client._satellite_id, "test-access-key")


# ---------------------------------------------------------------------------
# on_connect callback
# ---------------------------------------------------------------------------

class TestOnConnect(unittest.TestCase):
    def test_on_connect_subscribes_s2c_and_publishes_online(self):
        client = _make_client()
        mock_mqtt = MagicMock()
        client._on_mqtt_connect(mock_mqtt, None, None, rc=0)

        mock_mqtt.subscribe.assert_called_once_with(
            "hivemind/test-hub/s2c/test-access-key", qos=1
        )
        mock_mqtt.publish.assert_called_once_with(
            "hivemind/test-hub/status/test-access-key", "online", qos=1, retain=True
        )
        self.assertTrue(client.connected.is_set())

    def test_on_connect_rc_nonzero_does_not_set_connected(self):
        client = _make_client()
        mock_mqtt = MagicMock()
        client._on_mqtt_connect(mock_mqtt, None, None, rc=1)
        self.assertFalse(client.connected.is_set())


# ---------------------------------------------------------------------------
# emit — publishes to c2s topic
# ---------------------------------------------------------------------------

class TestEmit(unittest.TestCase):
    def test_emit_publishes_to_c2s_topic(self):
        client = _make_client()
        client.connected.set()

        msg = HiveMessage(HiveMessageType.BUS, Message("speak", {"utterance": "hi"}))
        client.emit(msg)

        client._mqtt.publish.assert_called()
        topic = client._mqtt.publish.call_args[0][0]
        self.assertEqual(topic, "hivemind/test-hub/c2s/test-access-key")

    def test_emit_raises_if_not_connected(self):
        client = _make_client()
        msg = HiveMessage(HiveMessageType.BUS, Message("speak", {}))
        with self.assertRaises(ConnectionAbortedError):
            client.emit(msg)

    def test_emit_wraps_mycroft_message(self):
        client = _make_client()
        client.connected.set()

        mycroft_msg = Message("speak", {"utterance": "hello"})
        client.emit(mycroft_msg)

        client._mqtt.publish.assert_called()
        topic = client._mqtt.publish.call_args[0][0]
        self.assertEqual(topic, "hivemind/test-hub/c2s/test-access-key")


# ---------------------------------------------------------------------------
# Inbound message routing through _handle_hive_protocol
# ---------------------------------------------------------------------------

class TestInboundRouting(unittest.TestCase):
    def _mqtt_msg(self, payload: str):
        """Simulate a paho MQTTMessage."""
        msg = MagicMock()
        msg.topic = "hivemind/test-hub/s2c/test-access-key"
        msg.payload = payload.encode("utf-8")
        return msg

    def test_handshake_message_routed_to_protocol(self):
        client = _make_client()
        hm_msg = HiveMessage(HiveMessageType.HANDSHAKE, {"binarize": False})
        raw = json.dumps(hm_msg.serialize())

        client._on_mqtt_message(MagicMock(), None, self._mqtt_msg(raw))

        client.protocol.handle_handshake.assert_called_once()

    def test_bus_message_routed_to_protocol(self):
        client = _make_client()
        inner = Message("speak", {"utterance": "hello"})
        hm_msg = HiveMessage(HiveMessageType.BUS, inner)
        raw = json.dumps(hm_msg.serialize())

        client._on_mqtt_message(MagicMock(), None, self._mqtt_msg(raw))

        client.protocol.handle_bus.assert_called_once()

    def test_hello_message_routed_to_protocol(self):
        client = _make_client()
        hm_msg = HiveMessage(HiveMessageType.HELLO, {"node_id": "hub-node"})
        raw = json.dumps(hm_msg.serialize())

        client._on_mqtt_message(MagicMock(), None, self._mqtt_msg(raw))

        client.protocol.handle_hello.assert_called_once()


# ---------------------------------------------------------------------------
# LWT / close
# ---------------------------------------------------------------------------

class TestLWTAndClose(unittest.TestCase):
    def test_close_publishes_offline(self):
        client = _make_client()
        client.connected.set()

        client._do_disconnect()

        publish_calls = client._mqtt.publish.call_args_list
        offline_calls = [
            c for c in publish_calls
            if c[0][1] == "offline"
        ]
        self.assertTrue(len(offline_calls) >= 1)
        # Verify topic
        self.assertEqual(
            offline_calls[0][0][0],
            "hivemind/test-hub/status/test-access-key",
        )

    def test_close_clears_connected_and_handshake(self):
        client = _make_client()
        client.connected.set()
        client.handshake_event.set()

        client._do_disconnect()

        self.assertFalse(client.connected.is_set())
        self.assertFalse(client.handshake_event.is_set())

    def test_close_calls_loop_stop(self):
        client = _make_client()
        client._do_disconnect()
        client._mqtt.loop_stop.assert_called_once()


# ---------------------------------------------------------------------------
# Handler registration
# ---------------------------------------------------------------------------

class TestHandlerRegistration(unittest.TestCase):
    def test_on_registers_handler(self):
        client = _make_client()
        fn = MagicMock()
        client.on(HiveMessageType.BUS, fn)
        self.assertIn(fn, client._handlers[HiveMessageType.BUS])

    def test_on_mycroft_registers_handler(self):
        client = _make_client()
        fn = MagicMock()
        client.on_mycroft("speak", fn)
        self.assertIn(fn, client._agent_handlers["speak"])

    def test_remove_deregisters_handler(self):
        client = _make_client()
        fn = MagicMock()
        client.on(HiveMessageType.BUS, fn)
        client.remove(HiveMessageType.BUS, fn)
        self.assertNotIn(fn, client._handlers.get(HiveMessageType.BUS, []))


if __name__ == "__main__":
    unittest.main()
