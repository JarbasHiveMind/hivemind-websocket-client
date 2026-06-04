import json
import threading
import time
from typing import Dict, List, Callable, Union, Optional

import pybase64
import paho.mqtt.client as mqtt
from Cryptodome.PublicKey import RSA
from ovos_bus_client import Message as MycroftMessage, MessageBusClient as OVOSBusClient
from ovos_bus_client.session import Session
from ovos_utils.fakebus import FakeBus
from ovos_utils.log import LOG

from hivemind_bus_client.client import BinaryDataCallbacks
from hivemind_bus_client.encryption import (
    encrypt_as_json, decrypt_from_json, encrypt_bin, decrypt_bin,
    SupportedEncodings, SupportedCiphers,
)
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType, HiveMindBinaryPayloadType
from hivemind_bus_client.protocol import HiveMindSlaveProtocol
from hivemind_bus_client.serialization import get_bitstring, decode_bitstring
from hivemind_bus_client.util import serialize_message
from poorman_handshake.asymmetric.utils import encrypt_RSA, load_RSA_key, sign_RSA

_ONLINE = "online"
_OFFLINE = "offline"


class HiveMindMQTTClient(threading.Thread):
    """
    A client for the HiveMind MQTT transport protocol.

    Mirrors HiveMindHTTPClient exactly — only the transport layer (MQTT
    publish/subscribe) differs from the HTTP polling or WebSocket push model.

    Topic scheme (must match hivemind-mqtt-protocol hub-side):
        <prefix>/<hub_id>/c2s/<satellite_id>   satellite → hub  (publish)
        <prefix>/<hub_id>/s2c/<satellite_id>   hub → satellite  (subscribe)
        <prefix>/<hub_id>/status/<satellite_id> LWT / presence

    The satellite_id is the HiveMind access key (MQTT username).  The MQTT
    payload is the same encrypted HiveMessage frame used by ws/http transports.
    """

    def __init__(
        self,
        key: Optional[str] = None,
        password: Optional[str] = None,
        crypto_key: Optional[str] = None,
        host: Optional[str] = None,
        port: Optional[int] = None,
        useragent: str = "HiveMindMQTTClientV1.0",
        self_signed: bool = True,
        share_bus: bool = False,
        compress: bool = True,
        binarize: bool = True,
        identity: NodeIdentity = None,
        internal_bus: Optional[OVOSBusClient] = None,
        bin_callbacks: BinaryDataCallbacks = None,
        # MQTT-specific
        broker_host: str = "localhost",
        broker_port: int = 1883,
        hub_id: Optional[str] = None,
        topic_prefix: str = "hivemind",
        qos: int = 1,
        tls: bool = False,
        tls_ca_certs: Optional[str] = None,
        tls_certfile: Optional[str] = None,
        tls_keyfile: Optional[str] = None,
        broker_username: Optional[str] = None,
        broker_password: Optional[str] = None,
    ):
        super().__init__(daemon=True)
        self.bin_callbacks = bin_callbacks or BinaryDataCallbacks()
        self.json_encoding = SupportedEncodings.JSON_HEX
        self.cipher = SupportedCiphers.AES_GCM
        self.server_key: Optional[str] = None
        self.identity = identity or None
        self._password = password
        self._access_key = key
        self._name = useragent
        self._port = port
        self._host = host
        self.init_identity()
        self.crypto_key = crypto_key
        self.allow_self_signed = self_signed
        self.share_bus = share_bus
        self.handshake_event = threading.Event()
        self.compress = compress
        self.binarize = binarize

        # MQTT transport config
        self._broker_host = broker_host
        self._broker_port = broker_port
        self._hub_id = hub_id  # resolved lazily in connect() if None
        self._topic_prefix = topic_prefix
        self._qos = qos
        self._tls = tls
        self._tls_ca_certs = tls_ca_certs
        self._tls_certfile = tls_certfile
        self._tls_keyfile = tls_keyfile
        self._broker_username = broker_username
        self._broker_password = broker_password

        self._mqtt: Optional[mqtt.Client] = None

        if not internal_bus:
            sess = Session()
            self.internal_bus = FakeBus(session=sess)
        else:
            sess = Session(session_id=internal_bus.session_id)
            self.internal_bus = internal_bus
        LOG.info(f"Session ID: {sess.session_id}")
        self.session_id = sess.session_id
        self.stopped = threading.Event()
        self.connected = threading.Event()
        self._handlers: Dict[str, List[Callable[[HiveMessage], None]]] = {}
        self._agent_handlers: Dict[str, List[Callable[[MycroftMessage], None]]] = {}
        self.start()

    # ------------------------------------------------------------------
    # Topic helpers (mirror the hub plugin exactly)
    # ------------------------------------------------------------------

    @property
    def _satellite_id(self) -> str:
        """satellite_id == MQTT username == HiveMind access key."""
        return self.key

    def _c2s_topic(self) -> str:
        return f"{self._topic_prefix}/{self._hub_id}/c2s/{self._satellite_id}"

    def _s2c_topic(self) -> str:
        return f"{self._topic_prefix}/{self._hub_id}/s2c/{self._satellite_id}"

    def _status_topic(self) -> str:
        return f"{self._topic_prefix}/{self._hub_id}/status/{self._satellite_id}"

    # ------------------------------------------------------------------
    # Identity helpers (mirrored from HiveMindHTTPClient)
    # ------------------------------------------------------------------

    def wait_for_handshake(self, timeout=5):
        self.handshake_event.wait(timeout=timeout)
        if not self.handshake_event.is_set():
            self.protocol.start_handshake()
            self.wait_for_handshake()
        time.sleep(1)

    @property
    def useragent(self) -> str:
        return self.identity.name

    @useragent.setter
    def useragent(self, val):
        self.identity.name = val

    @property
    def password(self) -> str:
        return self.identity.password

    @property
    def key(self) -> str:
        return self.identity.access_key

    @property
    def site_id(self) -> str:
        return self.identity.site_id

    @site_id.setter
    def site_id(self, val):
        self.identity.site_id = val

    @password.setter
    def password(self, val):
        self.identity.password = val

    @key.setter
    def key(self, val):
        self.identity.access_key = val

    def init_identity(self, site_id=None):
        self.identity = self.identity or NodeIdentity()
        self.identity.password = self._password or self.identity.password
        self.identity.access_key = self._access_key or self.identity.access_key
        self.identity.default_master = self._host = self._host or self.identity.default_master
        self.identity.default_port = self._port = self._port or self.identity.default_port
        self.identity.name = self._name or "HiveMessageBusClientV0.0.1"
        self.identity.site_id = site_id or self.identity.site_id

        if not self.identity.access_key or not self.identity.password:
            raise RuntimeError(
                "NodeIdentity not set, please pass key and password or "
                "call 'hivemind-client set-identity'"
            )

    # ------------------------------------------------------------------
    # Inbound message handling (identical to HiveMindHTTPClient)
    # ------------------------------------------------------------------

    def on_message(self, message: Union[bytes, str]):
        if self.crypto_key:
            if isinstance(message, bytes):
                message = decrypt_bin(self.crypto_key, message, cipher=self.cipher)
            elif "ciphertext" in message:
                message = decrypt_from_json(
                    self.crypto_key, message, cipher=self.cipher, encoding=self.json_encoding
                )
            else:
                LOG.debug("Message was unencrypted")

        if isinstance(message, bytes):
            message = decode_bitstring(message)
        elif isinstance(message, str):
            message = json.loads(message)
        if isinstance(message, dict) and "ciphertext" in message:
            LOG.error("got encrypted message, but could not decrypt!")
            return

        if isinstance(message, HiveMessage) and message.msg_type == HiveMessageType.BINARY:
            self._handle_binary(message)
            return

        if isinstance(message, HiveMessage):
            self._handle_hive_protocol(message)
        elif isinstance(message, str):
            self._handle_hive_protocol(HiveMessage(**json.loads(message)))
        else:
            assert isinstance(message, dict)
            self._handle_hive_protocol(HiveMessage(**message))

    def _handle_binary(self, message: HiveMessage):
        assert message.msg_type == HiveMessageType.BINARY
        bin_data = message.payload
        LOG.debug(f"Got binary data of type: {message.bin_type}")
        if message.bin_type == HiveMindBinaryPayloadType.TTS_AUDIO:
            lang = message.metadata.get("lang")
            utt = message.metadata.get("utterance")
            file_name = message.metadata.get("file_name")
            try:
                self.bin_callbacks.handle_receive_tts(bin_data, utt, lang, file_name)
            except Exception:
                LOG.exception("Error in binary callback: handle_receive_tts")
        elif message.bin_type == HiveMindBinaryPayloadType.FILE:
            file_name = message.metadata.get("file_name")
            try:
                self.bin_callbacks.handle_receive_file(bin_data, file_name)
            except Exception:
                LOG.exception("Error in binary callback: handle_receive_file")
        else:
            LOG.warning(f"Ignoring received untyped binary data: {len(bin_data)} bytes")

    def _handle_hive_protocol(self, message: HiveMessage):
        LOG.debug(f"received HiveMind message: {message}")
        if message.msg_type == HiveMessageType.HELLO:
            self.protocol.handle_hello(message)
        if message.msg_type == HiveMessageType.HANDSHAKE:
            self.protocol.handle_handshake(message)
        if message.msg_type == HiveMessageType.BUS:
            self.protocol.handle_bus(message)
        if message.msg_type == HiveMessageType.BROADCAST:
            self.protocol.handle_broadcast(message)
        if message.msg_type == HiveMessageType.PROPAGATE:
            self.protocol.handle_propagate(message)
        if message.msg_type == HiveMessageType.INTERCOM:
            self.protocol.handle_intercom(message)

        if message.msg_type in self._handlers:
            for handler in self._handlers[message.msg_type]:
                try:
                    handler(message)
                except Exception as e:
                    LOG.error(f"Error in message handler: {handler} - {e}")
        if message.msg_type == HiveMessageType.BUS and message.payload.msg_type in self._agent_handlers:
            for handler in self._agent_handlers[message.payload.msg_type]:
                try:
                    handler(message.payload)
                except Exception as e:
                    LOG.error(f"Error in agent message handler: {handler} - {e}")

        if message.msg_type == HiveMessageType.ESCALATE:
            self.protocol.handle_illegal_msg(message)
        if message.msg_type == HiveMessageType.SHARED_BUS:
            self.protocol.handle_illegal_msg(message)

    # ------------------------------------------------------------------
    # paho callbacks
    # ------------------------------------------------------------------

    def _on_mqtt_connect(self, client: mqtt.Client, userdata, flags, rc: int):
        if rc != 0:
            LOG.error(f"[MQTT] Broker connection failed, rc={rc}")
            return
        LOG.info("[MQTT] Connected to broker")
        # Subscribe to hub-to-satellite topic
        client.subscribe(self._s2c_topic(), qos=self._qos)
        # Publish online presence
        client.publish(self._status_topic(), _ONLINE, qos=1, retain=True)
        LOG.debug(f"[MQTT] Subscribed to {self._s2c_topic()}, published online to {self._status_topic()}")
        self.connected.set()

    def _on_mqtt_message(self, client: mqtt.Client, userdata, msg: mqtt.MQTTMessage):
        LOG.debug(f"[MQTT] inbound on {msg.topic}: {len(msg.payload)} bytes")
        try:
            payload = msg.payload
            # Try to decode as str (JSON frames); fall back to bytes (binary/encrypted)
            try:
                payload = payload.decode("utf-8")
            except (UnicodeDecodeError, AttributeError):
                pass
            self.on_message(payload)
        except Exception as e:
            LOG.error(f"[MQTT] Error processing inbound message: {e}")

    def _on_mqtt_disconnect(self, client: mqtt.Client, userdata, rc: int):
        if rc != 0:
            LOG.warning(f"[MQTT] Unexpected broker disconnect, rc={rc}")
        self.connected.clear()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self):
        self.stopped.clear()
        # Block until connect() sets up the MQTT client and connects
        self.connected.wait()
        # MQTT loop is driven in a background thread started by connect()
        while not self.stopped.is_set():
            self.stopped.wait(1)
        self._do_disconnect()

    def shutdown(self):
        self.stopped.set()

    # ------------------------------------------------------------------
    # User-facing API (mirrors HiveMindHTTPClient)
    # ------------------------------------------------------------------

    def on(self, event_name: str, func: Callable):
        if event_name not in self._handlers:
            self._handlers[event_name] = []
        self._handlers[event_name].append(func)

    def on_mycroft(self, event_name: str, func: Callable):
        if event_name not in self._agent_handlers:
            self._agent_handlers[event_name] = []
        self._agent_handlers[event_name].append(func)

    def remove(self, event_name: str, func: Callable):
        if event_name in self._handlers:
            self._handlers[event_name] = [h for h in self._handlers[event_name] if h is not func]

    def remove_mycroft(self, event_name: str, func: Callable):
        if event_name in self._agent_handlers:
            self._agent_handlers[event_name] = [
                h for h in self._agent_handlers[event_name] if h is not func
            ]

    def emit(
        self,
        message: Union[MycroftMessage, HiveMessage],
        binary_type: HiveMindBinaryPayloadType = HiveMindBinaryPayloadType.UNDEFINED,
    ):
        if not self.connected.is_set():
            raise ConnectionAbortedError("self.connect() needs to be called first!")
        if isinstance(message, MycroftMessage):
            message = HiveMessage(msg_type=HiveMessageType.BUS, payload=message)
        if message.msg_type == HiveMessageType.BUS:
            ctxt = dict(message.payload.context)
            if "source" not in ctxt:
                ctxt["source"] = self.useragent
            if "platform" not in message.payload.context:
                ctxt["platform"] = self.useragent
            if "destination" not in message.payload.context:
                ctxt["destination"] = "HiveMind"
            if "session" not in ctxt:
                ctxt["session"] = {}
            ctxt["session"]["session_id"] = self.session_id
            ctxt["session"]["site_id"] = self.site_id
            message.payload.context = ctxt

        LOG.debug(f"sending to HiveMind via MQTT: {message.msg_type}")
        binarize = False
        if message.msg_type == HiveMessageType.BINARY:
            binarize = True
        elif message.msg_type not in [HiveMessageType.HELLO, HiveMessageType.HANDSHAKE]:
            binarize = self.protocol.binarize and self.binarize

        if binarize:
            bitstr = get_bitstring(
                hive_type=message.msg_type,
                payload=message.payload,
                compressed=self.compress,
                binary_type=binary_type,
                hivemeta=message.metadata,
            )
            if self.crypto_key:
                payload = encrypt_bin(self.crypto_key, bitstr.bytes, cipher=self.cipher)
            else:
                payload = bitstr.bytes
        else:
            payload = serialize_message(message)
            if self.crypto_key:
                payload = encrypt_as_json(
                    self.crypto_key, payload, cipher=self.cipher, encoding=self.json_encoding
                )

        is_bin = isinstance(payload, bytes)
        qos = 0 if is_bin and message.msg_type == HiveMessageType.BINARY else self._qos
        self._mqtt.publish(self._c2s_topic(), payload, qos=qos)

    def emit_intercom(
        self,
        message: Union[MycroftMessage, HiveMessage],
        pubkey: Union[str, bytes, RSA.RsaKey],
    ):
        encrypted_message = encrypt_RSA(pubkey, message.serialize())
        private_key = load_RSA_key(self.identity.private_key)
        signature = sign_RSA(private_key, encrypted_message)
        self.emit(
            HiveMessage(
                HiveMessageType.INTERCOM,
                payload={
                    "ciphertext": pybase64.b64encode(encrypted_message),
                    "signature": pybase64.b64encode(signature),
                },
            )
        )

    # ------------------------------------------------------------------
    # MQTT transport lifecycle
    # ------------------------------------------------------------------

    def connect(self, bus=FakeBus(), protocol=None, site_id=None):
        LOG.info("[MQTT] Connecting...")
        self.identity.site_id = site_id or self.identity.site_id

        if protocol is None:
            LOG.debug("Initializing HiveMindSlaveProtocol")
            self.protocol = HiveMindSlaveProtocol(
                self,
                shared_bus=self.share_bus,
                site_id=self.identity.site_id or "unknown",
                identity=self.identity,
            )
        else:
            self.protocol = protocol
            self.protocol.identity = self.identity
            if self.identity.site_id is not None:
                self.protocol.site_id = self.identity.site_id

        self.protocol.bind(bus)

        # Default hub_id to "hivemind-hub" if not provided
        if self._hub_id is None:
            self._hub_id = "hivemind-hub"

        # Build paho client — satellite_id == access key
        client_id = f"hivemind-satellite-{self._satellite_id}"
        self._mqtt = mqtt.Client(client_id=client_id)

        # MQTT username = HiveMind access key (broker ACL key-off this)
        self._mqtt.username_pw_set(
            self._broker_username or self._satellite_id,
            self._broker_password or self.password,
        )

        if self._tls:
            self._mqtt.tls_set(
                ca_certs=self._tls_ca_certs,
                certfile=self._tls_certfile,
                keyfile=self._tls_keyfile,
            )

        # LWT — broker publishes offline if the client drops without clean disconnect
        self._mqtt.will_set(self._status_topic(), _OFFLINE, qos=1, retain=True)

        self._mqtt.on_connect = self._on_mqtt_connect
        self._mqtt.on_message = self._on_mqtt_message
        self._mqtt.on_disconnect = self._on_mqtt_disconnect

        self._mqtt.connect(self._broker_host, self._broker_port, keepalive=60)
        self._mqtt.loop_start()  # non-blocking paho loop in its own thread

        # Wait until on_connect fires and sets self.connected
        self.connected.wait(timeout=10)
        self.wait_for_handshake()

    def _do_disconnect(self):
        LOG.info("[MQTT] Disconnecting...")
        if self._mqtt is not None:
            self._mqtt.publish(self._status_topic(), _OFFLINE, qos=1, retain=True)
            self._mqtt.disconnect()
            self._mqtt.loop_stop()
        self.connected.clear()
        self.handshake_event.clear()

    def close(self):
        """Alias for shutdown + disconnect, mirroring websocket client surface."""
        self.stopped.set()
