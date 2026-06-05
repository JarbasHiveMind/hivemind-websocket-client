import random

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from ovos_bus_client import Message as MycroftMessage
from ovos_bus_client import MessageBusClient
from ovos_bus_client.message import Message
from ovos_bus_client.session import Session, SessionManager
from ovos_utils.log import LOG

from hivemind_bus_client.client import HiveMessageBusClient
from hivemind_bus_client.encryption import SupportedEncodings, SupportedCiphers, optimal_ciphers, hybrid_decrypt
from hivemind_bus_client.hive_map import HiveMapper
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from poorman_handshake import HandShake, PasswordHandShake
from poorman_handshake.asymmetric.utils import load_RSA_key


class CascadeAggregator:
    """Collects CASCADE responses over a timeout window, then selects the best.

    When the first response arrives a timer starts. Subsequent responses are
    buffered until the timer expires **or** ``expected_responses`` have been
    collected (whichever comes first), at which point ``select_callback``
    picks the winner and ``emit_callback`` delivers it.

    Args:
        timeout: Seconds to wait after the first response before resolving.
        select_callback: ``(List[HiveMessage]) -> Optional[HiveMessage]`` chooser.
        emit_callback: Called with the selected message to deliver it.
        expected_responses: If set, resolve early once this many responses arrive.
    """

    def __init__(self, timeout: float,
                 select_callback: Callable[[List[HiveMessage]], Optional[HiveMessage]],
                 emit_callback: Callable[[HiveMessage], None],
                 expected_responses: Optional[int] = None) -> None:

        self.timeout = timeout
        self.select_callback = select_callback or random.choice
        self.emit_callback = emit_callback
        self.expected_responses = expected_responses
        self.responses: List[HiveMessage] = []
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()
        self._resolved = False

    def add_response(self, message: HiveMessage) -> None:
        """Buffer a response and start the timer on the first one.

        Resolves early if ``expected_responses`` have been collected.

        Args:
            message: A CASCADE response HiveMessage.
        """
        with self._lock:
            if self._resolved:
                return
            self.responses.append(message)
            if self._timer is None:
                self._timer = threading.Timer(self.timeout, self._resolve)
                self._timer.daemon = True
                self._timer.start()
            # early resolution when all expected responses have arrived
            if (self.expected_responses is not None
                    and len(self.responses) >= self.expected_responses):
                if self._timer is not None:
                    self._timer.cancel()
                self._do_resolve()
                return

    def _resolve(self) -> None:
        """Timer callback — resolve under lock."""
        with self._lock:
            self._do_resolve()

    def _do_resolve(self) -> None:
        """Select the best response and emit it.  Caller must hold ``_lock``."""
        if self._resolved:
            return
        self._resolved = True
        responses = self.responses
        self.responses = []
        self._timer = None
        if responses:
            selected = self.select_callback(responses)
            if selected is not None:
                self.emit_callback(selected)

    def cancel(self) -> None:
        """Cancel the pending timer without emitting."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            self.responses = []
            self._resolved = True


@dataclass()
class HiveMindSlaveInternalProtocol:
    """ this class handles all interactions between a hivemind listener and a ovos-core messagebus"""
    hm_bus: HiveMessageBusClient
    share_bus: bool = False
    bus: Optional[MessageBusClient] = None
    node_id: str = ""  # this is how ovos-core bus refers to this slave's master

    def register_bus_handlers(self):
        self.bus.on("hive.send.upstream", self.handle_send) # meant for internal usage by agent protocol plugins
        self.bus.on("message", self.handle_outgoing_mycroft)  # catch all

    # mycroft handlers  - from slave -> master
    def handle_send(self, message: Message):
        """ ovos wants to send a HiveMessage

        a device can be both a master and a slave, upstream messages are handled here

        HiveMindListenerInternalProtocol will handle requests meant to go downstream
        """

        payload = message.data.get("payload")
        msg_type = message.data["msg_type"]

        hmessage = HiveMessage(msg_type, payload=payload)

        if msg_type == HiveMessageType.BROADCAST:
            # only masters can broadcast, ignore silently
            #   if this device is also a master to something,
            #   HiveMindListenerInternalProtocol will handle the request
            pass
        else:
            self.hm_bus.emit(hmessage)

    def handle_outgoing_mycroft(self, message: Message):
        """ forward internal messages to masters"""
        if isinstance(message, str):
            # "message" is a special case in ovos-bus-client that is not deserialized
            message = Message.deserialize(message)

        # this allows the master node to do passive monitoring of bus events
        if self.share_bus:
            msg = HiveMessage(HiveMessageType.SHARED_BUS,
                              payload=message.serialize())
            self.hm_bus.emit(msg)

        # this message is targeted at master
        # eg, a response to some bus event injected by master
        # note: master might completely ignore it
        peers = message.context.get("destination")
        if peers:
            if not isinstance(peers, list):
                peers = [peers]
            if self.node_id in peers:
                msg = HiveMessage(HiveMessageType.BUS,
                                  payload=message.serialize())
                self.hm_bus.emit(msg)


@dataclass()
class HiveMindSlaveProtocol:
    """
    Joins this instance ovos-core bus with master ovos-core bus
    Master becomes able to inject arbitrary bus messages
    """
    hm: HiveMessageBusClient
    identity: Optional[NodeIdentity] = None
    handshake: Optional[HandShake] = None
    pswd_handshake: Optional[PasswordHandShake] = None
    internal_protocol: HiveMindSlaveInternalProtocol = None
    mpubkey: str = ""  # asc public PGP key from master
    shared_bus: bool = False
    binarize: bool = False
    site_id: str = "unknown"
    cascade_timeout: float = 5.0
    cascade_select_callback: Optional[Callable[[List[HiveMessage]], Optional[HiveMessage]]] = None
    hive_mapper: Optional[HiveMapper] = None
    cascade_aggregator: Optional[CascadeAggregator] = field(default=None, repr=False)

    def bind(self, bus: Optional[MessageBusClient] = None):
        if self.identity is None:
            self.identity = self.hm.identity or NodeIdentity()
        self.handshake = HandShake(self.identity.private_key)
        self.pswd_handshake = PasswordHandShake(self.identity.password) if self.identity.password else None

        if bus is None:
            bus = MessageBusClient()
            bus.run_in_thread()
            bus.connected_event.wait()
        LOG.info("Initializing HiveMindSlaveInternalProtocol")
        self.internal_protocol = HiveMindSlaveInternalProtocol(bus=bus, hm_bus=self.hm)
        self.internal_protocol.register_bus_handlers()
        LOG.info("registering protocol handlers")
        self.hm.on(HiveMessageType.HELLO, self.handle_hello)
        self.hm.on(HiveMessageType.BROADCAST, self.handle_broadcast)
        self.hm.on(HiveMessageType.PROPAGATE, self.handle_propagate)
        self.hm.on(HiveMessageType.INTERCOM, self.handle_intercom)
        self.hm.on(HiveMessageType.ESCALATE, self.handle_illegal_msg)
        self.hm.on(HiveMessageType.SHARED_BUS, self.handle_illegal_msg)
        self.hm.on(HiveMessageType.QUERY, self.handle_query)
        self.hm.on(HiveMessageType.CASCADE, self.handle_cascade)
        self.hm.on(HiveMessageType.BUS, self.handle_bus)
        self.hm.on(HiveMessageType.HANDSHAKE, self.handle_handshake)

    @property
    def node_id(self):
        # this is how ovos-core bus refers to this slave's master
        return self.internal_protocol.node_id

    # hivemind events
    def handle_illegal_msg(self, message: HiveMessage):
        # this should not happen,
        # only sent from client -> server NOT server -> client
        # TODO log, kill connection (?)
        LOG.warning(f"illegal message {message}")

    def handle_hello(self, message: HiveMessage):
        # this check is because other nodes in the hive
        # may also send HELLO with their pubkey
        # only want this on the first connection
        LOG.info(f"HELLO: {message.payload}")
        assert message.msg_type == HiveMessageType.HELLO
        if not self.node_id:
            self.mpubkey = message.payload.get("pubkey")
            node_id = message.payload.get("node_id", "")
            self.internal_protocol.node_id = node_id
            LOG.info(f"Connected to HiveMind: {node_id}")

    def start_handshake(self):
        if self.binarize:
            LOG.info("hivemind supports binarization protocol")
        else:
            LOG.info("hivemind does not support binarization protocol")

        payload = {"binarize": self.binarize,
                   "encodings": list(SupportedEncodings),
                   "ciphers": optimal_ciphers()}
        if self.pswd_handshake is not None:
            payload["envelope"] = self.pswd_handshake.generate_handshake()
        else:
            payload["pubkey"] = self.handshake.pubkey

        self.hm.emit(HiveMessage(HiveMessageType.HANDSHAKE, payload))

    def receive_handshake(self, envelope):
        if self.pswd_handshake is not None:
            LOG.info("Received password envelope")
            self.pswd_handshake.receive_and_verify(envelope)  # validate master password matched
            self.hm.crypto_key = self.pswd_handshake.secret  # update to new crypto key
        else:
            LOG.info("Received pubkey envelope")
            # if we have a pubkey let's verify the master node is who it claims to be
            # currently this is sent in HELLO, but advance use cases can read it from somewhere else
            if self.mpubkey:
                # authenticates the server to the client
                self.handshake.receive_and_verify(envelope, self.mpubkey)
            else:
                # implicitly trust the server
                self.handshake.receive_handshake(envelope)
            self.hm.crypto_key = self.handshake.secret  # update to new crypto key

        # now that communication is secure, send our Session data and other personal info
        sess = Session(self.hm.session_id)
        msg = HiveMessage(HiveMessageType.HELLO, {"pubkey": self.identity.public_key,
                                                  "session": sess.serialize(),
                                                  "site_id": self.site_id})
        self.hm.emit(msg)
        self.hm.handshake_event.set()

    def handle_handshake(self, message: HiveMessage):
        LOG.info(f"HANDSHAKE: {message.payload}")
        assert message.msg_type == HiveMessageType.HANDSHAKE
        # master is performing the handshake
        if "envelope" in message.payload:
            envelope = message.payload["envelope"]
            self.hm.json_encoding = message.payload.get("encoding") or SupportedEncodings.JSON_HEX
            self.hm.cipher = message.payload.get("cipher") or SupportedCiphers.AES_GCM
            self.receive_handshake(envelope)
            LOG.debug(f"Encoding: {self.hm.json_encoding}")
            LOG.debug(f"Cipher: {self.hm.cipher}")
            LOG.debug(f"Key size: {len(self.pswd_handshake.secret) * 8}bit")

        # master is requesting handshake start
        else:
            # required = message.payload.get("handshake")
            # if not required:
            #    self.hm.handshake_event.set()  # don't wait
            #    return

            encodings = message.payload.get("encodings") or [SupportedEncodings.JSON_HEX]
            ciphers = message.payload.get("ciphers") or [SupportedCiphers.AES_GCM]
            LOG.debug(f"Server supported encodings: {encodings}")
            LOG.debug(f"Server supported ciphers: {ciphers}")
            if message.payload.get("crypto_key") and self.hm.crypto_key:
                pass
                # we can use the pre-shared key instead of handshake
                # TODO - flag to give preference to pre-shared key over handshake

            self.binarize = message.payload.get("binarize", False)
            # TODO - flag to give preference to / require password or use RSA handshake
            # currently if password is set then it is always used
            if message.payload.get("password") and self.identity.password:
                self.pswd_handshake = PasswordHandShake(self.identity.password)
                self.start_handshake()

    def _is_source_trusted(self, message: HiveMessage) -> bool:
        """Check if the message originates from a trusted peer.

        Checks the message's source_peer against the HiveMapper's trust
        data (populated from ``NodeIdentity.trusted_keys`` via
        ``HiveMapper.mark_trusted_nodes``).  Also checks the identity's
        trusted keys directly against any public key in the route.

        Args:
            message: The HiveMessage to check.

        Returns:
            True if the source peer is trusted.
        """
        # check HiveMapper trust data first (fast path)
        if self.hive_mapper and message.source_peer:
            if self.hive_mapper.is_peer_trusted(message.source_peer):
                return True
        # fallback: check route for any known trusted public key
        if self.identity:
            for hop in message.route:
                source = hop.get("source", "")
                if self.hive_mapper:
                    node = self.hive_mapper.nodes.get(source)
                    if node and node.public_key and self.identity.is_trusted_key(node.public_key):
                        return True
        return False

    def handle_bus(self, message: HiveMessage):
        """Dispatch event to the agent protocol bus"""
        assert message.msg_type == HiveMessageType.BUS
        assert isinstance(message.payload, MycroftMessage)
        LOG.info(f"BUS: {message.payload.msg_type}")
        # master wants to inject message into mycroft bus
        pload = message.payload

        # update session sent from hivemind-core
        sess = Session.from_message(pload)
        if sess.session_id == self.hm.session_id:
            sess.site_id = self.site_id  # do not allow overwriting site_id
        SessionManager.update(sess)

        # from this point on, it should be a native source and execute audio
        if "destination" in pload.context:
            pload.context["source"] = pload.context.pop("destination")
        self.internal_protocol.bus.emit(pload)

    def handle_broadcast(self, message: HiveMessage):
        """Handle a BROADCAST message received from the master.

        By definition all messages from masters are trusted

        Args:
            message: The BROADCAST HiveMessage.
        """
        LOG.info(f"BROADCAST: {message.payload}")
        assert message.msg_type == HiveMessageType.BROADCAST
        assert message.payload.msg_type in [HiveMessageType.BUS, HiveMessageType.INTERCOM]

        if message.payload.msg_type == HiveMessageType.INTERCOM:
            self.handle_intercom(message.payload)
        elif message.payload.msg_type == HiveMessageType.BUS:
            # if the message targets our site_id, send it to internal bus
            site = message.target_site_id
            if site and site == self.site_id:
                # always trusted, comes from a master, never from other satellite
                self.handle_bus(message.payload)

    def handle_propagate(self, message: HiveMessage):
        """Handle a PROPAGATE message (bidirectional flood).

        BUS payloads are only injected if the source peer is trusted
        (via ``NodeIdentity.trusted_keys``).  Untrusted BUS payloads
        are silently dropped to prevent cross-satellite injection.

        Args:
            message: The PROPAGATE HiveMessage.
        """
        LOG.info(f"PROPAGATE: {message.payload}")
        assert message.msg_type == HiveMessageType.PROPAGATE
        assert message.payload.msg_type in [HiveMessageType.BUS,
                                            HiveMessageType.INTERCOM,
                                            HiveMessageType.PING]
        if message.payload.msg_type == HiveMessageType.INTERCOM:
            self.handle_intercom(message.payload)
        elif message.payload.msg_type == HiveMessageType.PING:
            self.handle_ping(message.payload)
        elif message.payload.msg_type == HiveMessageType.BUS:
            site = message.target_site_id
            if site and site == self.site_id:
                if self._is_source_trusted(message):
                    self.handle_bus(message.payload)
                else:
                    LOG.warning(f"Dropping untrusted PROPAGATE(BUS) from {message.source_peer}")

    def handle_ping(self, message: HiveMessage):
        """Handle a received PROPAGATE(PING) using flood-based discovery.

        If this ``flood_id`` has not been seen before, builds and sends
        this node's own responsive PING (same ``flood_id``) upstream.

        Args:
            message: The outer PROPAGATE HiveMessage whose inner payload is a PING.
        """
        assert message.msg_type == HiveMessageType.PING
        ping_payload = message.payload if isinstance(message.payload, dict) else {}

        flood_id = ping_payload.get("flood_id", "")

        # Lazy init for tests / callers that don't set hive_mapper
        if self.hive_mapper is None:
            self.hive_mapper = HiveMapper()

        # Flood-loop prevention — delegated to HiveMapper
        if self.hive_mapper.check_flood_id(flood_id):
            return

        # Build our own responsive PING with the same flood_id
        peer = f"{self.identity.name or 'satellite'}::{self.hm.session_id}"
        # announce lang from active session if available
        sess = SessionManager.default_session
        lang = getattr(sess, "lang", None) if sess else None

        own_ping_payload = {
            "flood_id": flood_id,
            "peer": peer,
            "site_id": self.site_id,
            "timestamp": time.time(),
            "public_key": self.identity.public_key,
            "lang": lang,
        }
        own_ping_inner = HiveMessage(HiveMessageType.PING, own_ping_payload)
        own_ping_outer = HiveMessage(HiveMessageType.PROPAGATE, payload=own_ping_inner)

        LOG.debug(f"Sending responsive PING for flood_id={flood_id}")
        self.hm.emit(own_ping_outer)

    def handle_query(self, message: HiveMessage):
        """Handle a QUERY message received from the master.

        By definition all responses from masters are trusted

        Args:
            message: The QUERY HiveMessage.
        """
        LOG.info(f"QUERY: {message.payload}")
        assert message.msg_type == HiveMessageType.QUERY
        assert message.payload.msg_type in [HiveMessageType.BUS, HiveMessageType.INTERCOM]
        if message.payload.msg_type == HiveMessageType.INTERCOM:
            # using INTERCOM allows end2end privacy, nodes along the chain can't read responses
            self.handle_intercom(message)
        elif message.payload.msg_type == HiveMessageType.BUS:
            # the QUERY wraps an inner BUS HiveMessage; emit that, not the wrapper
            self.handle_bus(message.payload)

    def handle_cascade(self, message: HiveMessage):
        """Handle a CASCADE response received from the master.

        Unlike QUERY we may receive untrusted responses from all across the hive

        Responses are buffered in a ``CascadeAggregator``. After
        ``cascade_timeout`` seconds the ``cascade_select_callback``
        picks the best response and it is emitted on the internal bus.

        Args:
            message: The CASCADE HiveMessage.
        """
        LOG.info(f"CASCADE: {message.payload}")
        assert message.msg_type == HiveMessageType.CASCADE
        assert message.payload.msg_type == HiveMessageType.BUS

        # using INTERCOM allows end2end privacy, nodes along the chain can't read responses
        if self.cascade_aggregator is None or self.cascade_aggregator._resolved:
            select_cb = self.cascade_select_callback or random.choice
            expected = len(self.hive_mapper.nodes) if self.hive_mapper else None
            self.cascade_aggregator = CascadeAggregator(
                timeout=self.cascade_timeout,
                select_callback=select_cb,
                emit_callback=self.handle_bus,
                expected_responses=expected,
            )
        self.cascade_aggregator.add_response(message)

    def handle_intercom(self, message: HiveMessage):
        """Handle an INTERCOM (end-to-end encrypted) message.

        Decrypts the payload if it contains a ciphertext envelope,
        then injects the inner BUS message only if:
        - The message is explicitly targeted at us (target_public_key matches), OR
        - The source peer is in the trusted keys list.

        Untrusted, non-targeted INTERCOM messages are silently dropped.

        Args:
            message: The INTERCOM HiveMessage.
        """
        LOG.info(f"INTERCOM: {message.payload}")
        assert message.msg_type == HiveMessageType.INTERCOM
        assert message.payload.msg_type == HiveMessageType.BUS

        k = message.target_public_key
        if k and k != self.identity.public_key:
            # explicitly targeted at someone else — not for us
            return False

        pload = message.payload
        if isinstance(pload, dict) and "encrypted_key" in pload:
            # hybrid encryption envelope (AES key RSA-encrypted)
            try:
                private_key = load_RSA_key(self.identity.private_key)
                decrypted = hybrid_decrypt(private_key, pload).decode("utf-8")
                message._payload = HiveMessage.deserialize(decrypted)
            except Exception as e:
                if k:
                    LOG.error("failed to decrypt INTERCOM message!")
                else:
                    LOG.debug("failed to decrypt INTERCOM, not for us")
                return False

        # explicitly targeted at us → always trust
        if k and k == self.identity.public_key:
            self.handle_bus(message)
            return True

        # not targeted — only inject if source is trusted
        if self._is_source_trusted(message):
            self.handle_bus(message)
            return True

        LOG.warning(f"Dropping untrusted INTERCOM from {message.source_peer}")
        return False
