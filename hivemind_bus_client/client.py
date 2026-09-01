import json
import random
import ssl
from collections.abc import Callable
from threading import Event, Lock, Thread, current_thread
from typing import Optional, Union

import pybase64
from Cryptodome.PublicKey import RSA
from ovos_bus_client import Message as MycroftMessage
from ovos_bus_client import MessageBusClient as OVOSBusClient
from ovos_bus_client.session import Session
from ovos_utils.fakebus import FakeBus
from ovos_utils.log import LOG
from poorman_handshake.asymmetric.utils import load_RSA_key
from pyee import EventEmitter
from websocket import ABNF, WebSocketApp, WebSocketConnectionClosedException

from hivemind_bus_client.encryption import (
    SupportedCiphers,
    SupportedEncodings,
    decrypt_bin,
    decrypt_from_json,
    encrypt_as_json,
    encrypt_bin,
    hybrid_encrypt,
)
from hivemind_bus_client.exceptions import MetadataTooLarge
from hivemind_bus_client.identity import NodeIdentity
from hivemind_bus_client.keepalive import websocket_keepalive_options
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.noise import NoiseTransportFailed
from hivemind_bus_client.serialization import (
    BINARY_ENCODABLE_TYPES,
    HiveMindBinaryPayloadType,
    decode_bitstring,
    get_bitstring,
)
from hivemind_bus_client.util import serialize_message


class BinaryDataCallbacks:
    def handle_receive_tts(self, bin_data: bytes,
                           utterance: str,
                           lang: str,
                           file_name: str):
        LOG.warning(f"Ignoring received binary TTS audio: {utterance} with {len(bin_data)} bytes")

    def handle_receive_file(self, bin_data: bytes,
                            file_name: str):
        LOG.warning(f"Ignoring received binary file: {file_name} with {len(bin_data)} bytes")


class HiveMessageWaiter:
    """Wait for a single message.

    Encapsulate the wait for a message logic separating the setup from
    the actual waiting act so the waiting can be setuo, actions can be
    performed and _then_ the message can be waited for.

    Arguments:
        bus: Bus to check for messages on
        message_type: message type to wait for
    """

    def __init__(self, bus: 'HiveMessageBusClient',
                 message_type: Union[HiveMessageType, str]):
        self.bus = bus
        self.msg_type = message_type
        self.received_msg = None
        # Setup response handler
        self.response_event = Event()
        self.bus.on(self.msg_type, self._handler)

    def _handler(self, message):
        """Receive response data."""
        self.received_msg = message
        self.response_event.set()

    def wait(self, timeout=3.0):
        """Wait for message.

        Arguments:
            timeout (int or float): seconds to wait for message

        Returns:
            HiveMessage or None
        """
        self.response_event.wait(timeout)
        self.bus.remove(self.msg_type, self._handler)
        return self.received_msg


class HivePayloadWaiter(HiveMessageWaiter):
    def __init__(self, bus: 'HiveMessageBusClient',
                 payload_type: Union[HiveMessageType, str],
                 message_type: Union[HiveMessageType, str] = HiveMessageType.BUS,
                 *args, **kwargs):
        super(HivePayloadWaiter, self).__init__(bus=bus, message_type=message_type,
                                                *args, **kwargs)
        self.payload_type = payload_type

    def _handler(self, message):
        """Receive response data."""
        if message.payload.msg_type == self.payload_type:
            super()._handler(message)


class HiveMessageBusClient(OVOSBusClient):
    # emit() grace window (seconds) for the "connection not currently open"
    # case. Kept short and non-configurable on purpose: it only exists to let
    # a send that races the final moments of a handshake still succeed. It is
    # NOT a retry/backoff knob - if the transport is actually down (eg. an
    # unreachable master) emit() must fail fast rather than block its caller,
    # since callers include event-loop code (see emit() docstring).
    _EMIT_NOT_CONNECTED_GRACE = 0.05

    def __init__(self, key: Optional[str] = None,
                 password: Optional[str] = None,
                 crypto_key: Optional[str] = None,
                 host: Optional[str] = None,
                 port: Optional[int] = None,
                 useragent: str = "",
                 self_signed: bool = True,
                 share_bus: bool = False,
                 compress: bool = True,
                 binarize: bool = True,
                 identity: NodeIdentity = None,
                 internal_bus: Optional[OVOSBusClient] = None,
                 bin_callbacks: BinaryDataCallbacks = BinaryDataCallbacks(),
                 websocket_ping_interval: Optional[float] = None,
                 websocket_ping_timeout: Optional[float] = None,
                 max_protocol_version: int = 3):
        self.bin_callbacks = bin_callbacks
        # highest HiveMind protocol version this client will negotiate
        # (HIVEMIND-WIRE-1 §2). 3 -> Noise handshake when the server also
        # supports it; servers capped at 2 or lower fall back to the legacy
        # handshake transparently. Set to 2 to force the legacy handshake.
        self.max_protocol_version = max_protocol_version
        # established protocol v3 Noise session (None on v2 and below)
        self.noise_transport = None
        self.json_encoding = SupportedEncodings.JSON_HEX  # server defaults before it was made configurable
        self.cipher = SupportedCiphers.AES_GCM  # server defaults before it was made configurable

        self.identity = identity or None
        self._password = password
        self._access_key = key
        self._name = useragent
        self._port = port
        self._host = host
        self._site_id = None
        self.init_identity()

        self.crypto_key = crypto_key
        self.allow_self_signed = self_signed
        self.share_bus = share_bus
        self.handshake_event = Event()
        self.protocol = None
        # Own the reconnect lifecycle here instead of relying on
        # ovos-bus-client's recursive on_error -> run_forever callback.  The
        # latter does not handle a clean websocket close and can leave the
        # worker thread dead while wait_for_handshake() waits forever.
        self._init_worker_lifecycle()
        self.websocket_ping_interval = websocket_ping_interval
        self.websocket_ping_timeout = websocket_ping_timeout

        # if you want to reduce CPU usage in exchange for more bandwidth set below to False
        self.compress = compress  # None -> auto
        self.binarize = binarize  # only if hivemind reports also supporting it

        # connect to OVOS, if on a OVOS device
        if not internal_bus:
            # FakeBus needed to send emitted events to handlers registered within the client
            sess = Session()  # new session for this client
            self.internal_bus = FakeBus(session=sess)
        else:
            sess = Session(session_id=internal_bus.session_id)
            self.internal_bus = internal_bus
        LOG.info(f"Session ID: {sess.session_id}")

        # NOTE: self._host and self._port accessed only after self.init_identity()
        # this allows them to come from set-identity cli command
        use_ssl = self._host.startswith("wss://")
        host = self._host.replace("ws://", "").replace("wss://", "").strip()
        super().__init__(host=host, port=self._port, ssl=use_ssl,
                         emitter=EventEmitter(), session=sess)

    def _init_worker_lifecycle(self) -> None:
        """Initialize reconnect-worker ownership state."""
        # set to the server's reason when it refuses our credentials; while
        # set, the reconnect lifecycle stays stopped
        self._auth_rejected = None
        self._stop_event = Event()
        self._worker_lock = Lock()
        self._worker_token: object | None = None
        self._worker_thread: Thread | None = None

    def init_identity(self, site_id=None):
        """Resolve the credentials this client connects with.

        A node has ONE identity: one keypair, one Noise static key, one set of
        pinned peer keys, used in both directions. Credentials are not part of
        it. They say how to reach one particular master, and a node that both
        serves clients and connects upstream has its own access key and
        password as well as its master's.

        So they are read from the identity as a fallback and never written
        back. Copying them in overwrote the node's own access key, password
        and name with its master's on the first save — and the first Noise
        handshake saves, because pinning a peer key persists the file. Every
        downstream client then failed with "invalid api key" against
        credentials the node no longer had.
        """
        self.identity = self.identity or NodeIdentity()
        self._password = self._password or self.identity.password
        self._access_key = self._access_key or self.identity.access_key
        self._host = self._host or self.identity.default_master
        self._port = self._port or self.identity.default_port
        self._name = self._name or "HiveMessageBusClientV0.0.1"
        self._site_id = site_id or self.identity.site_id

        if not self._access_key or not self._password:
            raise RuntimeError("NodeIdentity not set, please pass key and password or "
                               "call 'hivemind-client set-identity'")
        if not self._host:
            raise RuntimeError("host not set, please pass host and port or "
                               "call 'hivemind-client set-identity'")

    @property
    def useragent(self):
        return self._name

    @useragent.setter
    def useragent(self, val):
        self._name = val

    @property
    def password(self):
        return self._password

    @property
    def key(self):
        return self._access_key

    @property
    def site_id(self):
        return self._site_id

    @site_id.setter
    def site_id(self, val):
        self._site_id = val

    @password.setter
    def password(self, val):
        self._password = val

    @key.setter
    def key(self, val):
        self._access_key = val

    def connect(self, bus=FakeBus(), protocol=None, site_id=None,
                handshake_max_retries=None):
        from hivemind_bus_client.protocol import HiveMindSlaveProtocol

        # The site this connection reports is the client's, not the identity's
        # — writing it back would rewrite the node's own site, and reading it
        # back would silently ignore `client.site_id = ...` set before connect.
        self._site_id = site_id or self._site_id or self.identity.site_id

        if protocol is None:
            LOG.debug("Initializing HiveMindSlaveProtocol")
            self.protocol = HiveMindSlaveProtocol(self,
                                                  shared_bus=self.share_bus,
                                                  site_id=self._site_id or "unknown",
                                                  identity=self.identity)
        else:
            self.protocol = protocol
            self.protocol.identity = self.identity
            if self._site_id is not None:
                self.protocol.site_id = self._site_id

        LOG.info("Connecting to Hivemind")
        # bind BEFORE opening the websocket so the server's initial cleartext
        # HELLO + HANDSHAKE parameter payloads are never missed — protocol v3
        # needs them for Noise prologue binding (HIVEMIND-CRYPTO-1 §3.4.3)
        self.protocol.bind(bus)
        self.run_in_thread()
        # None retries forever (legacy behaviour); pass a bound so a failed
        # handshake (e.g. wrong password on protocol v3) fails fast instead
        # of blocking connect() indefinitely
        self.wait_for_handshake(max_retries=handshake_max_retries)

    def on_open(self, *args):
        """
        Handle the "open" event from the websocket.
        A Basic message with the name "open" is forwarded to the emitter.
        """
        LOG.debug("Connected")
        self.connected_event.set()
        self.emitter.emit("open")
        # Restore reconnect timer to 5 seconds on sucessful connect
        self.retry = 5

    def on_error(self, *args):
        error = args[0] if len(args) == 1 else args[1]

        # websocket-client hands a CLOSE frame to on_error rather than to
        # on_close when the peer closes mid-read, so this is where an
        # "authorization refused" close is actually observable. It arrives as
        # a control frame, not an exception, so it must be classified before
        # the not-an-exception guard below drops it.
        if isinstance(error, ABNF):
            if self._is_auth_rejection(error):
                self._clear_connection_state()
                self.close()
            else:
                LOG.debug("ignoring websocket control frame: opcode=%s",
                          error.opcode)
            return

        # websocket-client can invoke this callback with other non-exception
        # values. Those are not connection failures.
        if not isinstance(error, BaseException):
            LOG.debug("ignoring non-exception websocket error callback: %r",
                      error)
            return

        self._clear_connection_state()
        # Closed/refused/reset are expected reconnect triggers. Log them
        # without emitting pyee's special "error" event, which raises when no
        # application listener is registered. Unclassified failures remain
        # observable to application error listeners below.
        if isinstance(error, WebSocketConnectionClosedException):
            LOG.warning("HiveMind websocket connection closed unexpectedly")
        elif isinstance(error, ConnectionRefusedError):
            LOG.warning("HiveMind websocket connection refused")
        elif isinstance(error, ConnectionResetError):
            LOG.warning("HiveMind websocket connection reset")
        else:
            LOG.warning("HiveMind websocket error: %r", error)
            # Event handlers are application callbacks; one faulty listener
            # must not terminate the reconnect worker.
            try:
                self.emitter.emit("error", error)
            except Exception as emitter_error:  # noqa: BLE001
                LOG.exception("Failed to emit websocket error event: %s",
                              emitter_error)

        # A callback exception does not make WebSocketApp.run_forever()
        # return by itself. Closing only the current socket guarantees that
        # every real error reaches the outer reconnect loop.
        try:
            if self.client.keep_running:
                self.client.close()
        except Exception as close_error:  # noqa: BLE001
            LOG.exception("Failed to close errored websocket: %s",
                          close_error)

    #: WebSocket close code the server sends when it refuses the credentials
    #: (hivemind-websocket-protocol: ``close(code=1008, reason="invalid
    #: authorization")``).
    AUTH_REJECTED_CLOSE_CODE = 1008

    #: RFC6455 CLOSE opcode, as websocket-client reports it on an ABNF frame

    def on_close(self, *args):
        # websocket-client calls this as (ws, close_status_code, close_msg).
        # Older versions call it with no arguments at all, so read defensively
        # by position rather than assuming an arity.
        close_code = args[1] if len(args) > 1 else None
        close_reason = args[2] if len(args) > 2 else None

        if close_code == self.AUTH_REJECTED_CLOSE_CODE:
            # Reconnecting cannot help: the credentials do not change between
            # attempts, so a retry loop here is an infinite loop that only
            # emits close frames. Record it, say so once, and stop.
            self._auth_rejected = (
                close_reason or "the server refused these credentials"
            )
            LOG.error(
                f"HiveMind refused this identity: {self._auth_rejected}. "
                f"Check the access key and password "
                f"(hivemind-client set-identity), and that the client is "
                f"registered on the server (hivemind-core list-clients). "
                f"Not reconnecting."
            )
            self._clear_connection_state()
            self.emitter.emit("auth_rejected", self._auth_rejected)
            self.emitter.emit("close")
            self.close()
            return

        self._clear_connection_state()
        self.emitter.emit("close")

    def _is_auth_rejection(self, frame: ABNF) -> bool:
        """True when *frame* is a CLOSE saying the credentials were refused.

        Retrying cannot help: the identity does not change between attempts, so
        without this the client reconnects forever and the operator sees only a
        repeating raw close frame instead of "your key is wrong".
        """
        if frame.opcode != ABNF.OPCODE_CLOSE:
            return False
        data = frame.data or b""
        if len(data) < 2:
            return False
        code = 256 * data[0] + data[1]
        if code != self.AUTH_REJECTED_CLOSE_CODE:
            return False
        try:
            reason = data[2:].decode("utf-8") or "credentials refused"
        except UnicodeDecodeError:
            reason = "credentials refused"
        self._auth_rejected = reason
        LOG.error(
            f"HiveMind refused this identity: {reason}. Check the access key "
            f"and password (hivemind-client set-identity) and that the client "
            f"is registered on the server (hivemind-core list-clients). "
            f"Not reconnecting."
        )
        try:
            self.emitter.emit("auth_rejected", reason)
        except Exception:  # noqa: BLE001
            LOG.exception("failed to emit auth_rejected")
        return True

    def _clear_connection_state(self):
        self.connected_event.clear()
        self.handshake_event.clear()
        self.crypto_key = None
        self.noise_transport = None
        if self.protocol is not None:
            self.protocol.reset_connection_state()

    def close_connection(self):
        """Close the current websocket but keep reconnecting.

        Use this for a connection that has become unusable — a failed
        handshake, an invalid Noise transport frame — so that
        ``run_forever()`` returns and the reconnect loop establishes a
        fresh session. Public :meth:`close` is reserved for an intentional
        permanent shutdown.
        """
        self.client.close()

    def close(self):
        """Permanently stop reconnecting and close the websocket."""
        # Serialize the stop request with worker reservation. A worker that is
        # already shutting down retains ownership until its finally block, so
        # a second starter cannot clear this event and revive it.
        with self._worker_lock:
            self._stop_event.set()
        try:
            self.client.close()
        finally:
            self._clear_connection_state()

    def wait_for_handshake(self, timeout=5, max_retries=None):
        """
        Waits for the HiveMind handshake to complete.

        By default this waits for reconnect forever. Pass ``max_retries`` to
        bound the wait for tests or command-line tools that need a hard fail.

        Parameters:
            timeout (float): Number of seconds to wait for each handshake or connection attempt before retrying.
            max_retries (int | None): Number of reconnect/handshake retries;
                                      ``None`` means retry forever.
        """
        attempts = 0
        while not self.handshake_event.is_set():
            self.handshake_event.wait(timeout=timeout)
            if self.handshake_event.is_set():
                return
            if self._auth_rejected:
                # no number of retries fixes a wrong key or password
                raise ConnectionRefusedError(
                    f"HiveMind refused this identity: {self._auth_rejected}"
                )
            if max_retries is not None and attempts >= max_retries:
                raise RuntimeError("timed out waiting for handshake")
            attempts += 1
            if self.connected_event.is_set():
                self.protocol.start_handshake()
            else:
                LOG.warning("Can't start handshake because websocket connection is not yet open...")
                self.connected_event.wait(timeout=timeout)

    @staticmethod
    def build_url(key, host='127.0.0.1', port=5678,
                  useragent="HiveMessageBusClientV0.0.1", ssl=True):
        scheme = 'wss' if ssl else 'ws'
        key = pybase64.b64encode(f"{useragent}:{key}".encode("utf-8")).decode("utf-8")
        return f'{scheme}://{host}:{port}?authorization={key}'

    def create_client(self):
        url = self.build_url(ssl=self.config.ssl,
                             host=self.config.host,
                             port=self.config.port,
                             key=self.key,
                             useragent=self.useragent)
        return WebSocketApp(url, on_open=self.on_open, on_close=self.on_close,
                            on_error=self.on_error, on_message=self.on_message)

    def run_in_thread(self) -> Thread:
        """Launch the reconnect lifecycle in a daemon thread."""
        token = self._reserve_worker()
        try:
            thread = Thread(
                target=self._run_worker, args=(token,), daemon=True
            )
            self._set_worker_thread(token, thread)
            thread.start()
        except Exception:
            self._stop_event.set()
            self._release_worker(token)
            raise
        return thread

    def run_forever(self) -> None:
        """Block the calling thread while the connection is maintained.

        If nothing owns the reconnect lifecycle yet, this starts it and
        runs it on the calling thread, same as before.

        If ``connect()`` (or ``run_in_thread()``) already started it in a
        background thread -- the common case for a bridge that calls
        ``connect()`` in ``__init__`` and then wants to block ``run()`` on
        the connection -- this used to raise ``RuntimeError("HiveMind
        websocket reconnect worker is already running")``. That made the
        combination of "connect() to get a synchronous, retried handshake"
        and "run_forever() to block the main thread" -- a completely
        reasonable pair of calls -- a footgun: every bridge that wrote it
        naturally hit the crash. There is nothing to "start" a second time
        in that case; what the caller actually wants is to block on the
        worker that already exists, so that is what this does instead.
        """
        while True:
            token = self._try_reserve_worker()
            if token is not None:
                self._set_worker_thread(token, current_thread())
                self._run_worker(token)
                return
            existing = self._get_worker_thread()
            if existing is None:
                # Reservation raced with the owning worker's shutdown
                # (it released the token between our failed reserve and
                # this read); nothing left to join, so try again -- either
                # we win the reservation this time or a new worker to
                # join appears.
                continue
            existing.join()
            return

    def _reserve_worker(self) -> object:
        """Claim exclusive ownership of the reconnect lifecycle, or raise."""
        token = self._try_reserve_worker()
        if token is None:
            raise RuntimeError(
                "HiveMind websocket reconnect worker is already running"
            )
        return token

    def _try_reserve_worker(self) -> Optional[object]:
        """Claim exclusive ownership of the reconnect lifecycle, or return None."""
        with self._worker_lock:
            if self._worker_token is not None:
                return None
            token = object()
            self._worker_token = token
            self._worker_thread = None
            self._stop_event.clear()
            return token

    def _get_worker_thread(self) -> Optional[Thread]:
        with self._worker_lock:
            return self._worker_thread

    def _set_worker_thread(self, token: object, thread: Thread) -> None:
        with self._worker_lock:
            if self._worker_token is token:
                self._worker_thread = thread

    def _release_worker(self, token: object) -> None:
        with self._worker_lock:
            if self._worker_token is token:
                self._worker_token = None
                self._worker_thread = None

    def _run_worker(self, token: object) -> None:
        try:
            self._run_forever()
        finally:
            self._release_worker(token)

    def _run_forever(self):
        self.started_running = True
        run_options = self._websocket_keepalive_options()
        if self.allow_self_signed:
            run_options["sslopt"] = {
                "cert_reqs": ssl.CERT_NONE,
                "check_hostname": False,
                "ssl_version": ssl.PROTOCOL_TLS_CLIENT}
        try:
            while not self._stop_event.is_set():
                self.client.run_forever(**run_options)
                self._clear_connection_state()
                if self._stop_event.is_set():
                    break

                # Jitter the wait (not the stored retry value) so that a core
                # restart, which disconnects the whole fleet at once, does not
                # make every satellite wake up and reconnect at the exact same
                # instant. Without this the herd never de-phases and keeps
                # re-forming into synchronized reconnect waves. Clamp the base
                # first and jitter afterwards: clamping the jittered value
                # instead would collapse half of the probability mass onto
                # exactly 60s at the ceiling, waking the whole fleet at the
                # same instant - the very thing the jitter prevents.
                delay = min(self.retry, 60) * random.uniform(0.5, 1.5)
                LOG.warning("HiveMind websocket disconnected; reconnecting "
                            "in %.1f seconds", delay)
                if self._stop_event.wait(delay):
                    break

                self.retry = min(max(self.retry, 1) * 2, 60)
                try:
                    self.emitter.emit("reconnecting")
                except Exception as emitter_error:  # noqa: BLE001
                    LOG.exception("Failed to emit websocket reconnecting "
                                  "event: %s", emitter_error)
                self.client = self.create_client()
        finally:
            self.started_running = False
            self._clear_connection_state()

    def _websocket_keepalive_options(self):
        return websocket_keepalive_options(
            ping_interval=self.websocket_ping_interval,
            ping_timeout=self.websocket_ping_timeout,
            disabled_interval_value=0,
        )

    # event handlers
    def on_message(self, *args):
        if len(args) == 1:
            message = args[0]
        else:
            message = args[1]
        if self.noise_transport is not None:
            # protocol v3: every post-handshake message is a Noise transport
            # message; there is no cleartext v3 session (CRYPTO-1 §3.4.5)
            if not isinstance(message, bytes):
                LOG.error("dropping non-Noise message received on a "
                          "protocol v3 session")
                return
            try:
                message = self.noise_transport.decrypt_frame(message)
            except NoiseTransportFailed:
                # tampered / replayed / out-of-order — MUST reject; the
                # receive counter is now out of sync so the session is dead
                LOG.exception("rejecting invalid Noise transport message, "
                              "closing connection")
                self.close_connection()
                return
        elif self.crypto_key:
            # handle binary encryption
            if isinstance(message, bytes):
                message = decrypt_bin(self.crypto_key, message, cipher=self.cipher)
            # handle json encryption
            elif "ciphertext" in message:
                # LOG.debug(f"got encrypted message: {len(message)}")
                message = decrypt_from_json(self.crypto_key, message,
                                            cipher=self.cipher, encoding=self.json_encoding)
            else:
                LOG.debug("Message was unencrypted")

        if isinstance(message, bytes):
            try:
                message = decode_bitstring(message)
            except Exception:
                # WIRE-1 §4.2: a malformed binary frame (e.g. an
                # unassigned/reserved message-type code) MUST be rejected.
                # Drop it instead of crashing the receive loop.
                LOG.exception("dropping malformed binary frame")
                return
        elif isinstance(message, str):
            message = json.loads(message)
        if isinstance(message, dict) and "ciphertext" in message:
            LOG.error("got encrypted message, but could not decrypt!")
            return

        if (isinstance(message, HiveMessage) and message.msg_type == HiveMessageType.BINARY):
            self._handle_binary(message)
            return

        if isinstance(message, HiveMessage):
            self.emitter.emit('message', message.serialize())  # raw message
            self._handle_hive_protocol(message)
        elif isinstance(message, str):
            self.emitter.emit('message', message)  # raw message
            self._handle_hive_protocol(HiveMessage(**json.loads(message)))
        else:
            assert isinstance(message, dict)
            self.emitter.emit('message', json.dumps(message, ensure_ascii=False))  # raw message
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
            except:
                LOG.exception("Error in binary callback: handle_receive_tts")
        elif message.bin_type == HiveMindBinaryPayloadType.FILE:
            file_name = message.metadata.get("file_name")
            try:
                self.bin_callbacks.handle_receive_file(bin_data, file_name)
            except:
                LOG.exception("Error in binary callback: handle_receive_file")
        else:
            LOG.warning(f"Ignoring received untyped binary data: {len(bin_data)} bytes")

    def _handle_hive_protocol(self, message: HiveMessage):
        # LOG.debug(f"received HiveMind message: {message.msg_type}")
        if message.msg_type == HiveMessageType.BUS:
            self.internal_bus.emit(message.payload)
        self.emitter.emit(message.msg_type, message)  # hive message

    def emit(self, message: Union[MycroftMessage, HiveMessage],
             binary_type: HiveMindBinaryPayloadType = HiveMindBinaryPayloadType.UNDEFINED):
        """
        Send a HiveMessage or MycroftMessage to the HiveMind network, injecting routing context for BUS messages and optionally sending binary payloads.
       
        Parameters:
            message (MycroftMessage | HiveMessage): The message to send. If a MycroftMessage is provided it will be wrapped into a BUS HiveMessage.
            binary_type (HiveMindBinaryPayloadType): When sending binary payloads, indicates the binary payload subtype; defaults to UNDEFINED.
       
        Notes:
            - For messages with msg_type == HiveMessageType.BUS, the function will ensure the payload.context contains routing fields (source, platform, destination, session) and will emit the payload to the client's internal bus before sending.
            - This method transmits the message over the client's WebSocket and may perform serialization, optional compression, and optional encryption depending on client configuration.
       
        Raises:
            ValueError: If the client has not been started with run_forever() and the connection is not ready.
            RuntimeError: If the transport is down (eg. master unreachable) and does not
                          come up within a brief grace window.

        Note:
            When the connection is not currently open, this method waits only a short,
            bounded margin (``_EMIT_NOT_CONNECTED_GRACE`` seconds) rather than the old
            10 second timeout. ``emit()`` is called synchronously from callers that may
            themselves be running on an event loop (eg. hivemind-core forwarding a
            PROPAGATE message from its Tornado ioloop); blocking that caller for
            seconds every time a master/relay is unreachable stalls the whole loop and,
            because the subsequent RuntimeError bubbles up as a send failure, can get
            the sender itself disconnected. The short grace window still lets a send
            that merely races a connection that is finishing its handshake succeed,
            without parking an ioloop for multiple seconds on the common "peer is
            unreachable" case.
        """
        if isinstance(message, MycroftMessage):
            message = HiveMessage(msg_type=HiveMessageType.BUS,
                                  payload=message)
        if not self.connected_event.is_set():
            LOG.warning("hivemind connection not ready!")
            if not self.started_running:
                raise ValueError('You must execute run_forever() '
                                 'before emitting messages')
            if not self.connected_event.wait(self._EMIT_NOT_CONNECTED_GRACE):
                raise RuntimeError(f"Can not send messages before opening the websocket connection. Failed to emit : {message.serialize()}")

        try:
            # auto inject context for proper routing, this is confusing for
            # end users if they need to do it manually, error prone and easy
            # to forget
            if message.msg_type == HiveMessageType.BUS:
                updated_payload = message.payload
                if "source" not in updated_payload.context:
                    updated_payload.context["source"] = self.useragent
                if "platform" not in updated_payload.context:
                    updated_payload.context["platform"] = self.useragent
                if "destination" not in updated_payload.context:
                    updated_payload.context["destination"] = "HiveMind"
                if "session" not in updated_payload.context:
                    updated_payload.context["session"] = {}
                session = updated_payload.context["session"]
                if not session.get("session_id"):
                    session["session_id"] = self.session_id
                if not session.get("site_id"):
                    session["site_id"] = self.site_id
                message.payload = updated_payload

                # also send event to client registered handlers
                self.internal_bus.emit(message.payload)

            elif message.msg_type == HiveMessageType.QUERY and self.protocol is not None:
                # NODE-1 §5.5: as originator, bound our own wait for the answer
                self.protocol.arm_query_timeout()

            LOG.debug(f"sending to HiveMind: {message.msg_type}")
            binarize = False
            if message.msg_type == HiveMessageType.BINARY:
                binarize = True
            elif (message.msg_type in BINARY_ENCODABLE_TYPES
                  and message.msg_type not in [HiveMessageType.HELLO, HiveMessageType.HANDSHAKE]):
                binarize = self.protocol.binarize and self.binarize

            bitstr = None
            if binarize:
                # the message carries its own bin_type; an explicit
                # binary_type argument overrides it. Without this a caller
                # that set bin_type on the HiveMessage -- the obvious thing
                # to do -- silently put UNDEFINED on the wire, and the
                # receiver could not tell audio from a file.
                if binary_type == HiveMindBinaryPayloadType.UNDEFINED:
                    binary_type = message.bin_type
                try:
                    bitstr = get_bitstring(hive_type=message.msg_type,
                                           payload=message.payload,
                                           compressed=self.compress,
                                           binary_type=binary_type,
                                           hivemeta=message.metadata)
                except MetadataTooLarge as e:
                    # WIRE-1 §4.1 offers text framing as the last of the three
                    # remedies; taking it beats dropping the message. A BINARY
                    # payload has no text form, so that one has to be refused.
                    if message.msg_type == HiveMessageType.BINARY:
                        raise
                    LOG.warning(f"sending {message.msg_type} as a text frame: {e}")

            if bitstr is not None:
                if self.noise_transport is not None:
                    # protocol v3: Noise transport CipherState (replay
                    # resistant sequential nonces) replaces the v2 AEAD
                    ws_payload = self.noise_transport.encrypt_frame(bitstr.bytes)
                elif self.crypto_key:
                    ws_payload = encrypt_bin(self.crypto_key, bitstr.bytes, cipher=self.cipher)
                else:
                    ws_payload = bitstr.bytes
                self.client.send(ws_payload, ABNF.OPCODE_BINARY)
            else:
                ws_payload = serialize_message(message)
                if self.noise_transport is not None:
                    # v3 sessions are always encrypted, HELLO included
                    ws_payload = self.noise_transport.encrypt_frame(ws_payload)
                    self.client.send(ws_payload, ABNF.OPCODE_BINARY)
                    return
                if self.crypto_key:
                    ws_payload = encrypt_as_json(self.crypto_key, ws_payload,
                                                 cipher=self.cipher, encoding=self.json_encoding)
                self.client.send(ws_payload)

        except WebSocketConnectionClosedException:
            LOG.warning(f'Could not send {message.msg_type} message because connection '
                        'has been closed')

    def emit_mycroft(self, message: MycroftMessage):
        message = HiveMessage(msg_type=HiveMessageType.BUS, payload=message)
        self.emit(message)

    def on_mycroft(self, mycroft_msg_type, func):
        LOG.debug(f"registering mycroft event: {mycroft_msg_type}")
        self.internal_bus.on(mycroft_msg_type, func)

    # event api
    def on(self, event_name, func):
        if event_name not in list(HiveMessageType):
            # assume it's a mycroft message
            # this could be done better,
            # but makes this lib almost a drop in replacement
            # for the mycroft bus client
            # LOG.info(f"registering mycroft handler: {event_name}")
            self.on_mycroft(event_name, func)
        else:
            # hivemind message
            LOG.debug(f"registering handler: {event_name}")
            self.emitter.on(event_name, func)

    def remove(self, event_name: str, func: Callable):
        if event_name not in list(HiveMessageType):
            self.internal_bus.remove(event_name, func)
        else:  # hivemind message
            self.emitter.remove_listener(event_name, func)

    # utility
    def wait_for_message(self, message_type: Union[HiveMessageType, str], timeout=3.0):
        """Wait for a message of a specific type.

        Arguments:
            message_type (HiveMessageType): the message type of the expected message
            timeout: seconds to wait before timeout, defaults to 3

        Returns:
            The received message or None if the response timed out
        """

        return HiveMessageWaiter(self, message_type).wait(timeout)

    def wait_for_payload(self, payload_type: Union[HiveMessageType, str],
                         message_type: Union[HiveMessageType, str] = HiveMessageType.BUS,
                         timeout=3.0):
        """Wait for a message of a specific type + payload of a specific type.

        Arguments:
            payload_type (str): the message type of the expected payload
            message_type (HiveMessageType): the message type of the expected message
            timeout: seconds to wait before timeout, defaults to 3

        Returns:
            The received message or None if the response timed out
        """

        return HivePayloadWaiter(bus=self, payload_type=payload_type,
                                 message_type=message_type).wait(timeout)

    def wait_for_mycroft(self, mycroft_msg_type: str, timeout: float = 3.0):
        return self.wait_for_payload(mycroft_msg_type, timeout=timeout,
                                     message_type=HiveMessageType.BUS)

    def wait_for_response(self, message: Union[MycroftMessage, HiveMessage],
                          reply_type: Optional[Union[HiveMessageType, str]] = None,
                          timeout=3.0):
        """Send a message and wait for a response.

        Arguments:
            message (HiveMessage): message to send, mycroft Message objects also accepted
            reply_type (HiveMessageType): the message type of the expected reply.
                                          Defaults to "<message.msg_type>".
            timeout: seconds to wait before timeout, defaults to 3

        Returns:
            The received message or None if the response timed out
        """
        message_type = reply_type or message.msg_type
        if isinstance(message, MycroftMessage):
            waiter = HivePayloadWaiter(bus=self, payload_type=message_type)
        else:
            waiter = HiveMessageWaiter(bus=self, message_type=message_type)  # Setup response handler
        # Send message and wait for it's response
        self.emit(message)
        return waiter.wait(timeout)

    def wait_for_payload_response(self, message: Union[MycroftMessage, HiveMessage],
                                  payload_type: Union[HiveMessageType, str],
                                  reply_type: Optional[Union[HiveMessageType, str]] = None,
                                  timeout=3.0):
        """Send a message and wait for a response.

        Arguments:
            message (HiveMessage): message to send, mycroft Message objects also accepted
            payload_type (str): the message type of the expected payload
            reply_type (HiveMessageType): the message type of the expected reply.
                                          Defaults to "<message.msg_type>".
            timeout: seconds to wait before timeout, defaults to 3

        Returns:
            The received message or None if the response timed out
        """
        if isinstance(message, MycroftMessage):
            message = HiveMessage(msg_type=HiveMessageType.BUS, payload=message)
        message_type = reply_type or message.msg_type
        waiter = HivePayloadWaiter(bus=self, payload_type=payload_type,
                                   message_type=message_type)  # Setup
        # response handler
        # Send message and wait for it's response
        self.emit(message)
        return waiter.wait(timeout)

    # targeted messages for nodes, asymmetric encryption
    def emit_intercom(self, message: Union[MycroftMessage, HiveMessage],
                      pubkey: Union[str, bytes, 'RSA.RsaKey']):
        """Send an INTERCOM message using hybrid encryption.

        Generates a random AES-256 key, encrypts the payload with AES-GCM,
        then RSA-encrypts only the AES key with the target's public key.
        The ciphertext is signed with this node's private key.

        Args:
            message: The message to send.
            pubkey: RSA public key of the target peer.
        """
        private_key = load_RSA_key(self.identity.private_key)
        envelope = hybrid_encrypt(pubkey, message.serialize(), sign_key=private_key)
        # Two things this used to leave out, which together meant a peer-to-peer
        # INTERCOM never arrived anywhere.
        #
        # `target_pubkey` is the address. Without it a node reads
        # `target_public_key` as None, tries to decrypt the envelope with its
        # own key, fails, and has nothing left to route on.
        #
        # PROPAGATE is the envelope that travels. A bare INTERCOM is dispatched
        # by `handle_message` to `handle_intercom_message`, whose return value
        # that call site discards — so a frame addressed to someone else is
        # consumed and dropped at the first node it reaches. The fan-out and
        # upstream-forward live in the PROPAGATE handler, which does check that
        # return value and keeps relaying a frame that is not for it.
        inner = HiveMessage(HiveMessageType.INTERCOM, payload=envelope,
                            target_pubkey=pubkey if isinstance(pubkey, str) else None)
        self.emit(HiveMessage(HiveMessageType.PROPAGATE, payload=inner))
