"""HiveMind protocol version 3 — Noise handshake and transport glue.

Implements the version-3 session layer of HIVEMIND-CRYPTO-1 §3.4 on top of
the ``poorman_handshake.noise`` primitive:

- **negotiation helpers** — the server advertises supported Noise ``patterns``
  and ``suites`` (preference ordered); the node selects one of each and fixes
  the Noise protocol name (HIVEMIND-CRYPTO-1 §3.4.1/§3.4.2)
- **prologue construction** — the cleartext ``HELLO`` payload, the cleartext
  parameter ``HANDSHAKE`` payload, and the node's selected protocol name are
  bound into the Noise prologue so any tampering with the negotiation aborts
  the handshake (HIVEMIND-CRYPTO-1 §3.4.3)
- **transport framing** — after ``Split()`` every message travels as a Noise
  transport message under the per-direction ``CipherState``s, whose strictly
  sequential nonce counters give replay resistance and ordering enforcement
  (HIVEMIND-CRYPTO-1 §3.4.5); the fresh-IV AEAD construction of protocol
  versions 0-2 is not used on a version-3 session

Protocol version 2 and below are untouched: this module is only entered when
both peers negotiate version 3.
"""
import json
import logging
import os
import threading
from binascii import hexlify
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

LOG = logging.getLogger("hivemind_bus_client.noise")


try:
    from poorman_handshake.noise import NoiseHandShake, derive_psk

    NOISE_SUPPORTED = True
except ImportError:  # poorman-handshake without the noise primitive
    NoiseHandShake = None  # type: ignore
    derive_psk = None  # type: ignore
    NOISE_SUPPORTED = False

# HiveMind protocol version that switches the handshake to Noise
PROTOCOL_V3 = 3

# registered handshake patterns, preference ordered (HIVEMIND-CRYPTO-1 §3.4.2)
NOISE_PATTERN_XX = "XXpsk2"  # general case, MUST support
NOISE_PATTERN_KK = "KKpsk0"  # pre-provisioned static keys, MAY support
NOISE_PATTERNS: List[str] = [NOISE_PATTERN_KK, NOISE_PATTERN_XX]

# registered cipher suites, preference ordered (HIVEMIND-CRYPTO-1 §3.4.1)
NOISE_SUITE_CHACHA = "25519_ChaChaPoly_SHA256"  # MUST support
NOISE_SUITE_AESGCM = "25519_AESGCM_SHA256"  # MAY support (Web Crypto peers)
NOISE_SUITES: List[str] = [NOISE_SUITE_CHACHA, NOISE_SUITE_AESGCM]

# transport frame markers: the first plaintext byte tags the inner framing so
# the receiver knows how to parse the decrypted bytes.
#
# A single Noise transport message caps at 65535 bytes (poorman-handshake /
# the Noise spec), so a HiveMessage whose marked plaintext exceeds that limit
# is split across several consecutive Noise transport messages and reassembled
# by the receiver (HIVEMIND-WIRE-1 multi-frame transport). The SINGLE markers
# are unchanged so any message that fits in one Noise message stays byte
# identical on the wire.
_FRAME_JSON = b"\x00"  # single-frame utf-8 JSON HiveMessage
_FRAME_BINARY = b"\x01"  # single-frame HIVEMIND-WIRE-1 binary frame (bitstring)
_FRAME_FIRST_JSON = b"\x02"  # first chunk of a multi-frame JSON message
_FRAME_FIRST_BINARY = b"\x03"  # first chunk of a multi-frame binary message
_FRAME_MORE = b"\x04"  # a middle chunk of a multi-frame message
_FRAME_LAST = b"\x05"  # the final chunk of a multi-frame message

# Maximum plaintext a single Noise transport message can carry is
# 65535 - 16 (Poly1305/GCM AEAD tag) - 1 (frame marker) = 65518 bytes. A
# conservative chunk size keeps well under that and leaves room for any
# implementation overhead.
CHUNK_SIZE = 65000

# Bounded reassembly budget: a multi-frame message may not accumulate more
# than this many bytes before the whole buffer is dropped. This caps the
# memory a peer can force us to allocate from a single message (DoS/OOM
# guard); 32 MiB comfortably covers audio-sized bus messages.
MAX_REASSEMBLY_BYTES = 32 * 1024 * 1024


class NoiseHandshakeFailed(Exception):
    """The Noise handshake aborted — wrong password/PSK, tampered
    negotiation (prologue mismatch), static-key contradiction, or a
    malformed handshake message. Fatal: the connection must be rejected."""


class NoiseTransportFailed(Exception):
    """A Noise transport message failed to decrypt at the current receive
    counter — tampering, replay, or reordering. Fatal for the session."""


def canonical_json(payload: Dict[str, Any]) -> bytes:
    """Serialize a payload dict deterministically for prologue binding.

    Both peers must derive identical prologue bytes from the negotiation
    payloads; sorted keys + compact separators make the serialization
    independent of dict ordering and formatting.
    """
    return json.dumps(payload, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def noise_protocol_name(pattern: str, suite: str) -> str:
    """Full Noise protocol name for a pattern + suite selection."""
    return f"Noise_{pattern}_{suite}"


def select_noise_options(server_patterns: List[str],
                         server_suites: List[str],
                         pinned_remote_key: Optional[str] = None
                         ) -> Optional[Tuple[str, str]]:
    """Pick the handshake pattern and suite from the server's advertised lists.

    ``KKpsk0`` is preferred when the remote static key is pre-provisioned
    (pinned) and the server offers it; otherwise ``XXpsk2``. Returns
    ``(pattern, suite)`` or None when there is no mutual option.
    """
    # walk our own preference-ordered list so 25519_ChaChaPoly_SHA256 wins
    # whenever both peers support it, regardless of the server's list order
    suite = next((s for s in NOISE_SUITES if s in server_suites), None)
    if suite is None:
        return None
    if pinned_remote_key and NOISE_PATTERN_KK in server_patterns:
        return NOISE_PATTERN_KK, suite
    if NOISE_PATTERN_XX in server_patterns:
        return NOISE_PATTERN_XX, suite
    return None


def build_prologue(hello_payload: Dict[str, Any],
                   handshake_payload: Dict[str, Any],
                   protocol_name: str) -> bytes:
    """Prologue bytes per HIVEMIND-CRYPTO-1 §3.4.3.

    Binds, in order: the server's cleartext ``HELLO`` payload, its cleartext
    parameter ``HANDSHAKE`` payload (advertised versions, patterns, suites,
    encodings, every other parameter), and the node's selected Noise protocol
    name. Both peers must supply identical bytes or the handshake aborts —
    this is the downgrade/tampering protection.
    """
    return (canonical_json(hello_payload)
            + canonical_json(handshake_payload)
            + protocol_name.encode("utf-8"))


class NoiseTransport:
    """A completed protocol-v3 Noise session.

    Wraps the post-``Split()`` transport of a :class:`NoiseHandShake` with
    thread-safe per-direction locks (the CipherState nonce counters are
    strictly sequential — encryption order must match send order) and the
    HiveMind frame markers that distinguish JSON from binary frames after
    decryption.
    """

    def __init__(self, handshake: "NoiseHandShake",
                 max_reassembly_bytes: int = MAX_REASSEMBLY_BYTES):
        if not handshake.handshake_finished:
            raise NoiseHandshakeFailed("handshake not finished")
        self._hs = handshake
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()
        self._max_reassembly = max_reassembly_bytes
        # open multi-frame reassembly (None when no message is in progress)
        self._reasm: Optional[bytearray] = None
        self._reasm_is_json: bool = False
        self.remote_static_key: Optional[str] = (
            hexlify(handshake.remote_pubkey).decode("utf-8")
            if handshake.remote_pubkey else None)
        self.handshake_hash: Optional[bytes] = handshake.handshake_hash

    def encrypt_frame(self, payload: Union[str, bytes]) -> bytes:
        """Encrypt one outgoing message as a single Noise transport message.

        This only ever produces a SINGLE frame and raises on an oversize
        payload. Prefer :meth:`send_message`, which chunks transparently;
        this method is retained for callers that already guarantee the
        payload fits in one Noise transport message.

        Args:
            payload: a serialized JSON HiveMessage (str) or a WIRE-1 binary
                frame (bytes).

        Returns:
            Ciphertext bytes to send as a single (binary) websocket message.
        """
        if isinstance(payload, str):
            plaintext = _FRAME_JSON + payload.encode("utf-8")
        else:
            plaintext = _FRAME_BINARY + bytes(payload)
        with self._send_lock:
            return self._hs.encrypt(plaintext)

    def send_message(self, payload: Union[str, bytes],
                     raw_send: Callable[[bytes], None]) -> None:
        """Encrypt and send one message, chunking it if it is oversize.

        A message whose marked plaintext fits in one Noise transport message
        is sent as a SINGLE frame, byte identical to :meth:`encrypt_frame`.
        A larger message is split into FIRST / MORE* / LAST chunks, each its
        own Noise transport message. ``raw_send`` puts one binary websocket
        message on the wire.

        The whole send holds ``_send_lock`` so every chunk of one message is
        encrypted and placed on the wire contiguously and in order: the Noise
        CipherState nonce counter is strictly sequential, so interleaving the
        chunks of two messages would break AEAD ordering at the receiver.

        Args:
            payload: a serialized JSON HiveMessage (str) or a WIRE-1 binary
                frame (bytes).
            raw_send: callback that transmits one binary websocket message.
        """
        if isinstance(payload, str):
            body = payload.encode("utf-8")
            single, first = _FRAME_JSON, _FRAME_FIRST_JSON
        else:
            body = bytes(payload)
            single, first = _FRAME_BINARY, _FRAME_FIRST_BINARY

        with self._send_lock:
            if len(body) <= CHUNK_SIZE:
                raw_send(self._hs.encrypt(single + body))
                return
            last = len(body) - CHUNK_SIZE  # start offset of the final chunk
            offset = 0
            while offset < len(body):
                chunk = body[offset:offset + CHUNK_SIZE]
                if offset == 0:
                    marker = first
                elif offset >= last:
                    marker = _FRAME_LAST
                else:
                    marker = _FRAME_MORE
                raw_send(self._hs.encrypt(marker + chunk))
                offset += CHUNK_SIZE

    def _reset_reassembly(self) -> None:
        self._reasm = None
        self._reasm_is_json = False

    def _guard_cap(self) -> None:
        if self._reasm is not None and len(self._reasm) > self._max_reassembly:
            size = len(self._reasm)
            self._reset_reassembly()
            msg = (f"multi-frame reassembly exceeded the {self._max_reassembly} "
                   f"byte cap ({size} bytes buffered); dropping the message")
            LOG.error(msg)
            raise NoiseTransportFailed(msg)

    def decrypt_frame(self, data: bytes) -> Optional[Union[str, bytes]]:
        """Decrypt one incoming Noise transport message.

        A SINGLE frame is decoded and returned immediately. A multi-frame
        message is reassembled across calls: FIRST/MORE chunks buffer and
        return ``None`` ("no complete message yet"); the LAST chunk decodes
        the whole buffer and returns it. Callers must treat a ``None`` return
        as "keep receiving" and not dispatch it.

        Returns:
            The decoded message (str for JSON, bytes for binary), or ``None``
            when this frame only advanced an in-progress reassembly.

        Raises:
            NoiseTransportFailed: on any AEAD failure — tampering, replay, or
                out-of-order delivery (per HIVEMIND-CRYPTO-1 §3.4.5, fatal for
                the session) — or on a malformed multi-frame sequence (a
                MORE/LAST chunk with no open buffer, a new message starting
                while one is still open, or the reassembly cap exceeded).
        """
        with self._recv_lock:
            try:
                plaintext = self._hs.decrypt(bytes(data))
            except Exception as e:
                raise NoiseTransportFailed(
                    f"Noise transport message rejected (tampered, replayed "
                    f"or out-of-order): {e}") from e

            marker, body = plaintext[:1], plaintext[1:]

            if marker in (_FRAME_JSON, _FRAME_BINARY):
                if self._reasm is not None:
                    size = len(self._reasm)
                    self._reset_reassembly()
                    msg = (f"single frame arrived while {size} bytes of a "
                           f"multi-frame message were still buffered")
                    LOG.error(msg)
                    raise NoiseTransportFailed(msg)
                if marker == _FRAME_JSON:
                    return body.decode("utf-8")
                return body

            if marker in (_FRAME_FIRST_JSON, _FRAME_FIRST_BINARY):
                if self._reasm is not None:
                    size = len(self._reasm)
                    self._reset_reassembly()
                    msg = (f"a new multi-frame message started while {size} "
                           f"bytes of a previous one were still buffered")
                    LOG.error(msg)
                    raise NoiseTransportFailed(msg)
                self._reasm = bytearray(body)
                self._reasm_is_json = (marker == _FRAME_FIRST_JSON)
                self._guard_cap()
                return None

            if marker == _FRAME_MORE:
                if self._reasm is None:
                    msg = "MORE chunk arrived with no multi-frame message open"
                    LOG.error(msg)
                    raise NoiseTransportFailed(msg)
                self._reasm += body
                self._guard_cap()
                return None

            if marker == _FRAME_LAST:
                if self._reasm is None:
                    msg = "LAST chunk arrived with no multi-frame message open"
                    LOG.error(msg)
                    raise NoiseTransportFailed(msg)
                self._reasm += body
                self._guard_cap()
                buf, is_json = self._reasm, self._reasm_is_json
                self._reset_reassembly()
                if is_json:
                    return bytes(buf).decode("utf-8")
                return bytes(buf)

            raise NoiseTransportFailed(f"unknown v3 frame marker: {marker!r}")


def start_noise_handshake(initiator: bool,
                          pattern: str,
                          suite: str,
                          password: Optional[Union[str, bytes]],
                          node_id: str,
                          prologue: bytes,
                          key_path: Optional[str] = None,
                          remote_pubkey: Optional[str] = None,
                          *,
                          psk: Optional[bytes] = None
                          ) -> "NoiseHandShake":
    """Initialize a Noise handshake for a HiveMind protocol-v3 connection.

    The PSK is derived from the shared site password with argon2id, salted
    by ``SHA-256(node_id)`` of the *server's* node id (HIVEMIND-CRYPTO-1
    §3.4.4). The static X25519 key is loaded from (or generated and
    persisted to) ``key_path``.

    Args:
        initiator: True on the node (client) side, False on the server side.
        pattern: selected handshake pattern (``XXpsk2`` or ``KKpsk0``).
        suite: selected cipher suite (e.g. ``25519_ChaChaPoly_SHA256``).
        password: the shared site password (the only secret; never
            transmitted — it authenticates the handshake as the Noise PSK).
            May be omitted if ``psk`` is supplied instead.
        node_id: the server's node id announced in its cleartext HELLO.
        prologue: bytes from :func:`build_prologue`.
        key_path: where the static X25519 private key persists.
        remote_pubkey: hex-encoded pinned remote static key (required for
            ``KKpsk0``).
        psk: a precomputed 32-byte pre-shared key, i.e. the output of
            ``derive_psk(password, node_id=node_id)``. Deriving the PSK
            runs argon2id (time_cost=3, memory_cost=64 MiB), which takes
            150-330ms; since the salt is ``SHA-256(node_id)`` the result is
            constant for a given (password, node_id) pair, so callers that
            handshake repeatedly against the same node should derive it
            once and pass it here to skip re-deriving it every time. It
            must equal ``derive_psk(password, node_id=node_id)`` for this
            node — a mismatched psk does not fail locally, it makes the
            handshake fail on the peer. Takes precedence over ``password``
            when both are given, matching :class:`NoiseHandShake`.
    """
    if not NOISE_SUPPORTED:
        raise NoiseHandshakeFailed(
            "poorman-handshake was installed without the noise primitive")
    if psk is None and password is None:
        raise ValueError("either 'password' or 'psk' is required")
    name = noise_protocol_name(pattern, suite)
    if key_path and os.path.dirname(key_path):
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
    try:
        return NoiseHandShake(
            initiator=initiator,
            path=key_path,
            password=password,
            node_id=node_id,
            psk=psk,
            remote_pubkey=remote_pubkey if pattern == NOISE_PATTERN_KK else None,
            prologue=prologue,
            pattern=name.encode("utf-8"),
        )
    except Exception as e:
        raise NoiseHandshakeFailed(f"failed to initialize {name}: {e}") from e
