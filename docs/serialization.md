# Binary Serialization Protocol

The HiveMind binary serialization protocol (`hivemind_bus_client/serialization.py`) encodes `HiveMessage` objects into compact bitstrings for efficient WebSocket transport. This is the reference implementation. Other language clients must produce identical wire bytes.

## Protocol Version

Current version: **1** (`PROTOCOL_VERSION`, `serialization.py`).

Decoding a bitstring with an unsupported version raises `UnsupportedProtocolVersion` (`exceptions.py`).

## Wire Format (v1)

All fields are packed MSB-first. The bitstring is left-padded with `0` bits to reach a byte boundary. The first `1` bit marks the start of meaningful data.

```
┌─────────────┬───────────┬─────────────────────┬──────────┬──────────┬──────────────────┬────────────────┬──────────┐
│ Padding 0s  │ Start (1) │ Versioned (1 bit)   │ [Proto   │ Type     │ Compressed       │ Meta-length    │ Metadata │
│ (0+ bits)   │           │ 0=unversioned       │  Version │ (5 bits) │ (1 bit)          │ (8 bits = N    │ (N bytes)│
│             │           │ 1=versioned         │  8 bits] │          │ 0=raw, 1=zlib    │  bytes)        │          │
└─────────────┴───────────┴─────────────────────┴──────────┴──────────┴──────────────────┴────────────────┴──────────┘
                                                                       ┌────────────────────────────────────────────┐
                                                                       │ If Type == BINARY:                         │
                                                                       │   BinarySubtype (4 bits)                   │
                                                                       │ Payload (remaining bits)                   │
                                                                       └────────────────────────────────────────────┘
```

### Field Details

| Field | Bits | Description | Source |
|-------|------|-------------|--------|
| Padding | 0+ | Leading `0` bits for byte alignment | `_get_bitstring_v1`, `serialization.py` |
| Start marker | 1 | Always `1`. Decoder skips `0`s until it finds this | `serialization.py` |
| Versioned flag | 1 | `1` = next 8 bits are a protocol version, `0` = assume current version | `serialization.py` |
| Protocol version | 8 (optional) | Only present when versioned=1. Integer protocol version | `serialization.py` |
| Message type | 5 | Index into `_INT2TYPE` mapping (13 types, 0-12) | `serialization.py`, `_INT2TYPE`, `serialization.py` |
| Compressed | 1 | `1` = payload is zlib-compressed | `serialization.py` |
| Metadata length | 8 | Number of **bytes** of metadata that follow | `serialization.py` |
| Metadata | N×8 | JSON-encoded dict, optionally zlib-compressed | `serialization.py` |
| Binary subtype | 4 (conditional) | Only for `BINARY` type. Maps to `HiveMindBinaryPayloadType` | `serialization.py` |
| Payload | remaining | JSON string (text types) or raw bytes (BINARY type) | `serialization.py` |

### Type Map (`_INT2TYPE`, `serialization.py`)

| Integer | HiveMessageType |
|---------|-----------------|
| 0 | HANDSHAKE |
| 1 | BUS |
| 2 | SHARED_BUS |
| 3 | BROADCAST |
| 4 | PROPAGATE |
| 5 | ESCALATE |
| 6 | HELLO |
| 7 | QUERY |
| 8 | CASCADE |
| 9 | PING |
| 10 | RENDEZVOUS |
| 11 | THIRDPRTY |
| 12 | BINARY |

Codes 13-31 are **unassigned**. Per HIVEMIND-WIRE-1 §4.2 a receiver
**MUST** reject a frame carrying an unassigned message-type code as
malformed: `decode_bitstring()` raises `ValueError` for any code not in
this map instead of silently coercing it to a type. The three client
receive loops (`client.py`, `async_client.py`, `http_client.py`) catch
that error, log it, and drop the frame rather than crashing.

> **Spec-vs-impl note.** This numbering is the wire reality retained for
> compatibility with deployed encoders and the HiveMind-js peer; it does
> **not** match the aspirational table in HIVEMIND-WIRE-1 §4.2 (which
> lists 6=INTERCOM, 7=PING, 8/11=reserved, 9=HELLO, 10=THIRDPRTY and
> makes QUERY/CASCADE/RENDEZVOUS text-only wrapper types). Reconciling
> the two is a wire-breaking change reserved for a coordinated spec
> revision; only the unassigned-code rejection (13-31) is enforced here.

### Binary Payload Subtypes (`HiveMindBinaryPayloadType`, `message.py`)

| Integer | Subtype | Description |
|---------|---------|-------------|
| 0 | UNDEFINED | No info about binary contents |
| 1 | RAW_AUDIO | Raw audio data |
| 2 | NUMPY_IMAGE | Image as numpy array |
| 3 | FILE | Generic file transfer |
| 4 | STT_AUDIO_TRANSCRIBE | Audio for STT transcription |
| 5 | STT_AUDIO_HANDLE | Audio for STT + immediate handling |
| 6 | TTS_AUDIO | Synthesized TTS audio |

## Public API

### `get_bitstring()`, `serialization.py`

Encode a `HiveMessage` to a `BitArray`.

```python
from hivemind_bus_client.serialization import get_bitstring
from hivemind_bus_client.message import HiveMessageType

bitstr = get_bitstring(
    hive_type=HiveMessageType.BUS,
    payload=message,          # Message, HiveMessage, str, dict, or bytes
    compressed=None,          # None=auto (pick smaller), True/False=force
    hivemeta=None,            # optional dict of metadata
    binary_type=...,          # HiveMindBinaryPayloadType (for BINARY only)
    proto_version=1,          # protocol version
    versioned=False,          # embed version in bitstring
)
# Returns: BitArray, call .bytes for raw bytes
```

When `compressed=None`, both compressed and uncompressed encodings are generated and the smaller one is returned (`serialization.py`).

### `decode_bitstring()`, `serialization.py`

Decode raw bytes back to a `HiveMessage`.

```python
from hivemind_bus_client.serialization import decode_bitstring

hive_msg = decode_bitstring(raw_bytes)  # returns HiveMessage
```

### `BINARY_ENCODABLE_TYPES`, `serialization.py`

The frozen set of message types that have a 5-bit wire code. `INTERCOM` is not in it: it
has never had a code, so it can only travel as a text frame. `_get_bitstring_v1` raises
`ValueError` for a type outside this set instead of relabelling the frame as `THIRDPRTY`,
which is what it used to do. Senders check the set before they pick a framing.

### `mycroft2bitstring()`, `serialization.py`

Convenience wrapper: encode an OVOS `Message` as a `BUS`-type bitstring, using `msg.context` as metadata.

```python
from hivemind_bus_client.serialization import mycroft2bitstring

bitstr = mycroft2bitstring(msg, compressed=False)
```

## Auto-Compression

`get_bitstring(compressed=None)` encodes the payload both ways and returns whichever is smaller. The `compressed` bit in the wire format tells the decoder which path to take. For small payloads, uncompressed is often smaller. For payloads over ~200 bytes, zlib compression typically wins.

## Cross-Language Implementors

To implement a compatible encoder/decoder:

1. Pack fields in the exact order and bit widths above
2. Use zlib (RFC 1950) for compression
3. JSON-encode metadata and non-binary payloads as UTF-8 before compression
4. Left-pad with `0` bits to byte-align, then prepend a `1` start marker
5. For `BINARY` messages, the 4-bit subtype appears before the raw payload bytes
6. Test against the Python reference implementation using the cross-platform vectors that
   `HiveMind-js/test/generate_vectors.py` produces. `tests/test_serialization.py` loads
   them and skips when the file is absent

---
[← Message Types](message_types.md) · [Home](index.md) · [Binary Handlers →](binary_handlers.md)
