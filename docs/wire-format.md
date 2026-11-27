# Wire format
<!-- agent-hint
covers: the bit layout of a binary frame, the 5-bit type codes, the binary subtypes, and the rules for an encoder or decoder in another language
source: hivemind_bus_client/serialization.py:_get_bitstring_v1, hivemind_bus_client/serialization.py:decode_bitstring, hivemind_bus_client/util.py:cast2bytes
generated: no
verify: diff <(python <(awk '/^```python/{f=1;next} f&&/^```/{exit} f' docs/wire-format.md) 2>/dev/null) <(awk '/^```text/{f=1;next} f&&/^```/{exit} f' docs/wire-format.md)
see: messages.md
-->

A binary frame packs one `HiveMessage` into a bit string. `hivemind_bus_client/serialization.py` is the reference encoder and decoder. An implementation in another language must make the same bytes.

## Example

```python
from hivemind_bus_client.message import HiveMessageType, HiveMindBinaryPayloadType
from hivemind_bus_client.serialization import get_bitstring, decode_bitstring

frame = get_bitstring(HiveMessageType.BINARY, b"\x01\x02", compressed=False,
                      binary_type=HiveMindBinaryPayloadType.RAW_AUDIO)
print(frame.bin)
print(frame.bytes.hex())
back = decode_bitstring(frame.bytes)
print(back.msg_type, back.bin_type, back.payload)
```

```text
00001001100000000010011110110111110100010000000100000010
098027b7d10102
HiveMessageType.BINARY 1 b'\x01\x02'
```

The 56 bits of the frame, from left to right:

| Bits | Value | Field |
| :--- | :--- | :--- |
| `0000` | | Padding to a byte boundary |
| `1` | 1 | Start marker |
| `0` | 0 | Versioned flag: no version field follows |
| `01100` | 12 | Message type `BINARY` |
| `0` | 0 | Compressed flag: not compressed |
| `00000010` | 2 | Metadata length in bytes |
| `01111011 01111101` | `{}` | Metadata |
| `0001` | 1 | Binary subtype `RAW_AUDIO` |
| `00000001 00000010` | `01 02` | Payload |

The decoder gives `bin_type` as the integer value of the subtype.

## Bit layout

The encoder writes the fields in this order, the most significant bit first:

```text
[padding 0s] 1 [versioned:1] [version:8, only when versioned=1] [type:5] [compressed:1] [meta_len:8] [metadata:meta_len bytes] [subtype:4, BINARY only] [payload]
```

| Field | Bits | Content |
| :--- | :--- | :--- |
| Padding | 0 to 7 | `0` bits on the left, so that the frame is a whole number of bytes |
| Start marker | 1 | Always `1`. The decoder skips `0` bits until it reads this bit |
| Versioned flag | 1 | `1` when a protocol version follows. `0` means version 1 |
| Protocol version | 8 | Only when the versioned flag is `1`. `PROTOCOL_VERSION` is 1 |
| Message type | 5 | A code from the type table below |
| Compressed flag | 1 | `1` when zlib compresses the metadata and the payload |
| Metadata length | 8 | Number of metadata bytes. The maximum is 255 (`MAX_METADATA_BYTES`) |
| Metadata | 8 × length | A JSON object, compressed when the flag is `1` |
| Binary subtype | 4 | Only for `BINARY`. A `HiveMindBinaryPayloadType` value |
| Payload | the rest | For `BINARY`, the raw bytes. For another type, a JSON object, compressed when the flag is `1` |

The encoder writes `{}` when there is no metadata. The decoder reads a metadata length of 0 as `{}`.

## Type codes

| Code | Type |
| :--- | :--- |
| 0 | `HANDSHAKE` |
| 1 | `BUS` |
| 2 | `SHARED_BUS` |
| 3 | `BROADCAST` |
| 4 | `PROPAGATE` |
| 5 | `ESCALATE` |
| 6 | `HELLO` |
| 7 | `QUERY` |
| 8 | `CASCADE` |
| 9 | `PING` |
| 10 | `RENDEZVOUS` |
| 12 | `BINARY` |

Code 11 was `THIRDPRTY`, which is removed. Code 11 and codes 13 to 31 have no type. A new type takes the next free code from 13, never 11. `INTERCOM` has no code, so it always travels as text, and `get_bitstring()` raises `ValueError` for it. `BINARY_ENCODABLE_TYPES` is the set of the types that have a code.

The binary subtypes are in [Messages](messages.md#binary-payloads).

## Errors

| Error | Cause |
| :--- | :--- |
| `MalformedBinaryFrame` | The decoder reads a type code with no type, a metadata length longer than the rest of the frame, a frame that ends too soon, or data that is not valid JSON or zlib |
| `UnsupportedProtocolVersion` | The frame has a version above 1, or `get_bitstring()` gets `proto_version` above 1 |
| `MetadataTooLarge` | The metadata is more than 255 bytes. With `compressed=None`, the encoder tries the compressed form first |
| `MalformedWirePayload` | A `BINARY` payload that is not bytes, or another payload that is not a JSON object |

All four are `ValueError` subclasses. The clients drop a frame that does not decode, and keep the connection.

## Encoder rules for other languages

1. Write the fields in the order and the widths of the bit layout.
2. Encode JSON as UTF-8. Compress with zlib (RFC 1950) after the JSON encoding.
3. When the compressed flag is `1`, compress the metadata and the payload separately. Never compress the subtype or the raw bytes of a `BINARY` payload.
4. Add the `0` padding on the left of the start marker, never on the right of the payload.
5. Refuse an unassigned type code as malformed. Do not map it to another type.
6. Test against the cross-platform vectors of `HiveMind-js/test/generate_vectors.py`. `tests/test_serialization.py` loads them, and skips the test when the file is not there.

`get_bitstring(compressed=None)` makes both forms and returns the shorter one. For a short payload, the form without compression is often shorter.

---
[← Routing and peers](routing-and-peers.md) · [Home](index.md) · [Security →](security.md)
