# API Reference

## `HiveMessage` (`hivemind_bus_client/message.py:45`)

The fundamental message type exchanged across the HiveMind network.

### Properties

| Property | Type | Description | Source |
|---|---|---|---|
| `msg_type` | `str` | One of the `HiveMessageType` values | `message.py:105` |
| `payload` | `Message \| HiveMessage \| dict \| bytes` | Message content; automatically cast to the appropriate type | `message.py:128` |
| `bin_type` | `HiveMindBinaryPayloadType` | Binary payload subtype (only for `BINARY` messages) | `message.py:164` |
| `metadata` | `dict` | Auxiliary metadata (e.g. `sample_rate`, `lang`, `file_name`) | `message.py:94` |
| `node_id` | `str` | Node semi-unique identifier | `message.py:109` |
| `source_peer` | `str` | Peer ID of the sender | `message.py:114` |
| `target_peers` | `list[str]` | Intended recipients | `message.py:118` |
| `target_site_id` | `str` | Route to a specific site ID | `message.py:98` |
| `target_public_key` | `str` | Route to a specific RSA public key (used with INTERCOM) | `message.py:102` |
| `route` | `list[dict]` | Hop history | `message.py:123` |

### Serialization

- `serialize()` (`message.py:200`): Returns the JSON string representation of the message.
- `deserialize(payload)` (`message.py:204`): Reconstructs a `HiveMessage` from a JSON string or dictionary.

---

## `HiveMessageType` (`hivemind_bus_client/message.py:9`)

Enumeration of HiveMind message types.

| Value | String | Description |
|---|---|---|
| `HANDSHAKE` | `"shake"` | Connection negotiation and key exchange |
| `BUS` | `"bus"` | OVOS/Mycroft bus message destined for the hub agent |
| `SHARED_BUS` | `"shared_bus"` | Passive bus share from a satellite (monitoring only) |
| `INTERCOM` | `"intercom"` | Peer-to-peer encrypted message |
| `BROADCAST` | `"broadcast"` | Forward message to all slaves |
| `PROPAGATE` | `"propagate"` | Forward message to all slaves and masters |
| `ESCALATE` | `"escalate"` | Forward message up the authority chain |
| `HELLO` | `"hello"` | Node announcement and session setup |
| `QUERY` | `"query"` | Escalate until one node responds |
| `CASCADE` | `"cascade"` | Propagate expecting responses from all nodes |
| `PING` | `"ping"` | Network topology discovery (flood-based; PONG removed) |
| `BINARY` | `"bin"` | Raw binary data container |
| `THIRDPRTY` | `"3rdparty"` | User-defined message type |

---

## `HiveMindBinaryPayloadType` (`hivemind_bus_client/message.py:33`)

Describes the content of a `BINARY` message.

| Value | Int | Description |
|---|---|---|
| `UNDEFINED` | `0` | Unknown binary content |
| `RAW_AUDIO` | `1` | Raw PCM audio |
| `NUMPY_IMAGE` | `2` | NumPy image array |
| `FILE` | `3` | Generic file transfer |
| `STT_AUDIO_TRANSCRIBE` | `4` | Audio for STT — return transcripts |
| `STT_AUDIO_HANDLE` | `5` | Audio for STT — transcribe and handle immediately |
| `TTS_AUDIO` | `6` | Synthesized TTS audio to be played back |

---

## `HiveMessageBusClient` (`hivemind_bus_client/client.py:93`)

WebSocket client that extends `ovos_bus_client.MessageBusClient`.

### Core Methods

- `connect(bus=FakeBus(), protocol=None, site_id=None)` (`client.py:193`): Connects to the HiveMind hub, starts the background thread, and waits for the handshake to complete.
- `emit(message, binary_type=UNDEFINED)` (`client.py:348`): Sends a `HiveMessage` or `MycroftMessage`. Automatically injects routing context for `BUS` messages (`client.py:379`).
- `on(event_name, func)` (`client.py:434`): Registers a handler. Automatically detects if the event name is a `HiveMessageType` or a standard OVOS message type (`client.py:435`).
- `on_mycroft(mycroft_msg_type, func)` (`client.py:429`): Explicitly registers a handler for an OVOS internal bus message.
- `remove(event_name, func)` (`client.py:447`): Removes a registered handler.
- `wait_for_handshake(timeout=5, max_retries=15)` (`client.py:236`): Blocks until the cryptographic handshake with the hub is finished.
- `emit_intercom(message, pubkey)` (`client.py:538`): Sends an RSA-encrypted message targeted at a specific node's public key.

### Waiting for Messages

- `wait_for_message(message_type, timeout=3.0)` (`client.py:454`): Blocks until a specific `HiveMessageType` is received.
- `wait_for_payload(payload_type, message_type=THIRDPRTY, timeout=3.0)` (`client.py:467`): Blocks until a message of a specific type with a specific payload type is received.
- `wait_for_mycroft(mycroft_msg_type, timeout=3.0)` (`client.py:484`): Blocks until a specific OVOS message is received over the `BUS` message type.
- `wait_for_response(message, reply_type=None, timeout=3.0)` (`client.py:488`): Sends a message and waits for a response.
- `wait_for_payload_response(message, payload_type, reply_type=None, timeout=3.0)` (`client.py:511`): Sends a message and waits for a specific payload in the response.

---

## `BinaryDataCallbacks` (`hivemind_bus_client/client.py:26`)

Base class for handling incoming binary data.

- `handle_receive_tts(bin_data, utterance, lang, file_name)` (`client.py:27`): Called when TTS audio is received.
- `handle_receive_file(bin_data, file_name)` (`client.py:33`): Called when a file is received.

---

## `NodeIdentity` (`hivemind_bus_client/identity.py:7`)

Manages the node's identity, including credentials and RSA keys.

- `save()` (`identity.py:153`): Persists identity settings to disk.
- `reload()` (`identity.py:159`): Reloads settings from the identity file.
- `create_keys()` (`identity.py:165`): Generates a new RSA key pair.

---

## `HiveMessageWaiter` / `HivePayloadWaiter` (`hivemind_bus_client/client.py:38`, `78`)

Utility classes used for one-shot message waiting. These are used internally by the `wait_for_*` methods of `HiveMessageBusClient`.
