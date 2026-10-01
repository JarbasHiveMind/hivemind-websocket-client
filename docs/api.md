# API Reference

## `HiveMessage` (`hivemind_bus_client/message.py`)

The fundamental message type exchanged across the HiveMind network.

### Properties

| Property | Type | Description | Source |
|---|---|---|---|
| `msg_type` | `str` | One of the `HiveMessageType` values | `message.py` |
| `payload` | `Message \| HiveMessage \| dict \| bytes` | Message content, automatically cast to the appropriate type | `message.py` |
| `bin_type` | `HiveMindBinaryPayloadType` | Binary payload subtype (only for `BINARY` messages) | `message.py` |
| `metadata` | `dict` | Auxiliary metadata (e.g. `sample_rate`, `lang`, `file_name`) | `message.py` |
| `node_id` | `str` | Node semi-unique identifier | `message.py` |
| `source_peer` | `str` | Peer ID of the sender | `message.py` |
| `target_peers` | `list[str]` | Intended recipients | `message.py` |
| `target_site_id` | `str` | Route to a specific site ID | `message.py` |
| `target_public_key` | `str` | Route to a specific RSA public key (used with INTERCOM) | `message.py` |
| `route` | `list[dict]` | Hop history | `message.py` |

### Serialization

- `serialize()` (`message.py`): Returns the JSON string representation of the message.
- `deserialize(payload)` (`message.py`): Reconstructs a `HiveMessage` from a JSON string or dictionary.

---

## `HiveMessageType` (`hivemind_bus_client/message.py`)

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
| `QUERY` | `"query"` | Request-response upstream, first answering node wins |
| `CASCADE` | `"cascade"` | Request-response flood, collects responses from all nodes |
| `PING` | `"ping"` | Network topology discovery (flood-based) |
| `RENDEZVOUS` | `"rendezvous"` | Reserved for rendezvous nodes |
| `BINARY` | `"bin"` | Raw binary data container |

---

## `HiveMindBinaryPayloadType` (`hivemind_bus_client/message.py`)

Describes the content of a `BINARY` message.

| Value | Int | Description |
|---|---|---|
| `UNDEFINED` | `0` | Unknown binary content |
| `RAW_AUDIO` | `1` | Raw PCM audio |
| `NUMPY_IMAGE` | `2` | NumPy image array |
| `FILE` | `3` | Generic file transfer |
| `STT_AUDIO_TRANSCRIBE` | `4` | Audio for STT, return transcripts |
| `STT_AUDIO_HANDLE` | `5` | Audio for STT, transcribe and handle immediately |
| `TTS_AUDIO` | `6` | Synthesized TTS audio to be played back |

---

## `HiveMessageBusClient` (`hivemind_bus_client/client.py`)

WebSocket client that extends `ovos_bus_client.MessageBusClient`.

### Core Methods

- `connect(bus=FakeBus(), protocol=None, site_id=None, handshake_max_retries=None)` (`client.py`): Connects to the HiveMind hub, starts the background thread, and waits for the handshake to complete.
- `emit(message, binary_type=UNDEFINED)` (`client.py`): Sends a `HiveMessage` or `MycroftMessage`. It automatically injects routing context for `BUS` messages (`client.py`).
- `on(event_name, func)` (`client.py`): Registers a handler. It automatically detects if the event name is a `HiveMessageType` or a standard OVOS message type (`client.py`).
- `on_mycroft(mycroft_msg_type, func)` (`client.py`): Explicitly registers a handler for an OVOS internal bus message.
- `remove(event_name, func)` (`client.py`): Removes a registered handler.
- `wait_for_handshake(timeout=5, max_retries=None)` (`client.py`): Blocks until the cryptographic handshake with the hub is finished. By default it waits through reconnects forever. Pass `max_retries` for a hard timeout.
- `emit_intercom(message, pubkey)` (`client.py`, `async_client.py`, `http_client.py`): Sends a hybrid-encrypted (AES-GCM + RSA) message targeted at a specific node's public key, signed with this node's private key so the receiver can verify origin. Travels wrapped as `PROPAGATE(INTERCOM)`, not bare — a bare `INTERCOM` is consumed and dropped at the first node it reaches, since only the `PROPAGATE` handler relays a frame that is not addressed to it. All three clients build the same envelope shape.

### Waiting for Messages

- `wait_for_message(message_type, timeout=3.0)` (`client.py`): Blocks until a specific `HiveMessageType` is received.
- `wait_for_payload(payload_type, message_type=BUS, timeout=3.0)` (`client.py`): Blocks until a message of a specific type with a specific payload type is received.
- `wait_for_mycroft(mycroft_msg_type, timeout=3.0)` (`client.py`): Blocks until a specific OVOS message is received over the `BUS` message type.
- `wait_for_response(message, reply_type=None, timeout=3.0)` (`client.py`): Sends a message and waits for a response.
- `wait_for_payload_response(message, payload_type, reply_type=None, timeout=3.0)` (`client.py`): Sends a message and waits for a specific payload in the response.

---

## `BinaryDataCallbacks` (`hivemind_bus_client/client.py`)

Base class for handling incoming binary data.

- `handle_receive_tts(bin_data, utterance, lang, file_name)` (`client.py`): Called when TTS audio is received.
- `handle_receive_file(bin_data, file_name)` (`client.py`): Called when a file is received.

---

## `NodeIdentity` (`hivemind_bus_client/identity.py`)

Manages the node's identity, including credentials and RSA keys.

### Persistence

- `save()` (`identity.py`): Persists identity settings to disk.
- `reload()` (`identity.py`): Reloads settings from the identity file.
- `create_keys()` (`identity.py`): Generates a new RSA key pair.

### Trusted Keys

Trusted keys are stored as an alias → public key mapping in the identity file. Used by protocol handlers to gate BUS injection from PROPAGATE messages, and to verify the origin signature on INTERCOM messages — the connected master's announced key is checked as well, so a default deployment (empty `trusted_keys`) can still receive mail from its own master. See [Message Types](message_types.md) for what a consumer can and cannot trust about a delivered INTERCOM's source.

- `trusted_keys` (`identity.py`): `Dict[str, str]`, an alias-to-public-key mapping.
- `add_trusted_key(alias, pubkey)` (`identity.py`): Add a peer. Returns `False` if alias already exists.
- `remove_trusted_key(alias)` (`identity.py`): Remove by alias. Returns `False` if not found.
- `is_trusted_key(pubkey)` (`identity.py`): Check if a public key is trusted.
- `get_trusted_alias(pubkey)` (`identity.py`): Look up alias for a public key. Returns `None` if not found.

---

## `HiveMapper` (`hivemind_bus_client/hive_map.py`)

Collects responsive PINGs from a flood and builds a directed hive topology graph.

### Key Methods

- `on_ping(message, received_at=None)` (`hive_map.py`): Ingest a PING and update topology.
- `check_flood_id(flood_id, max_size=1000)` (`hive_map.py`): Flood-loop prevention with FIFO eviction.
- `mark_trusted_nodes(trusted_keys)` (`hive_map.py`): Set `NodeInfo.trusted` based on `NodeIdentity.trusted_keys`.
- `is_peer_trusted(peer)` (`hive_map.py`): Check if a discovered peer is trusted.
- `to_ascii(root_peer=None)` (`hive_map.py`): Render topology as ASCII tree.
- `to_dict()` / `to_json()` (`hive_map.py`): JSON-serialisable topology snapshot.

### `NodeInfo` (`hive_map.py`)

| Field | Type | Description |
|-------|------|-------------|
| `peer` | `str` | Peer identifier |
| `site_id` | `str?` | Location identifier |
| `public_key` | `str?` | RSA public key announced in PING |
| `lang` | `str?` | Locale announced by the node |
| `trusted` | `bool` | Whether this peer's key is in the trusted list |
| `timestamp` | `float?` | Sender's clock when PING was created |
| `latency_ms` | `float?` | Estimated one-way latency (computed property) |

---

## Decorators (`hivemind_bus_client/decorators.py`)

Convenience decorators for registering handlers on specific message types.

| Decorator | Message Type | Source |
|-----------|-------------|--------|
| `on_query(payload_type, bus)` | `QUERY` | `decorators.py` |
| `on_cascade(payload_type, bus)` | `CASCADE` | `decorators.py` |
| `on_propagate(payload_type, bus)` | `PROPAGATE` | `decorators.py` |
| `on_broadcast(payload_type, bus)` | `BROADCAST` | `decorators.py` |
| `on_escalate(payload_type, bus)` | `ESCALATE` | `decorators.py` |
| `on_ping(payload_type, bus)` | `PING` | `decorators.py` |
| `on_mycroft_message(payload_type, bus)` | `BUS` | `decorators.py` |
| `on_shared_bus(payload_type, bus)` | `SHARED_BUS` | `decorators.py` |
| `on_hive_message(message_type, bus)` | any | `decorators.py` |

---

## Encryption (`hivemind_bus_client/encryption.py`)

### Hybrid Encryption (INTERCOM)

- `hybrid_encrypt(public_key, plaintext, sign_key=None)` (`encryption.py`): AES-256-GCM payload + RSA-encrypted ephemeral key. Returns a JSON-serialisable dict.
- `hybrid_decrypt(private_key, envelope)` (`encryption.py`): Decrypts a hybrid-encrypted envelope.

### Symmetric Encryption (per-link)

- `encrypt_AES(key, text)` / `decrypt_AES_128(key, ciphertext, tag, nonce)`: AES-GCM
- `encrypt_ChaCha20_Poly1305(key, text)` / `decrypt_ChaCha20_Poly1305(key, ciphertext, tag, nonce)`: ChaCha20-Poly1305

---

## `HiveMessageWaiter` / `HivePayloadWaiter` (`hivemind_bus_client/client.py`)

Utility classes used for one-shot message waiting. These are used internally by the `wait_for_*` methods of `HiveMessageBusClient`.

---
[← Installation](installation.md) · [Home](index.md) · [Client API →](client_api.md)
