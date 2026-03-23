
HiveMind communication is based on the `HiveMessage` class (defined in `hivemind_bus_client.message.HiveMessage`), which wraps standard AI bus messages with HiveMind-specific metadata and routing instructions.

## `HiveMessage` Fields

- **`msg_type`**: A value from the `HiveMessageType` enum.
- **`payload`**: The actual message (an OVOS `Message` for BUS types, `bytes` for BIN types).
- **`context`**: Metadata used for routing and tracking (optional).

## `HiveMessageType` (The Routing Modes)

The `msg_type` (defined in `hivemind_bus_client.message.HiveMessageType`) dictates how the Mind should handle the message.

| Type | Purpose | Use Case |
|---|---|---|
| **`BUS`** | Standard message for the AI | Utterances, intent triggers, speak events. |
| **`BIN`** | Raw binary data | Audio streams for STT/TTS, file transfers. |
| **`ESCALATE`** | Upstream request | Used by a Slave Mind to ask a Master Mind for help. |
| **`BROADCAST`** | Downstream flood (admin only) | Master pushes a message to all connected satellites. |
| **`PROPAGATE`** | Bidirectional flood | Forwards to all peers in both directions. |
| **`INTERCOM`** | End-to-end encrypted | Secure peer-to-peer messaging between Satellites. |
| **`QUERY`** | Request-response upstream | Like ESCALATE, but first answering node sends a response back. Stops propagation on answer. |
| **`CASCADE`** | Request-response flood | Like PROPAGATE, but expects responses from ALL nodes. Supports disambiguation. |
| **`PING`** | Network discovery flood | Each node responds with its own PING (same `flood_id`). Carried inside PROPAGATE. Route metadata = hive path. |
| **`HELLO`** | Node announcement | Session sync at connection time. |
| **`HANDSHAKE`** | Crypto negotiation | Key exchange at connection time. |
| **`THIRDPRTY`** | User-land custom | Application-defined payload; HiveMind relays without interpretation. |

## PING Flood — Network Discovery

PING messages are **always the inner payload of a PROPAGATE message**. They are never sent bare. Each node that receives a PING responds with its own PING carrying the same `flood_id`. The `flood_id` prevents infinite loops. PONG is no longer used.

### Sending a PING

```python
import time, uuid
from hivemind_bus_client.message import HiveMessage, HiveMessageType

flood_id = str(uuid.uuid4())
ping_inner = HiveMessage(
    HiveMessageType.PING,
    payload={
        "flood_id":  flood_id,
        "timestamp": time.time(),
        "peer":      client.peer,
        "site_id":   client.site_id,
    }
)
ping_outer = HiveMessage(HiveMessageType.PROPAGATE, payload=ping_inner)
client.emit(ping_outer)
```

### Receiving responsive PINGs

```python
def on_ping(message: HiveMessage) -> None:
    payload = message.payload          # inner PING dict
    route   = message.route            # List[{source, targets}] — the hive path
    print(f"PING from {payload['peer']} via {len(route)} hops")

client.on(HiveMessageType.PING, on_ping)
```

For automated topology collection use `HiveMapper` from `hivemind_core.hive_map`.

---

## Route Metadata

Every `HiveMessage` has a `route` field: `List[Dict[str, Any]]` — an ordered list of hops tracking the network path.

### Hop Structure

Each hop is a dict: `{"source": "peer_id", "targets": ["peer_id1", "peer_id2"]}`.

- `source`: the peer that forwarded the message at this hop
- `targets`: the peers the message was sent to from this hop

### Multi-Hop Example

After S0 → R1 → M0 traversal:

```python
message.route == [
    {"source": "S0_peer_id", "targets": ["R1_peer_id"]},
    {"source": "R1_peer_id", "targets": ["M0_peer_id"]},
]
```

### Route API

```python
# Record a hop (called automatically by protocol layer)
message.update_hop_data()

# Replace route (used when transferring between wrapper/inner messages)
message.replace_route(other_message.route)

# Read route (filters incomplete hops)
for hop in message.route:
    print(f"{hop['source']} → {hop['targets']}")
```

### Serialization

Route survives `as_dict()` → `deserialize()` roundtrips. The `route` field is included in JSON serialization and restored on deserialization (`message.py:208-231`).

---

## Serialization and Encryption

Before being sent over the network, `HiveMessage` objects are:
1. **Serialized**: Using functions in `hivemind_bus_client.serialization` (`get_bitstring`, `decode_bitstring`).
2. **Encrypted**: Using AES-256-GCM via functions in `hivemind_bus_client.encryption`.
3. **Encoded**: Frequently using Z85+Base91 for safe text transport via `hivemind_bus_client.encodings`.

### Examples

#### Sending a Standard Bus Message
```python
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

hive_msg = HiveMessage(HiveMessageType.BUS, 
                       Message("mycroft.stop"))
```

#### Sending Binary Audio Data
```python
audio_bytes = b"..." # Raw PCM audio
hive_msg = HiveMessage(HiveMessageType.BIN, audio_bytes)
```
