
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

## QUERY — Request-Response Upstream

QUERY is the request-response counterpart to ESCALATE. The originator sends a query upstream; the first node whose agent can answer sends a response back. Propagation stops once an answer is found.

### Sending a QUERY

```python
import uuid
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

query_id = str(uuid.uuid4())
bus_msg = Message("recognizer_loop:utterance",
                  {"utterances": ["what is 2+2?"]})
inner = HiveMessage(HiveMessageType.BUS, payload=bus_msg)
query = HiveMessage(
    HiveMessageType.QUERY,
    payload=inner,
    metadata={
        "query_id": query_id,
        "originator_peer": client.peer,
        "is_response": False,
    },
)
client.emit(query)
```

### Receiving a QUERY Response

```python
def on_query(message: HiveMessage) -> None:
    meta = message.metadata or {}
    if meta.get("is_response"):
        # Response received — inner payload is BUS(speak/etc.)
        inner_bus = message.payload.payload  # OVOS Message
        print(f"Answer from {meta.get('responder_peer')}: {inner_bus.data}")
    else:
        # Request forwarded to us (relay scenario)
        pass

client.on(HiveMessageType.QUERY, on_query)
```

### QUERY Metadata

| Field | Type | Description |
|-------|------|-------------|
| `query_id` | `str` | UUID correlation ID |
| `originator_peer` | `str` | Who started the query |
| `is_response` | `bool` | `False`=request, `True`=response |
| `responder_peer` | `str` | (response only) Who answered |

## CASCADE — Request-Response Flood

CASCADE is the request-response counterpart to PROPAGATE. The originator's query floods the entire hive, and **every** node's agent can respond. All responses are collected back at the originator for disambiguation.

### Sending a CASCADE

```python
import uuid
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

query_id = str(uuid.uuid4())
bus_msg = Message("recognizer_loop:utterance",
                  {"utterances": ["what is the weather?"]})
inner = HiveMessage(HiveMessageType.BUS, payload=bus_msg)
cascade = HiveMessage(
    HiveMessageType.CASCADE,
    payload=inner,
    metadata={
        "query_id": query_id,
        "originator_peer": client.peer,
        "is_response": False,
    },
)
client.emit(cascade)
```

### Receiving CASCADE Responses

```python
collected = []

def on_cascade(message: HiveMessage) -> None:
    meta = message.metadata or {}
    if meta.get("is_response"):
        collected.append({
            "from": meta.get("responder_peer"),
            "site": meta.get("responder_site_id"),
            "message": message.payload.payload,  # OVOS Message
        })
        print(f"Response {len(collected)} from {meta['responder_peer']}")

client.on(HiveMessageType.CASCADE, on_cascade)
```

### CASCADE Disambiguation (Server-Side)

On the master, set `cascade_select_callback` to pick the best answer:

```python
from hivemind_core.protocol import CascadeResponse
from ovos_bus_client.message import Message
from typing import List, Optional

def select_best(query_id: str, responses: List[CascadeResponse]) -> Optional[Message]:
    """Called each time a new CASCADE response arrives.
    Return a Message to emit on the bus, or None to wait for more."""
    if len(responses) >= 3:
        # Pick best by some scoring logic
        best = max(responses, key=lambda r: len(r.messages))
        return best.messages[0] if best.messages else None
    return None

hm_protocol.cascade_select_callback = select_best
```

---

## Serialization and Encryption

Before being sent over the network, `HiveMessage` objects are:
1. **Serialized**: Using `hivemind_bus_client.serialization.HiveMessageSerializer`.
2. **Encrypted**: Using AES-256-GCM in `hivemind_bus_client.encryption.HiveMessageEncryptor`.
3. **Encoded**: Frequently using Z85+Base91 for safe text transport in `hivemind_bus_client.encodings`.

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
