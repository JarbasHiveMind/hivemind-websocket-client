[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/JarbasHiveMind/hivemind-websocket-client)

# HiveMind Bus Client

Python client library for [hivemind-core](https://github.com/JarbasHiveMind/HiveMind-core) — the primary library for building HiveMind satellites.

Extends the standard OVOS bus client with secure, encrypted, routed communication across a HiveMind mesh network. See the [whitepaper](https://github.com/JarbasHiveMind/HiveMind-core/blob/dev/docs/whitepaper.md) for protocol details.

## Install

```bash
uv pip install hivemind_bus_client
```

## Quick Start

```python
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from ovos_bus_client.message import Message

client = HiveMessageBusClient(host="ws://localhost", port=5678)
client.connect()

client.on_mycroft("speak", lambda msg: print(msg.data["utterance"]))

client.emit(HiveMessage(HiveMessageType.BUS,
                        Message("recognizer_loop:utterance",
                                {"utterances": ["hello world"]})))
```

## Message Types

| Type | Direction | Description |
|------|-----------|-------------|
| `BUS` | satellite ↔ master | Standard AI bus message |
| `ESCALATE` | upstream | Forward up the authority chain |
| `QUERY` | upstream + response | First answering node wins |
| `BROADCAST` | downstream | Admin pushes to all satellites |
| `PROPAGATE` | flood | Forward to all peers in all directions |
| `CASCADE` | flood + responses | Collect answers from all nodes |
| `INTERCOM` | any → any | End-to-end hybrid-encrypted (AES-GCM + RSA) |
| `PING` | inside PROPAGATE | Flood-based network topology discovery |

## Security

- **Per-link encryption**: AES-GCM or ChaCha20-Poly1305, negotiated at handshake
- **Hybrid INTERCOM encryption**: Random AES-256 key per message, RSA-encrypted key exchange
- **Trusted peers**: `NodeIdentity.trusted_keys` gates BUS injection for PROPAGATE and INTERCOM from untrusted peers
- **Topology-as-policy**: Network structure determines access control (see whitepaper §4)

## Trusted Keys

```python
from hivemind_bus_client.identity import NodeIdentity

identity = NodeIdentity()
identity.add_trusted_key("living-room-hub", "<RSA_PUBLIC_KEY>")
identity.save()
```

Untrusted PROPAGATE(BUS) and INTERCOM messages are silently dropped.

## CASCADE Response Aggregation

CASCADE collects responses from all reachable nodes via `CascadeAggregator`:

```python
proto.cascade_select_callback = lambda responses: responses[0]  # pick best
proto.hive_mapper = mapper  # enables early resolution when all nodes answered
```

## CLI

```bash
hivemind-client set-identity --key KEY --password PASS --siteid SITE
hivemind-client terminal --host ws://hub.local --port 5678
hivemind-client ping --host ws://hub.local --port 5678
hivemind-client send-mycroft --msg "recognizer_loop:utterance" --payload '{"utterances": ["hello"]}'
hivemind-client escalate --msg "recognizer_loop:utterance" --payload '{"utterances": ["hello"]}'
hivemind-client propagate --msg "recognizer_loop:utterance" --payload '{"utterances": ["hello"]}'
```

## Documentation

Full docs in [`/docs`](docs/index.md):

- [API Reference](docs/api.md) — `HiveMessage`, `HiveMessageBusClient`, `NodeIdentity`, `HiveMapper`
- [Message Types](docs/message_types.md) — Routing modes, QUERY, CASCADE, PING
- [Identity & Trust](docs/identity.md) — Credentials, RSA keys, trusted peers
- [Examples](docs/examples.md) — Chat, TTS, INTERCOM, QUERY, CASCADE, trust management
- [CLI Guide](docs/cli_guide.md) — Terminal, ping, send commands
- [Serialization](docs/serialization.md) — Binary wire format
