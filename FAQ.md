# Hivemind Websocket Client — FAQ

## Security

### How is the connection secured?
Cryptographic handshake negotiates a session key via RSA or shared password (PBKDF2). All subsequent traffic is encrypted using AES-GCM or ChaCha20-Poly1305. Supports `wss://` for additional transport-layer security.

## Usage

### How does PING flood discovery work from the satellite side?
When a satellite receives `PROPAGATE(PING)`, `HiveMindSlaveProtocol._handle_ping()` builds a responsive PING with the same `flood_id` and sends it upstream. The `flood_id` is tracked to prevent re-announcing when the satellite's own PING bounces back.
Source: `_handle_ping` — `protocol.py:292`

### What is `flood_id` deduplication?
Each satellite tracks `flood_id` values it has already responded to. If a PING arrives with a previously-seen `flood_id`, the satellite skips sending a responsive PING (avoiding infinite flood loops). The PING is still dispatched to local handlers for topology updates.

### How do I handle binary data like audio?
Subclass `BinaryDataCallbacks` and pass an instance to the `HiveMessageBusClient` constructor. This lets you define custom logic for when the hub sends TTS audio or files to the satellite.

### What is `route` metadata on HiveMessage?
An ordered list of hops (`[{"source": peer, "targets": [peers]}]`) tracking the network path a message has traversed. Populated by `update_hop_data()` at each node, transferred through wrappers via `replace_route()`. Survives `as_dict()` → `deserialize()` roundtrips. Type hint: `List[Dict[str, Any]]`, not `List[str]`.

### Why was `deserialize()` dropping route/node/source_peer?
Bug: `as_dict` serialized these fields but `deserialize()` didn't pass them to the constructor. Fixed in `message.py:208-231` — all three deserialize paths now restore `route`, `node`, and `source_peer`.
