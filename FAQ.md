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
