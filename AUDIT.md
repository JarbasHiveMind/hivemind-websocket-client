# Audit — hivemind-websocket-client

## Known Issues

### `handle_query` and `handle_cascade` are structurally identical
`protocol.py:311-325` and `protocol.py:327-338` share identical logic (assert BUS/INTERCOM, dispatch). Consider extracting a shared helper. Low priority — duplication is small and semantics may diverge.

### `handle_propagate` BUS payload for matching site_id is a no-op
`protocol.py:241-251` — when a PROPAGATE carries a BUS payload targeting the satellite's `site_id`, the handler does nothing (`pass`). The TODO suggests injection should happen for trusted peers, but no trust list exists yet.

### Protocol coverage is low (37%)
`protocol.py` has 37% test coverage. Most handlers (`handle_handshake`, `handle_bus`, `handle_broadcast`, `handle_intercom`, `bind`) lack unit tests.
