# Audit — hivemind-websocket-client

## Known Issues

### `handle_propagate` BUS payload for matching site_id is a no-op
`protocol.py:303-309` — when a PROPAGATE carries a BUS payload targeting the satellite's `site_id`, the handler does nothing (`pass`). The TODO suggests injection should happen for trusted peers, but no trust list exists yet.

### Protocol coverage is 50%
`protocol.py` has 50% test coverage. Handlers without unit tests: `handle_handshake`, `handle_bus`, `handle_broadcast`, `handle_intercom`, `bind`.

### CASCADE aggregator uses wall-clock timer
`CascadeAggregator` (`protocol.py:21`) uses `threading.Timer` which is subject to GIL and scheduling jitter. For production use with sub-second timeouts, consider an event-loop-based approach.
