# TODO — hivemind-websocket-client

## Known issues

- **`session_id` mutation under lock is a known hack** — `HiveMessageBusClient.session_id` is a mutable instance attribute used to tag outgoing messages. The flask chatroom works around this with a threading lock. The library should support per-message session context without mutating shared state.
- **`HiveMessageWaiter` has no deadlock protection** — `wait_for_response()` blocks until the expected message arrives or timeout. If the hub never sends the expected message type, the waiter waits for the full timeout on every call.
- **Binary callbacks are registered by type** — `BinaryDataCallbacks` dispatches by `HiveMindBinaryPayloadType`. If the hub sends an unknown binary type, it is silently dropped.

## Missing features

- **No automatic reconnect** — if the WebSocket connection drops, the client does not reconnect. Callers must detect the disconnect and create a new `HiveMessageBusClient`.
- **No connection state observable** — `connected_event` is a `threading.Event` that is set once on connect but not cleared on disconnect. There is no reliable way to check if the connection is currently active.
- **`HiveMindHTTPClient` does not support binary messages** — the HTTP client polls `get_messages` but binary messages require a separate `get_binary_messages` poll. There is no automatic polling loop that handles both.
- **`NodeIdentity.save()` writes the full identity including the password** — the password is stored in plaintext in the identity file. There is no keychain or secret storage integration.

## Architecture suggestions

- Add a `reconnect_on_disconnect` flag with configurable backoff
- Expose an `is_connected` property that reflects the actual socket state
- Add per-emit `session` context support to avoid the `session_id` mutation hack

## Testing gaps

- No test for `HiveMessageWaiter` timeout behaviour
- No test for binary callback dispatch
- `NodeIdentity` serialisation/deserialisation round-trip is not tested
- HTTP client polling is not tested

## Completed (2026-03-07)

- ✓ `test/test_identity.py` added: NodeIdentity property setters, access_key/password/site_id None handling, HiveMessageBusClient session_id UUID format
- ✓ `AUDIT.md` created: INTERCOM dispatch (FIXED), handle_illegal_msg only logs, implicit master trust, share_bus no filter
