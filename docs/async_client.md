# AsyncHiveMessageBusClient

An asyncio-native sibling of [`HiveMessageBusClient`](client_api.md), built
on `websockets` instead of `websocket-client`. Same protocol on the wire,
same `HiveMessage` envelopes, same handshake state machine — just
`await` everywhere.

## When to use it

Use `AsyncHiveMessageBusClient` when your application's main loop is
already asyncio: FastAPI, aiohttp, Matrix `nio`, `discord.py`,
DeltaChat-RPC, Telegram async clients, etc. The async client removes the
need to spawn a daemon thread for the HiveMind connection and bridge
back to your event loop with `asyncio.run_coroutine_threadsafe`.

Keep the sync [`HiveMessageBusClient`](client_api.md) for:

- one-shot scripts and CLIs
- any program whose main thread is already blocking somewhere
- environments without `websockets` installed (the async client is an
  optional extra)

Both clients can talk to the same HiveMind server, send the same
`HiveMessage` types, and use the same `NodeIdentity`. Pick one per
process; do not mix them on the same connection.

## Install

The async path is an optional extra so the base install stays
threading-based and small:

```bash
pip install hivemind-bus-client[async]
```

Importing `AsyncHiveMessageBusClient` from a bare install (no
`websockets`) raises a descriptive `ImportError` at instantiation. Bare
installs that never reference the async surface keep working unchanged.

## Quick start

```python
import asyncio
from ovos_bus_client.message import Message
from hivemind_bus_client import (
    AsyncHiveMessageBusClient, HiveMessage, HiveMessageType,
)


async def main():
    bus = AsyncHiveMessageBusClient(
        key="my-api-key",
        password="my-password",
        host="ws://hivemind.local",
        port=5678,
    )
    await bus.connect()       # handshake completes before this returns

    # send a Mycroft Message — automatically wrapped as a BUS HiveMessage
    await bus.emit(Message("speak", {"utterance": "hello hive"}))

    # request/reply
    reply = await bus.wait_for_response(
        HiveMessage(HiveMessageType.PING, {"flood_id": "q1"}),
        timeout=3.0,
    )
    print(reply)

    await bus.close()


asyncio.run(main())
```

## API surface

| Method | Sync client equivalent | Notes |
|---|---|---|
| `await bus.connect(bus, protocol, site_id)` | `bus.connect(...)` | Awaits handshake completion. |
| `await bus.close()` | n/a (close happens via `client.close()`) | Cancels the receive task, clears state. |
| `await bus.emit(msg, binary_type=...)` | `bus.emit(...)` | Awaits send. Accepts `MycroftMessage` or `HiveMessage`. |
| `await bus.emit_mycroft(msg)` | `bus.emit_mycroft(...)` | Convenience for BUS-wrapped Mycroft messages. |
| `await bus.wait_for_message(type, timeout)` | `bus.wait_for_message(...)` | Returns `HiveMessage` or `None`. |
| `await bus.wait_for_payload(payload_type, message_type, timeout)` | `bus.wait_for_payload(...)` | Filters by inner payload type. |
| `await bus.wait_for_mycroft(msg_type, timeout)` | `bus.wait_for_mycroft(...)` | Sugar for `wait_for_payload(message_type=BUS)`. |
| `await bus.wait_for_response(msg, reply_type, timeout)` | `bus.wait_for_response(...)` | Emits then waits. |
| `await bus.wait_for_payload_response(...)` | `bus.wait_for_payload_response(...)` | Emits then payload-filtered wait. |
| `await bus.wait_for_handshake(timeout, max_retries)` | `bus.wait_for_handshake(...)` | Async retry loop. |
| `await bus.emit_intercom(msg, pubkey)` | `bus.emit_intercom(...)` | Hybrid-encrypted INTERCOM send. |
| `bus.on(event, fn)` / `bus.once(event, fn)` / `bus.remove(event, fn)` | same | **Synchronous**, like the sync client. Keeps `HiveMindSlaveProtocol` drop-in compatible. |
| `bus.on_mycroft(msg_type, fn)` | same | Internal-bus handler registration. |

`AsyncHiveMessageWaiter` and `AsyncHivePayloadWaiter` are the
asyncio.Event-based equivalents of `HiveMessageWaiter` and
`HivePayloadWaiter`; use them when you want to set up the waiter before
emitting and then `await waiter.wait(timeout)`.

## Handshake

`await bus.connect()` performs the full HiveMind handshake (asymmetric
RSA + symmetric AES, or password-handshake fallback) before returning.
If the server is reachable but the handshake stalls, the call retries up
to `max_retries` times before raising `RuntimeError`. Reconnect after a
forced disconnect re-runs the handshake automatically on the next
`emit`.

## Binary payloads, encryption, compression

All transport-side decoding/encoding (AES-GCM, ChaCha20, bitstring framing,
zlib compression) is reused from the shared
`hivemind_bus_client.encryption` and `serialization` modules — the async
client is just a different transport, not a different protocol. The
`compress`, `binarize`, `cipher`, and `json_encoding` knobs work the
same way on both clients.

## Benchmarks

Two scripts ship under `benchmarks/`. They measure different things and
both numbers matter.

### In-process — library overhead only

`benchmarks/bench_async_vs_sync.py` stubs out the WebSocket and measures
serialization, emitter dispatch, and waiter coordination only. Use it to
spot library-level regressions, not to predict real runtime.

Python 3.11, n=1500:

| Benchmark | Sync | Async | Notes |
|---|---|---|---|
| `emit()` — mean | 0.42 ms | 0.58 ms | async pays coroutine dispatch cost |
| `wait_for_message()` — mean (already-set) | 0.004 ms | 0.020 ms | sync `Event.is_set()` faster than asyncio scheduling |
| Concurrent emit ×200 fan-out | n/a | ≈1660 msg/s | async-only path |

### Real transport — loopback WebSocket echo server

`benchmarks/bench_async_vs_sync_ws.py` spins up a `websockets`-based
echo server on a free localhost port and exercises both clients
end-to-end (no encryption, no handshake). This is "real transport, no
network."

Python 3.11, n=300:

| Benchmark | Sync | Async | Notes |
|---|---|---|---|
| Emit + round-trip — mean | 0.33 ms | 0.55 ms | sync `websocket-client` is slightly leaner on a single connection |
| Emit + round-trip — p95 | 0.44 ms | 0.74 ms | both well under 1 ms |
| Concurrent round-trip ×300 (fan-out) | n/a (would need 300 threads) | ≈1190 req/s | async-only path |

### Honest reading

The async client is **not faster per-call** on a single connection. The
sync `websocket-client` library is well-optimised for blocking I/O on
one socket, and HiveMind's per-message serialization is the same cost
either way.

The case for `AsyncHiveMessageBusClient` is **integration**, not
microseconds:

- Your application is already asyncio. Threads-to-loop bridges
  (`asyncio.run_coroutine_threadsafe`) become direct `await` calls. The
  bridge code is a known source of bugs — lost messages on shutdown,
  double-delivery on reconnect.
- One process can run many independent HiveMind connections cheaply.
  Sync clients would need one thread per connection.
- Free up the calling task. While `await bus.wait_for_response(...)` is
  pending, the FastAPI request handler / Discord event loop / etc. can
  do other work.

If your code is single-shot scripts or CLIs, prefer the sync client.

### Run the benchmarks yourself

```bash
# Library overhead only (fast, no transport)
python benchmarks/bench_async_vs_sync.py --n 1500

# End-to-end via a real loopback WebSocket echo server
python benchmarks/bench_async_vs_sync_ws.py --n 300
```

## Reusing existing components

The async client deliberately reuses the transport-independent pieces of
the package:

- `HiveMessage`, `HiveMessageType` ([`hivemind_bus_client/message.py`](../hivemind_bus_client/message.py))
- `NodeIdentity` ([`hivemind_bus_client/identity.py`](../hivemind_bus_client/identity.py))
- All of [`encryption.py`](../hivemind_bus_client/encryption.py) (AES-GCM / ChaCha20 / hybrid)
- All of [`serialization.py`](../hivemind_bus_client/serialization.py) (binary framing, zlib)
- `HiveMindSlaveProtocol` ([`hivemind_bus_client/protocol.py`](../hivemind_bus_client/protocol.py)) — works with both sync and async emitters via `pyee`

That keeps async-vs-sync a transport question, not a protocol fork.

## Caveats

- **Reconnect**: the async client does not auto-reconnect today. The
  receive task exits on close; supervise it from your application
  (the same shape as the sync client's responsibility-of-the-caller
  pattern).
- **Mixed clients in one process**: don't share the same emitter or
  internal bus between sync and async clients. Each owns its own.
- **`websockets` version**: the package floor is `websockets>=10`.
  Newer versions are fine; the public API used here (`websockets.connect`,
  `WebSocketClientProtocol.send/recv`, `ConnectionClosed*`) is stable.
