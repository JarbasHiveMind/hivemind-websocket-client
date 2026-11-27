# AGENTS.md — hivemind-websocket-client

## Purpose

`hivemind-websocket-client` (PyPI `hivemind-bus-client`, module `hivemind_bus_client`) is the reference Python client of the HiveMind wire protocol. It extends the OVOS bus client with the Noise handshake, encrypted frames and the HiveMind routing types. Every HiveMind satellite (`hivemind-mic-satellite`, `HiveMind-voice-relay`, `HiveMind-voice-sat`, `HiveMind-cli`) and hivemind-core itself import it. A wire-format change here must stay compatible with all of them.

## Repository map

| Path | Content |
| :--- | :--- |
| `hivemind_bus_client/client.py` | `HiveMessageBusClient`, the sync WebSocket client |
| `hivemind_bus_client/async_client.py` | `AsyncHiveMessageBusClient` (needs the `async` extra) |
| `hivemind_bus_client/http_client.py` | `HiveMindHTTPClient` |
| `hivemind_bus_client/protocol.py` | `HiveMindSlaveProtocol`: handshake, routing handlers, key pinning |
| `hivemind_bus_client/noise.py` | Noise XXpsk2/KKpsk0, transport framing, PSK cache |
| `hivemind_bus_client/message.py` | `HiveMessage`, `HiveMessageType`, payload rules |
| `hivemind_bus_client/serialization.py` | Binary frame encode and decode |
| `hivemind_bus_client/encryption.py` | Legacy ciphers and JSON encodings |
| `hivemind_bus_client/identity.py` | `NodeIdentity` and the shared-file rules |
| `hivemind_bus_client/scripts.py` | The `hivemind-client` CLI |
| `tests/`, `tests/e2e/` | Unit tests; end-to-end tests with in-process masters (hivescope) |
| `docs/` | User docs, start at `docs/index.md`; `docs/img/` holds the figure scripts |

## Setup and tests

```bash
uv venv .venv
uv pip install --python .venv/bin/python --prerelease=allow -e ".[test,e2e]"
.venv/bin/python -m pytest tests --ignore=tests/e2e -q   # unit suite
.venv/bin/python -m pytest tests/e2e -q                  # e2e, no running hub needed
```

Never install into a shared venv. CI runs `tests/` with the `test,e2e` extras on Python 3.10 to 3.14.

## Rules the code and tests enforce

- A change to `protocol.py`, `message.py`, `serialization.py`, `encryption.py` or `noise.py` stays backward compatible with deployed hubs and satellites.
- `connect()` on the sync and async clients takes `handshake_max_retries` and passes it to `wait_for_handshake()`. Do not remove this bound.
- A refused access key is fatal: close code `AUTH_REJECTED_CLOSE_CODE = 1008` stops the client. Do not turn it into a reconnect loop. A 1008 on an established session reconnects.
- A pinned server key never changes by itself. A mismatch stops the client; `hivemind-client forget-server` or `NodeIdentity.forget_noise_key()` removes it.
- `NodeIdentity` without `app_name` never creates `~/.config/hivemind/_identity.json`; only an explicit `identity_file=` or `hivemind-client --shared` does (HIVEMIND-CRYPTO-1 §2).
- `NodeIdentity` refuses an identity file that exists but does not parse (`IdentityFileCorrupted`). Never relax `_assert_identity_readable()`: a fallback mints a new Noise key and every peer that pinned the old one refuses the node.
- A regression test fails before the fix and passes after it. Revert only the source to prove it.
- Docs follow `docs/index.md`: README about 60 lines, one page per task, an agent-hint after each H1, and the prev/home/next footer. The size figure comes from `docs/img/measure_encoding_sizes.py` and `docs/img/plot_encoding_sizes.py`; never type its numbers by hand.

## Conventions

- Draft PRs into `dev`; conventional commits, `feat:` only for a user-visible capability.
- Floor pins in `pyproject.toml`, no lockfiles, install prereleases. Apache-2.0: no GPL or AGPL dependencies.
- Every PR, issue and comment an agent writes starts with an AI disclosure that names the model.
