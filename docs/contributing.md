# Contributing
<!-- agent-hint
covers: the development setup, the unit and e2e test suites, the docs figure, and the rules for a change
source: pyproject.toml, tests/, tests/e2e/conftest.py, .github/workflows/build-tests.yml, docs/img/
generated: no
verify: python -m pytest tests --ignore=tests/e2e -q --co -p no:cacheprovider >/dev/null && grep -q "install_extras: 'test,e2e'" .github/workflows/build-tests.yml
see: index.md
-->

This page sets up a development environment, runs the tests, and lists the rules that a change must keep.

## Example

```bash
git clone https://github.com/JarbasHiveMind/hivemind-websocket-client
cd hivemind-websocket-client
uv venv .venv
uv pip install --python .venv/bin/python --prerelease=allow -e ".[test,e2e]"
.venv/bin/python -m pytest tests --ignore=tests/e2e -q
```

```text
1142 passed, 4 skipped, 30 warnings, 263 subtests passed in 73.02s (0:01:13)
```

## Steps

1. Make a virtual environment in the clone, and install the package in editable mode with the `test` extra. Add `e2e` for the end-to-end suite.
2. Run the unit suite: `python -m pytest tests --ignore=tests/e2e -q`.
3. Run the end-to-end suite: `python -m pytest tests/e2e -q`. It starts real hivemind-core masters in the test process through hivescope, so it needs no running hub. `tests/e2e/conftest.py` points the XDG folders at a temporary folder, so the tests never touch your `~/.config/hivemind`.
4. Open a pull request against `dev`. CI runs `tests/` with the `test` and `e2e` extras on Python 3.10 to 3.14 (`.github/workflows/build-tests.yml`).

## Extras

| Extra | Contents | Use |
| :--- | :--- | :--- |
| `async` | `websockets` | `AsyncHiveMessageBusClient` |
| `test`, `dev` | `pytest`, `pytest-asyncio`, `pytest-cov`, `websockets` | The unit suite |
| `e2e` | `hivescope`, `hivemind-core` | The end-to-end suite |
| `benchmark` | `websockets`, `psutil` | The scripts in `benchmarks/` |

## Test without a hub

`hivemind_bus_client.fakebus.AsyncFakeHiveMessageBus` has the surface of `AsyncHiveMessageBusClient` with no network. Use it in a unit test of code that takes an async client.

## The docs figure

The size figure on [Messages](messages.md#serialization) comes from two scripts. Run them from the repository root after a change to the serialization or the encodings:

```bash
.venv/bin/python docs/img/measure_encoding_sizes.py
uv pip install --python .venv/bin/python matplotlib
.venv/bin/python docs/img/plot_encoding_sizes.py
```

The first script writes `docs/img/encoding-sizes-results.json`. The second writes `encoding-sizes.json`, `encoding-sizes.svg` and `encoding-sizes-dark.svg`. Commit all of them.

## Rules for a change

- This library is the reference client of the HiveMind wire protocol. A change to `protocol.py`, `message.py`, `serialization.py`, `encryption.py` or `noise.py` must stay compatible with deployed hubs and satellites.
- A refused access key is fatal. Do not turn the 1008 refusal into a reconnect loop.
- `connect()` keeps its `handshake_max_retries` argument. Do not remove the bound.
- `NodeIdentity` refuses an identity file that does not parse. Do not relax that check: a silent fallback makes a new Noise key, and every peer that pinned the old key then refuses the node.
- A regression test fails before the fix and passes after it.
- Dependencies use floor pins in `pyproject.toml`. Do not add lockfiles.

---
[← Troubleshooting](troubleshooting.md) · [Home](index.md)
