# Troubleshooting
<!-- agent-hint
covers: each error a user of the client or the CLI can see, its cause, and the fix
source: hivemind_bus_client/scripts.py:test_identity, hivemind_bus_client/client.py:on_close, hivemind_bus_client/identity.py, hivemind_bus_client/protocol.py
generated: no
verify: for s in 'could not reach HiveMind within' 'HiveMind refused this identity' 'Check the access key and password' 'does not match "' 'Refusing to mint a new identity' 'refusing to {verb} the shared'; do grep -rqF "$s" hivemind_bus_client/ || exit 1; done
see: contributing.md
-->

This page lists the errors that you can see when you connect, with the cause of each one and the fix. Start with `hivemind-client --app <name> test-identity`, because it reports one error line in place of a reconnect loop.

## Example

```bash
hivemind-client --app docs-wrong test-identity --timeout 10
```

```text
2026-11-27 04:15:18,069 - ERROR - Connection closed (code 1008): invalid api key - goodbye
Error: HiveMind refused this identity: invalid api key
Check the access key and password with 'hivemind-client set-identity', and confirm the client is registered on the server with 'hivemind-core list-clients'.
```

## Steps

1. Run `test-identity` with `--app <name>` before the subcommand.
2. Find the error line in the sections below.
3. Apply the fix, then run `test-identity` again.

## The hub refuses the access key

```text
Error: HiveMind refused this identity: invalid api key
```

The hub closed the connection with code 1008. The access key is not in the hub database, or the hub revoked it. The client does not reconnect, because the same key fails each time. In Python, `connect()` raises `ConnectionRefusedError`.

Fix: run `hivemind-core list-clients` on the hub. Then store the right key with `hivemind-client --app <name> set-identity --key <key>`.

A 1008 close on a session that was already established is a protocol error, not a refusal. The client logs a warning and reconnects.

## A wrong password

```text
cryptography.exceptions.InvalidTag
Error: could not reach HiveMind within 10s. Check the host and port in the identity file, and that hivemind-core is listening.
```

With protocol v3, the password is the Noise PSK. A wrong password makes the handshake fail on the client side. `test-identity` then reports a timeout, which tells you to check the host and the port. Check the password too. Issue [#326](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/326) tracks the wrong hint.

Fix: compare the password with the hub (`hivemind-core list-clients`), then run `hivemind-client --app <name> set-identity --password <password>`. That command also clears the PSK cache.

## The hub does not answer

```text
2026-11-27 04:15:51,652 - ERROR - [Errno 111] Connection refused - goodbye
Error: could not reach HiveMind within 5s. Check the host and port in the identity file, and that hivemind-core is listening.
```

Nothing listens at that host and port. Check `default_master` and `default_port` in the identity, and check that `hivemind-core listen` runs. In Python, `connect()` with no `handshake_max_retries` retries forever. Pass a number to get `RuntimeError("timed out waiting for handshake")`.

## The hub key changed

```text
Error: HiveMind refused this identity: the server Noise static key for 127.0.0.1:15678 does not match the pinned key. Run 'hivemind-client forget-server' if the master was reinstalled or replaced
Check the access key and password with 'hivemind-client set-identity', and confirm the client is registered on the server with 'hivemind-core list-clients'.
```

The hub shows a Noise key that is not the pinned key. The second line of `test-identity` is about the access key and does not apply here ([#326](https://github.com/JarbasHiveMind/hivemind-websocket-client/issues/326)).

Fix: if you reinstalled or restored the hub, run `hivemind-client --app <name> forget-server`. If you did not, find out which machine answers at that address before you trust it. [Security](security.md#server-key-pinning) has the details.

## The client refuses to create the shared file

```text
ValueError: refusing to write a private key beside the shared /home/user/.config/hivemind/_identity.json: HIVEMIND-CRYPTO-1 §2 forbids ...
```

The identity has no `app_name`, and no shared file exists.

Fix: put `--app <name>` before the subcommand, or pass `NodeIdentity(app_name="<name>")`. To make the shared file on purpose, run `hivemind-client --shared set-identity ...`. [Identity](identity.md#the-refusal) has the full message.

## The hub closes the handshake with 1011

```text
ERROR - Connection closed (code 1011): internal error handling shake - goodbye
```

The hub failed while it handled the handshake. One cause is a hivemind-core hub with no node identity. The hub log then shows `could not generate a node public key` at start, and `AttributeError: 'NoneType' object has no attribute 'encode'` for each handshake. hivemind-core before 5.3.16a1 reads the shared identity file, and the library does not create that file without `--shared`.

Fix: upgrade the hub to hivemind-core 5.3.16a1 or later, which makes its own key in `~/.config/hivemind/hivemind-core/` on the first start. On an older hub, as the user that runs hivemind-core, run `hivemind-client --shared set-identity --siteid <site>`, then restart `hivemind-core listen`.

## The identity file does not parse

```text
hivemind_bus_client.exceptions.IdentityFileCorrupted: identity file ... exists but could not be parsed. Refusing to mint a new identity — restore it from a backup or delete it to start over as a new node.
```

Fix: restore `_identity.json` from a backup. [Identity](identity.md#a-damaged-identity-file) explains what happens when you delete it.

## The async client does not import

```text
ImportError: The 'websockets' package is required for AsyncHiveMessageBusClient. Install it with: pip install hivemind-bus-client[async]
```

Fix: `uv pip install --prerelease=allow "hivemind-bus-client[async]"`.

## The client needs credentials

```text
RuntimeError: NodeIdentity not set, please pass key and password or call 'hivemind-client set-identity'
RuntimeError: host not set, please pass host and port or call 'hivemind-client set-identity'
```

The constructor found no access key, no password or no host in its arguments or in the identity. Check that `app_name` names the identity that you wrote with `set-identity`.

---
[← HTTP client](polling-client.md) · [Home](index.md) · [Contributing →](contributing.md)
