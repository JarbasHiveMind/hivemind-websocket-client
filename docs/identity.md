# Identity
<!-- agent-hint
covers: where a node keeps its credentials and keys, NodeIdentity(app_name=...), the shared file, --app and --shared, and the refusal to create the shared file
source: hivemind_bus_client/identity.py:NodeIdentity, hivemind_bus_client/scripts.py:_node_identity
generated: no
verify: python -c "from hivemind_bus_client.identity import NodeIdentity as N; import inspect; p=inspect.signature(N).parameters; assert list(p)==['identity_file','app_name','shared_fallback'] and p['shared_fallback'].default is True" && grep -qF 'refusing to {verb} the shared' hivemind_bus_client/identity.py && hivemind-client --help | grep -q -- '--shared'
see: cli.md
-->

A node identity holds the credentials that reach a hub and the keys that prove who the node is. This page tells you where each application keeps its identity, and what to do when the library refuses to write one.

## Example

Give each application its own name. The identity then lives in `~/.config/hivemind/<app_name>/`:

```bash
hivemind-client --app docs-sat set-identity --key docs-key-0123 \
    --password "correct-horse-battery-staple-docs" \
    --host 127.0.0.1 --port 15678 --siteid kitchen
```

```text
PUBKEY: -----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
identity saved: /home/user/hm-demo/config/hivemind/docs-sat/_identity.json
```

The application reads the same file in Python:

```python
from hivemind_bus_client import HiveMessageBusClient
from hivemind_bus_client.identity import NodeIdentity

client = HiveMessageBusClient(identity=NodeIdentity(app_name="docs-sat"))
```

## Steps

1. Pick an application name. It is one path segment: letters, digits, `.`, `_` or `-`, starts with a letter or a digit, and has at most 64 characters. Another name raises:

   ```text
   ValueError: app_name must be letters, digits, '.', '_' or '-', start with a letter or digit, and be at most 64 characters: 'bad/name'
   ```

2. Write the identity with `hivemind-client --app <name> set-identity`. Put `--app` before the subcommand, because it is an option of the command group. The first `set-identity` makes an RSA key pair and prints the public key.

3. Pass `NodeIdentity(app_name="<name>")` to the client.

4. Optional: run `hivemind-client --app <name> test-identity` to check the credentials against the hub.

## The identity folder

After a first connection, the folder of `docs-sat` holds these files:

```text
config/hivemind/docs-sat/
├── _identity.json             credentials, public key, pinned server keys
├── HiveMindComs.pem           RSA private key, made by set-identity or reset-pgp
├── unnamed-node_noise.key     Noise static X25519 private key
└── unnamed-node_noise_psks.json   Noise PSK cache, see security.md
```

The Noise key file is named after `name` in the identity. With no `name`, the name is `unnamed-node`. The key paths in `_identity.json` are relative to the identity file, so you can move the folder to another home directory.

`_identity.json` holds these keys:

| Key | Set by | Use |
| :--- | :--- | :--- |
| `access_key` | `set-identity --key` | Identifies the client to the hub |
| `password` | `set-identity --password` | Input of the Noise PSK, never sent |
| `default_master` | `set-identity --host` | Hub URL, `ws://` is added when the scheme is missing |
| `default_port` | `set-identity --port` | Hub port, 5678 when not given |
| `site_id` | `set-identity --siteid` | Site of the node in `message.context` |
| `public_key`, `secret_key` | `set-identity`, `reset-pgp` | RSA key pair for INTERCOM and the legacy handshake |
| `name` | your code | Node label, and the stem of the Noise key file name |
| `noise_key` | your code | Path of the Noise static key, when not the default |
| `pinned_noise_keys` | first handshake | Server Noise keys, see [Security](security.md#server-key-pinning) |
| `trusted_keys` | `add_trusted_key()` | Peers whose PROPAGATE, CASCADE and INTERCOM messages reach the bus |

The client reads the credentials from the identity only as a fallback. It never writes credentials back to the identity.

## The shared file

The shared file is `~/.config/hivemind/_identity.json`. HIVEMIND-CRYPTO-1 §2 says that two applications of one user must not present one identifier and one static key. So the library treats the shared file as a choice that a deployer makes, never as a default:

| How you build the identity | Own file exists | Shared file exists | Result |
| :--- | :--- | :--- | :--- |
| `NodeIdentity(app_name="x")` | yes | any | Uses the own file. |
| `NodeIdentity(app_name="x")` | no | yes | Reads the shared file and logs a warning. `uses_shared_fallback` is `True`. |
| `NodeIdentity(app_name="x")` | no | no | Uses the own file, which `save()` creates. |
| `NodeIdentity(app_name="x", shared_fallback=False)` | any | any | Always uses the own file. |
| `NodeIdentity()` | not applicable | yes | Reads the shared file and logs a warning. |
| `NodeIdentity()` | not applicable | no | Refuses to create the shared file. |
| `NodeIdentity(identity_file=path)` | not applicable | not applicable | Uses `path`. Do not pass `app_name` too. |

The fallback warning names the fix:

```text
WARNING - 'kitchen-sat' has no identity file at /home/user/hm-demo/config/hivemind/kitchen-sat/_identity.json and reads the shared /home/user/hm-demo/config/hivemind/_identity.json. HIVEMIND-CRYPTO-1 §2 wants one identity per application: run 'hivemind-client --app kitchen-sat set-identity ...' to give it one
```

A client built without `identity=` uses `NodeIdentity()` and logs that it uses the shared file.

### Provision the shared file

`--shared` makes the CLI write the shared file, and create it when it does not exist. Use it when one identity for all applications is what you want, for example for a hivemind-core hub:

```bash
hivemind-client --shared set-identity --siteid hub
```

```text
identity saved: /home/user/hm-demo/config/hivemind/_identity.json
```

`--shared` is in `hivemind-bus-client` 1.3.0a1 and later. Like `--app`, it goes before the subcommand. After the subcommand, click refuses it:

```text
Error: No such option '--shared'. Did you mean '--siteid'?
```

## The refusal

With no `app_name` and no shared file, `save()`, `create_keys()` and `connect()` raise `ValueError` before they write anything. A bare `hivemind-client set-identity` on a box with no shared file fails in the same way:

```text
ValueError: refusing to write a private key beside the shared /home/user/hm-demo/config/hivemind/_identity.json: HIVEMIND-CRYPTO-1 §2 forbids an identity location shared by every application of this user. Give this application a name, NodeIdentity(app_name="<your-app>") or 'hivemind-client --app <your-app> set-identity ...', or provision the shared file deliberately with 'hivemind-client --shared set-identity ...'
```

`save()` gives the same message with `refusing to create`. To fix it, do one of these:

- Give the application a name: `NodeIdentity(app_name="<your-app>")`, and `hivemind-client --app <your-app> set-identity ...`.
- Make the shared file on purpose: `hivemind-client --shared set-identity ...`.

## A damaged identity file

An identity file that exists but does not parse stops the node. The library does not make a new identity, because a new identity has a new Noise key, and each hub that pinned the old key then refuses the node:

```text
hivemind_bus_client.exceptions.IdentityFileCorrupted: identity file /home/user/hm-demo/config/hivemind/docs-nohub/_identity.json exists but could not be parsed. Refusing to mint a new identity — restore it from a backup or delete it to start over as a new node.
```

Restore the file from a backup. If you delete it, the node starts as a new node with a new Noise key. The hub pinned the old key, so run `hivemind-core reset-noise-pin` on the hub to make it forget that pin.

---
[← Install and connect](install-and-connect.md) · [Home](index.md) · [CLI reference →](cli.md)
