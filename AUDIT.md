# Audit — hivemind-websocket-client

## Medium

| ID | Description | Location |
|----|-------------|----------|
| WC-001 | Bare `except:` in `HiveMessage.deserialize()` masks errors — should be `except Exception:` | `message.py:213,224` |
| WC-002 | Commented-out dead code in `handle_handshake` | `protocol.py:199-202` |
| WC-003 | `HiveMessage.payload` property reconstructs objects on every access (no caching) — performance hit in hot paths | `message.py:127-145` |

## Low

| ID | Description | Location |
|----|-------------|----------|
| WC-004 | Vague TODO about trusted peer injection in `handle_propagate` | `protocol.py:283` |
| WC-005 | Missing return type hints on `register_bus_handlers`, `start_handshake`, `receive_handshake` | `protocol.py` |
