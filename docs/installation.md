# Installation

## Install from PyPI

```bash
pip install hivemind_bus_client
```

## Verify

```bash
hivemind-client --help
```

## Dependencies

The library requires:

- `websocket-client`, the WebSocket transport
- `ovos-bus-client`, for `Message` type compatibility with OVOS
- `poorman-handshake`, the RSA-based handshake and AES session key derivation
- `pycryptodome`, for AES-GCM encryption
- `pybase64`, base64 encoding helpers

Package installation installs all of these automatically.

---
[← Setup](setup.md) · [Home](index.md) · [API Reference →](api.md)
