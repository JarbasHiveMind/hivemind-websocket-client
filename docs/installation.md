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
- `pycryptodomex`, for AES-GCM and ChaCha20-Poly1305 encryption. The imports are `Cryptodome.*`; `pycryptodome` is a different package and does not work here
- `pybase64`, base64 encoding helpers
- `bitstring`, the binary frame encoder and decoder
- `z85base91`, payload encodings for the JSON transport

Package installation installs all of these automatically.

---
[← Setup](setup.md) · [Home](index.md) · [API Reference →](api.md)
