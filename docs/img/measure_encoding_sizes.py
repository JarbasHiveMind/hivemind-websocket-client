"""Measure the wire size of one fixed BUS message in each serialization.

Run from the repository root: python docs/img/measure_encoding_sizes.py
It writes docs/img/encoding-sizes-results.json.
"""
import json

import Cryptodome.Cipher._mode_gcm as gcm
from ovos_bus_client.message import Message

from hivemind_bus_client.encryption import SupportedEncodings, encrypt_as_json
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.serialization import get_bitstring

MESSAGE = HiveMessage(HiveMessageType.BUS,
                      Message("speak", {"utterance": "hello world", "lang": "en-US"},
                              {"source": "skills", "destination": "satellite"}))
KEY = bytes(32)
# Base91 output length depends on the bytes, so a random nonce changes the
# size from run to run. A fixed all-zero nonce makes the result repeatable.
gcm.get_random_bytes = bytes

text = MESSAGE.serialize()
sizes = {
    "JSON text": len(text.encode("utf-8")),
    "binary frame": len(get_bitstring(HiveMessageType.BUS, MESSAGE.payload, compressed=False).bytes),
    "binary frame, compressed": len(get_bitstring(HiveMessageType.BUS, MESSAGE.payload, compressed=True).bytes),
}
for encoding in SupportedEncodings:
    sizes[f"legacy AES-GCM, {encoding.value}"] = len(
        encrypt_as_json(KEY, text, encoding=encoding).encode("utf-8"))

result = {"message": json.loads(text), "bytes": sizes}
with open("docs/img/encoding-sizes-results.json", "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=1)
    handle.write("\n")
print(json.dumps(sizes, indent=1))
