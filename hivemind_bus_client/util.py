import json
import zlib
from binascii import hexlify, unhexlify
from typing import Union, Dict

import pybase64
from ovos_utils.security import encrypt, decrypt, AES

from hivemind_bus_client.exceptions import EncryptionKeyError, DecryptionKeyError
from hivemind_bus_client.message import HiveMessage, HiveMessageType, Message


def serialize_message(message: Union[HiveMessage, Message, Dict]) -> str:
    # convert a Message object into raw data that can be sent over
    # websocket
    if hasattr(message, 'serialize'):
        return message.serialize()
    elif isinstance(message, dict):
        message = {
            k: v if not hasattr(v, 'serialize') else serialize_message(v)
            for k, v in message.items()}
        return json.dumps(message)
    else:
        return json.dumps(message.__dict__)


def payload2dict(payload: Union[HiveMessage, Message, str]) -> Dict:
    """helper to ensure all subobjects of a payload are a dict safe for serialization
    eg. ensure payload is valid to send over mycroft messagebus object """
    if isinstance(payload, HiveMessage):
        payload = payload.as_dict
    if isinstance(payload, Message):
        payload = payload.serialize()
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except:
            pass
    assert isinstance(payload, dict)

    def can_serialize(val):
        if isinstance(val, HiveMessage) \
                or isinstance(val, Message) \
                or isinstance(val, dict):
            return True
        return False

    for k, v in payload.items():
        if can_serialize(v):
            payload[k] = payload2dict(v)
        if isinstance(v, list):
            for idx, l in enumerate(v):
                if can_serialize(l):
                    payload[k][idx] = payload2dict(l)
    return payload


def get_payload(msg: Union[HiveMessage, Message, str, Dict]) -> Dict:
    """ helper to read normalized payload
    from all supported formats (HiveMessage, Message, json str)
    """
    if isinstance(msg, HiveMessage):
        msg = msg.payload
    if isinstance(msg, Message):
        msg = msg.serialize()
    if isinstance(msg, str):
        msg = json.loads(msg)
    return msg


def get_hivemsg(msg: Union[Message, str, Dict]) -> HiveMessage:
    """ helper to create a normalized HiveMessage object
    from all supported formats (Message, json str, dict)
    """
    if isinstance(msg, str):
        msg = json.loads(msg)
    if isinstance(msg, dict):
        msg = HiveMessage(**msg)
    if isinstance(msg, Message):
        msg = HiveMessage(msg_type=HiveMessageType.BUS, payload=msg)
    assert isinstance(msg, HiveMessage)
    return msg


def get_mycroft_msg(pload: Union[HiveMessage, str, Dict]) -> Message:
    if isinstance(pload, HiveMessage):
        assert pload.msg_type == HiveMessageType.BUS
        pload = pload.payload

    if isinstance(pload, str):
        try:
            pload = Message.deserialize(pload)
        except:
            pload = json.loads(pload)
    if isinstance(pload, dict):
        msg_type = pload.get("msg_type") or pload["type"]
        data = pload.get("data") or {}
        context = pload.get("context") or {}
        pload = Message(msg_type, data, context)

    assert isinstance(pload, Message)
    return pload


def encrypt_as_json(key, data, b64=False) -> str:
    # TODO default b64 to True in a future release
    #  we dont want clients to update before servers, otherwise servers won't be able to decode
    #  after a reasonable time all servers should support decoding both schemes and the default can change
    if isinstance(data, dict):
        data = json.dumps(data)
    if len(key) > 16:
        key = key[0:16]
    ciphertext = encrypt_bin(key, data)
    nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]
    if b64:
        return json.dumps({"ciphertext": pybase64.b64encode(ciphertext).decode('utf-8'),
                           "tag": pybase64.b64encode(tag).decode('utf-8'),
                           "nonce": pybase64.b64encode(nonce).decode('utf-8')})
    return json.dumps({"ciphertext": hexlify(ciphertext).decode('utf-8'),
                       "tag": hexlify(tag).decode('utf-8'),
                       "nonce": hexlify(nonce).decode('utf-8')})


def decrypt_from_json(key, data: Union[str, bytes]):
    if isinstance(data, str):
        data = json.loads(data)
    if len(key) > 16:
        key = key[0:16]

    # payloads can be either hex encoded (old style)
    # or b64 encoded (new style)
    def decode(b64=False):
        if b64:
            decoder = pybase64.b64decode
        else:
            decoder = unhexlify

        ciphertext = decoder(data["ciphertext"])
        if data.get("tag") is None:  # web crypto
            ciphertext, tag = ciphertext[:-16], ciphertext[-16:]
        else:
            tag = decoder(data["tag"])
        nonce = decoder(data["nonce"])
        return ciphertext, tag, nonce

    is_b64 = any(a.isupper() for a in str(data))  # if any letter is uppercase, it must be b64
    ciphertext, tag, nonce = decode(is_b64)
    try:
        return decrypt(key, ciphertext, tag, nonce)
    except ValueError as e:
        if not is_b64:
            try:  # maybe it was b64 after all? unlikely but....
                ciphertext, tag, nonce = decode(b64=True)
                return decrypt(key, ciphertext, tag, nonce)
            except ValueError:
                pass
        raise DecryptionKeyError from e


def encrypt_bin(key, data: Union[str, bytes]):
    if len(key) > 16:
        key = key[0:16]
    try:
        ciphertext, tag, nonce = encrypt(key, data)
    except:
        raise EncryptionKeyError

    return nonce + ciphertext + tag


def decrypt_bin(key, ciphertext: bytes):
    if len(key) > 16:
        key = key[0:16]

    nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]

    try:
        if not isinstance(key, bytes):
            key = bytes(key, encoding="utf-8")
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise DecryptionKeyError


def compress_payload(text: Union[str, bytes]) -> bytes:
    # Compressing text
    if isinstance(text, str):
        decompressed = text.encode("utf-8")
    else:
        decompressed = text
    return zlib.compress(decompressed)


def decompress_payload(compressed: Union[str, bytes]) -> bytes:
    # Decompressing text
    if isinstance(compressed, str): # we really should be getting bytes here and not a str
        if any(a.isupper() for a in compressed):
            decoder = pybase64.b64decode
        else:  # assume hex
            decoder = unhexlify
        compressed = decoder(compressed)
    return zlib.decompress(compressed)


def cast2bytes(payload: Union[Dict, str], compressed=False) -> bytes:
    if isinstance(payload, dict):
        payload = json.dumps(payload)
    if compressed:
        payload = compress_payload(payload)
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    assert isinstance(payload, bytes)
    return payload


def bytes2str(payload: bytes, compressed=False) -> str:
    if compressed:
        return decompress_payload(payload).decode("utf-8")
    else:
        return payload.decode("utf-8")


if __name__ == "__main__":
    k = "*" * 16
    test = "this is a test text for checking size of encryption and stuff"
    print(len(test))  # 61

    encjson = encrypt_as_json(k, test, b64=True)
    # {"ciphertext": "MkTc1LSK3jugt5SXapAeSrD6YWnYdSJ5oqF2bWYcnFpAYgjAgcTFXiKL3wBsqVKY52SkO5mjkqr7i/0A5A==", "tag": "37WNN8e23Mj0LlOxu9cjnQ==", "nonce": "inRwcb0H1Xu6pp80WFeJvg=="}
    print(len(encjson))  # 174
    assert decrypt_from_json(k, encjson) == test

    encjson = encrypt_as_json(k, test, b64=False)
    # {"ciphertext": "64c65bad86a3582097aa4958b7c9555e8bf7deeac6bdf8b5f648cc360aaf50062ae9c635f602b3c66b2de1eece57666b3412a26f55bbd5ace2f601d8c2", "tag": "ce550c1e399c92bb26bf3c171c212e7d", "nonce": "84d045071b05bf005145ce071df0ed41"}
    print(len(encjson))  # 228
    assert decrypt_from_json(k, encjson) == test
