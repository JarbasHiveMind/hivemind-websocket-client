import enum
import json
from binascii import hexlify, unhexlify
from typing import Union, Optional, Dict, Any

import pybase64
from Cryptodome.Cipher import AES, ChaCha20_Poly1305

from cpuinfo import get_cpu_info
from hivemind_bus_client.exceptions import EncryptionKeyError, DecryptionKeyError, InvalidCipher


def cpu_supports_AES() -> bool:
    return "aes" in get_cpu_info()["flags"]


class JsonCiphers(str, enum.Enum):
    """
    Enum representing JSON-based encryption ciphers.
    """
    JSON_B64_AES_GCM_128 = "JSON-B64-AES-GCM-128"  # JSON text output with Base64 encoding
    JSON_HEX_AES_GCM_128 = "JSON-HEX-AES-GCM-128"  # JSON text output with Hex encoding
    JSON_B64_CHACHA20_POLY1305 = "JSON-B64-CHACHA20-POLY1305"  # JSON text output with Base64 encoding
    JSON_HEX_CHACHA20_POLY1305 = "JSON-HEX-CHACHA20-POLY1305"  # JSON text output with Hex encoding


class BinaryCiphers(str, enum.Enum):
    """
    Enum representing binary encryption ciphers.

    Specifications:
      - AES - http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
      - GCM - http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
      - CHACHA20-POLY1305 - https://datatracker.ietf.org/doc/html/rfc7539
    """
    BINARY_AES_GCM_128 = "BINARY-AES-GCM-128"  # Binary output
    BINARY_CHACHA20_POLY1305 = "BINARY-CHACHA20-POLY1305"  # specified in RFC7539.


def encrypt_as_json(key: Union[str, bytes], data: Union[str, Dict[str, Any]],
                    cipher: JsonCiphers = JsonCiphers.JSON_B64_AES_GCM_128) -> str:
    """
    Encrypts the given data and outputs it as a JSON string.

    Args:
        key (Union[str, bytes]): The encryption key, up to 16 bytes. Longer keys will be truncated.
        data (Union[str, Dict[str, Any]]): The data to encrypt. If a dictionary, it will be serialized to JSON.
        cipher (JsonCiphers): The encryption cipher. Supported options:
            - JSON-B64-AES-GCM-128: Outputs Base64-encoded JSON.
            - JSON-HEX-AES-GCM-128: Outputs Hex-encoded JSON.

    Returns:
        str: A JSON string containing the encrypted data, nonce, and tag.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
    """
    if cipher not in JsonCiphers:
        raise InvalidCipher(f"Invalid JSON cipher: {str(cipher)}")

    if isinstance(data, dict):
        data = json.dumps(data)

    aes_ciphers = {JsonCiphers.JSON_B64_AES_GCM_128, JsonCiphers.JSON_HEX_AES_GCM_128}
    b64_ciphers = {JsonCiphers.JSON_B64_AES_GCM_128, JsonCiphers.JSON_B64_CHACHA20_POLY1305}

    bcipher = BinaryCiphers.BINARY_AES_GCM_128 if cipher in aes_ciphers else BinaryCiphers.BINARY_CHACHA20_POLY1305

    ciphertext = encrypt_bin(key, data, cipher=bcipher)

    # extract nonce/tag depending on cipher, sizes are different
    if cipher in aes_ciphers:
        nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]
    else:
        nonce, ciphertext, tag = ciphertext[:12], ciphertext[12:-16], ciphertext[-16:]

    encoder = pybase64.b64encode if cipher in b64_ciphers else hexlify

    return json.dumps({
        "ciphertext": encoder(ciphertext).decode('utf-8'),
        "tag": encoder(tag).decode('utf-8'),
        "nonce": encoder(nonce).decode('utf-8')
    })


def decrypt_from_json(key: Union[str, bytes], data: Union[str, bytes], cipher: JsonCiphers) -> str:
    """
    Decrypts data from a JSON string.

    Args:
        key (Union[str, bytes]): The decryption key, up to 16 bytes. Longer keys will be truncated.
        data (Union[str, bytes]): The encrypted data as a JSON string or bytes.
        cipher (Optional[JsonCiphers]): The cipher used for encryption. If None, it is auto-detected.

    Returns:
        str: The decrypted plaintext data.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
        DecryptionKeyError: If decryption fails due to an invalid key or corrupted data.
    """

    aes_ciphers = {JsonCiphers.JSON_B64_AES_GCM_128, JsonCiphers.JSON_HEX_AES_GCM_128}
    b64_ciphers = {JsonCiphers.JSON_B64_AES_GCM_128, JsonCiphers.JSON_B64_CHACHA20_POLY1305}

    if isinstance(data, str):
        data = json.loads(data)

    decoder = pybase64.b64decode if cipher in b64_ciphers else unhexlify
    bcipher = BinaryCiphers.BINARY_AES_GCM_128 if cipher in aes_ciphers else BinaryCiphers.BINARY_CHACHA20_POLY1305

    ciphertext = decoder(data["ciphertext"])
    if "tag" not in data:  # web crypto compatibility
        ciphertext, tag = ciphertext[:-16], ciphertext[-16:]
    else:
        tag = decoder(data["tag"])
    nonce = decoder(data["nonce"])

    decryptor = decrypt_AES_GCM_128 if bcipher == BinaryCiphers.BINARY_AES_GCM_128 else decrypt_ChaCha20_Poly1305
    try:
        plaintext = decryptor(key, ciphertext, tag, nonce)
        return plaintext.decode("utf-8")
    except ValueError as e:
        raise DecryptionKeyError from e


def encrypt_bin(key: Union[str, bytes], data: Union[str, bytes], cipher: BinaryCiphers) -> bytes:
    """
    Encrypts the given data and returns it as binary.

    Args:
        key (Union[str, bytes]): The encryption key, up to 16 bytes. Longer keys will be truncated.
        data (Union[str, bytes]): The data to encrypt. Strings will be encoded as UTF-8.
        cipher (BinaryCiphers): The encryption cipher. Only BINARY_AES_GCM_128 is supported.

    Returns:
        bytes: The encrypted data, including the nonce and tag.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
        EncryptionKeyError: If encryption fails.
    """
    if cipher not in BinaryCiphers:
        raise InvalidCipher(f"Invalid binary cipher: {str(cipher)}")

    encryptor = encrypt_AES_GCM_128 if cipher == BinaryCiphers.BINARY_AES_GCM_128 else encrypt_ChaCha20_Poly1305
    try:
        ciphertext, tag, nonce = encryptor(key, data)
    except Exception as e:
        raise EncryptionKeyError from e

    return nonce + ciphertext + tag


def decrypt_bin(key: Union[str, bytes], ciphertext: bytes, cipher: BinaryCiphers) -> bytes:
    """
    Decrypts binary data.

    Args:
        key (Union[str, bytes]): The decryption key, up to 16 bytes. Longer keys will be truncated.
        ciphertext (bytes): The binary encrypted data. Must include nonce and tag.
        cipher (BinaryCiphers): The cipher used for encryption. Only BINARY_AES_GCM_128 is supported.

    Returns:
        bytes: The decrypted plaintext data.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
        DecryptionKeyError: If decryption fails due to an invalid key or corrupted data.
    """
    if cipher not in BinaryCiphers:
        raise InvalidCipher(f"Invalid binary cipher: {str(cipher)}")

    # extract nonce/tag depending on cipher, sizes are different
    if cipher == BinaryCiphers.BINARY_AES_GCM_128:
        nonce, ciphertext, tag = ciphertext[:16], ciphertext[16:-16], ciphertext[-16:]
    else:
        nonce, ciphertext, tag = ciphertext[:12], ciphertext[12:-16], ciphertext[-16:]

    decryptor = decrypt_AES_GCM_128 if cipher == BinaryCiphers.BINARY_AES_GCM_128 else decrypt_ChaCha20_Poly1305
    try:
        return decryptor(key, ciphertext, tag, nonce)
    except ValueError as e:
        raise DecryptionKeyError from e


#############################
# Cipher Implementations
def encrypt_AES_GCM_128(key: Union[str, bytes], text: Union[str, bytes],
                        nonce: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-GCM-128.

    Args:
        key (Union[str, bytes]): The encryption key. Strings will be encoded as UTF-8.
        text (Union[str, bytes]): The plaintext to encrypt.
        nonce (Optional[bytes]): An optional nonce. If None, a new one is generated.

    Returns:
        tuple[bytes, bytes, bytes]: The ciphertext, authentication tag, and nonce.
    """
    if not isinstance(text, bytes):
        text = bytes(text, encoding="utf-8")
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return ciphertext, tag, cipher.nonce


def decrypt_AES_GCM_128(key: Union[str, bytes], ciphertext: bytes, tag: bytes, nonce: bytes) -> bytes:
    """
    Decrypts ciphertext encrypted using AES-GCM-128.

    Args:
        key (Union[str, bytes]): The decryption key. Strings will be encoded as UTF-8.
        ciphertext (bytes): The encrypted ciphertext.
        tag (bytes): The authentication tag.
        nonce (bytes): The nonce used during encryption.

    Returns:
        str: The decrypted plaintext.

    Raises:
        ValueError: If decryption or authentication fails.
    """
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_ChaCha20_Poly1305(key: Union[str, bytes],
                              text: Union[str, bytes],
                              nonce: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-GCM-128.

    Args:
        key (Union[str, bytes]): The encryption key. Strings will be encoded as UTF-8.
        text (Union[str, bytes]): The plaintext to encrypt.
        nonce (Optional[bytes]): An optional nonce. If None, a new one is generated.

    Returns:
        tuple[bytes, bytes, bytes]: The ciphertext, authentication tag, and nonce.
    """
    if not isinstance(text, bytes):
        text = bytes(text, encoding="utf-8")
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")
    assert len(key) == 32  # ChaCha20 uses 256 bit/32 byte keys
    if nonce:
        assert len(nonce) == 12  # 92bits/12bytes bytes per RFC7539
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return ciphertext, tag, cipher.nonce


def decrypt_ChaCha20_Poly1305(key: Union[str, bytes],
                              ciphertext: bytes,
                              tag: bytes,
                              nonce: bytes) -> bytes:
    """
    Decrypts ciphertext encrypted using AES-GCM-128.

    Args:
        key (Union[str, bytes]): The decryption key. Strings will be encoded as UTF-8.
        ciphertext (bytes): The encrypted ciphertext.
        tag (bytes): The authentication tag.
        nonce (bytes): The nonce used during encryption.

    Returns:
        str: The decrypted plaintext.

    Raises:
        ValueError: If decryption or authentication fails.
    """
    if not isinstance(key, bytes):
        key = bytes(key, encoding="utf-8")

    assert len(key) == 32  # ChaCha20 uses 256 bit/32 byte keys
    if nonce:
        assert len(nonce) == 12  # 92bits/12bytes per RFC7539
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


if __name__ == "__main__":
    from Cryptodome.Random import get_random_bytes

    print("JSON-B64-AES-GCM-128" == JsonCiphers.JSON_B64_AES_GCM_128)

    key = get_random_bytes(32)
    plaintext = b'Attack at dawn'
    ciphertext, tag, nonce = encrypt_ChaCha20_Poly1305(key, plaintext)
    recovered = decrypt_ChaCha20_Poly1305(key, ciphertext, tag, nonce)
    print(recovered)
    assert recovered == plaintext
