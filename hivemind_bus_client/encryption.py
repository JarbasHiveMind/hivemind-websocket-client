import enum
import json
from binascii import hexlify, unhexlify
from typing import Union, Optional, Dict, Any, Literal, List

import pybase64
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from cpuinfo import get_cpu_info

from hivemind_bus_client.exceptions import EncryptionKeyError, DecryptionKeyError, InvalidCipher, InvalidKeySize

# Cipher-specific constants
AES_KEY_SIZES = [16, 24, 32]  # poorman_handshake generates 32 bit secrets
AES_NONCE_SIZE = 16
AES_TAG_SIZE = 16
CHACHA20_KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 12
CHACHA20_TAG_SIZE = 16


def cpu_supports_AES() -> bool:
    """
    Check if the CPU supports AES encryption.

    Returns:
        bool: True if AES is supported by the CPU, False otherwise.
    """
    return "aes" in get_cpu_info()["flags"]


class SupportedEncodings(str, enum.Enum):
    """
    Enum representing JSON-based encryption encodings.

    Ciphers output binary data, json needs to transmit that data as plaintext
    """
    JSON_B64 = "JSON-B64"  # JSON text output with Base64 encoding
    JSON_HEX = "JSON-HEX"  # JSON text output with Hex encoding (LEGACY SUPPORT)


class SupportedCiphers(str, enum.Enum):
    """
    Enum representing binary encryption ciphers.

    Specifications:
      - AES - http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
      - GCM - http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
      - CHACHA20-POLY1305 - https://datatracker.ietf.org/doc/html/rfc7539
    """
    AES_GCM = "AES-GCM"
    AES_CCM = "AES-CCM"
    CHACHA20_POLY1305 = "CHACHA20-POLY1305"  # specified in RFC7539.


AES_CIPHERS = {c for c in SupportedCiphers if "AES" in c}
BLOCK_CIPHERS = AES_CIPHERS  # Blowfish etc can be added in the future


def optimal_ciphers() -> List[SupportedCiphers]:
    if not cpu_supports_AES():
        return [SupportedCiphers.CHACHA20_POLY1305, SupportedCiphers.AES_CCM, SupportedCiphers.AES_GCM]
    return [SupportedCiphers.AES_GCM, SupportedCiphers.AES_CCM, SupportedCiphers.CHACHA20_POLY1305]


def encrypt_as_json(key: Union[str, bytes], data: Union[str, Dict[str, Any]],
                    cipher: SupportedCiphers = SupportedCiphers.AES_GCM,
                    encoding: SupportedEncodings = SupportedEncodings.JSON_B64) -> str:
    """
    Encrypts the given data and outputs it as a JSON string.

    Args:
        key (Union[str, bytes]): The encryption key, up to 16 bytes. Longer keys will be truncated.
        data (Union[str, Dict[str, Any]]): The data to encrypt. If a dictionary, it will be serialized to JSON.
        cipher (SupportedEncodings): The encryption cipher. Supported options:
            - JSON-B64-AES-GCM-128: Outputs Base64-encoded JSON.
            - JSON-HEX-AES-GCM-128: Outputs Hex-encoded JSON.

    Returns:
        str: A JSON string containing the encrypted data, nonce, and tag.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
    """
    if cipher not in SupportedCiphers:
        raise InvalidCipher(f"Invalid cipher: {str(cipher)}")
    if encoding not in SupportedEncodings:
        raise InvalidCipher(f"Invalid JSON encoding: {str(encoding)}")

    if isinstance(data, dict):
        data = json.dumps(data)

    try:
        ciphertext = encrypt_bin(key=key, plaintext=data, cipher=cipher)
    except InvalidKeySize as e:
        raise e
    except Exception as e:
        raise EncryptionKeyError from e

    # extract nonce/tag depending on cipher, sizes are different
    if cipher in AES_CIPHERS:
        nonce, ciphertext, tag = (ciphertext[:AES_NONCE_SIZE],
                                  ciphertext[AES_NONCE_SIZE:-AES_TAG_SIZE],
                                  ciphertext[-AES_TAG_SIZE:])
    else:
        nonce, ciphertext, tag = (ciphertext[:CHACHA20_NONCE_SIZE],
                                  ciphertext[CHACHA20_NONCE_SIZE:-CHACHA20_TAG_SIZE],
                                  ciphertext[-CHACHA20_TAG_SIZE:])

    encoder = pybase64.b64encode if encoding == SupportedEncodings.JSON_B64 else hexlify

    return json.dumps({
        "ciphertext": encoder(ciphertext).decode('utf-8'),
        "tag": encoder(tag).decode('utf-8'),
        "nonce": encoder(nonce).decode('utf-8')
    })


def decrypt_from_json(key: Union[str, bytes], data: Union[str, bytes],
                      cipher: SupportedCiphers = SupportedCiphers.AES_GCM,
                      encoding: SupportedEncodings = SupportedEncodings.JSON_B64) -> str:
    """
    Decrypts data from a JSON string.

    Args:
        key (Union[str, bytes]): The decryption key, up to 16 bytes. Longer keys will be truncated.
        data (Union[str, bytes]): The encrypted data as a JSON string or bytes.
        cipher (SupportedEncodings): The cipher used for encryption.

    Returns:
        str: The decrypted plaintext data.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
        DecryptionKeyError: If decryption fails due to an invalid key or corrupted data.
    """
    if cipher not in SupportedCiphers:
        raise InvalidCipher(f"Invalid cipher: {str(cipher)}")
    if encoding not in SupportedEncodings:
        raise InvalidCipher(f"Invalid JSON encoding: {str(encoding)}")

    if isinstance(data, str):
        data = json.loads(data)

    decoder = pybase64.b64decode if encoding == SupportedEncodings.JSON_B64 else unhexlify

    ciphertext = decoder(data["ciphertext"])
    if "tag" not in data:  # web crypto compatibility
        if cipher in AES_CIPHERS:
            ciphertext, tag = ciphertext[:-AES_TAG_SIZE], ciphertext[-AES_TAG_SIZE:]
        else:
            ciphertext, tag = ciphertext[:-CHACHA20_TAG_SIZE], ciphertext[-CHACHA20_TAG_SIZE:]
    else:
        tag = decoder(data["tag"])
    nonce = decoder(data["nonce"])

    try:
        plaintext = decrypt_bin(key=key,
                                ciphertext=nonce + ciphertext + tag,
                                cipher=cipher)
        return plaintext.decode("utf-8")
    except InvalidKeySize as e:
        raise e
    except Exception as e:
        raise DecryptionKeyError from e


def encrypt_bin(key: Union[str, bytes], plaintext: Union[str, bytes], cipher: SupportedCiphers) -> bytes:
    """
    Encrypts the given data and returns it as binary.

    Args:
        key (Union[str, bytes]): The encryption key, up to 16 bytes. Longer keys will be truncated.
        plaintext (Union[str, bytes]): The data to encrypt. Strings will be encoded as UTF-8.
        cipher (SupportedCiphers): The encryption cipher. Supported options:
            - AES_GCM: AES-GCM with 128-bit/256-bit key
            - AES_CCM: AES-GCM with 128-bit/256-bit key
            - CHACHA20_POLY1305: ChaCha20-Poly1305 with 256-bit key

    Returns:
        bytes: The encrypted data, including the nonce and tag.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
        EncryptionKeyError: If encryption fails.
    """
    if cipher not in SupportedCiphers:
        raise InvalidCipher(f"Invalid cipher: {str(cipher)}")

    encryptor = encrypt_AES if cipher in AES_CIPHERS else encrypt_ChaCha20_Poly1305

    try:
        if cipher in BLOCK_CIPHERS:
            if cipher == SupportedCiphers.AES_GCM:
                mode = AES.MODE_GCM
            elif cipher == SupportedCiphers.AES_CCM:
                mode = AES.MODE_CCM
            else:
                raise ValueError("invalid block cipher mode")
            ciphertext, tag, nonce = encryptor(key, plaintext, mode=mode)
        else:
            ciphertext, tag, nonce = encryptor(key, plaintext)
    except InvalidKeySize as e:
        raise e
    except Exception as e:
        raise EncryptionKeyError from e

    return nonce + ciphertext + tag


def decrypt_bin(key: Union[str, bytes], ciphertext: bytes, cipher: SupportedCiphers) -> bytes:
    """
    Decrypts binary data.

    Args:
        key (Union[str, bytes]): The decryption key, up to 16 bytes. Longer keys will be truncated.
        ciphertext (bytes): The binary encrypted data. Must include nonce and tag.
        cipher (SupportedCiphers): The cipher used for encryption.

    Returns:
        bytes: The decrypted plaintext data.

    Raises:
        InvalidCipher: If an unsupported cipher is provided.
        DecryptionKeyError: If decryption fails due to an invalid key or corrupted data.
    """
    if cipher not in SupportedCiphers:
        raise InvalidCipher(f"Invalid cipher: {str(cipher)}")

    # extract nonce/tag depending on cipher, sizes are different
    if cipher in AES_CIPHERS:
        nonce, ciphertext, tag = (ciphertext[:AES_NONCE_SIZE],
                                  ciphertext[AES_NONCE_SIZE:-AES_TAG_SIZE],
                                  ciphertext[-AES_TAG_SIZE:])
    else:
        nonce, ciphertext, tag = (ciphertext[:CHACHA20_NONCE_SIZE],
                                  ciphertext[CHACHA20_NONCE_SIZE:-CHACHA20_TAG_SIZE],
                                  ciphertext[-CHACHA20_TAG_SIZE:])

    decryptor = decrypt_AES_128 if cipher in AES_CIPHERS else decrypt_ChaCha20_Poly1305
    try:
        if cipher in BLOCK_CIPHERS:
            if cipher == SupportedCiphers.AES_GCM:
                mode = AES.MODE_GCM
            elif cipher == SupportedCiphers.AES_CCM:
                mode = AES.MODE_CCM
            else:
                raise ValueError("invalid block cipher mode")
            return decryptor(key, ciphertext, tag, nonce, mode=mode)
        return decryptor(key, ciphertext, tag, nonce)
    except InvalidKeySize as e:
        raise e
    except Exception as e:
        raise DecryptionKeyError from e


#############################
# Cipher Implementations
def encrypt_AES(key: Union[str, bytes], text: Union[str, bytes],
                nonce: Optional[bytes] = None,
                mode: Literal[AES.MODE_GCM, AES.MODE_CCM] = AES.MODE_GCM) -> tuple[bytes, bytes, bytes]:
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
    # AES-128 uses 128 bit/16 byte keys
    # AES-256 uses 256 bit/32 byte keys
    if len(key) not in AES_KEY_SIZES:
        raise InvalidKeySize("AES-GCM requires a 16/24/32 bytes key")
    cipher = AES.new(key, mode, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return ciphertext, tag, cipher.nonce


def decrypt_AES_128(key: Union[str, bytes],
                    ciphertext: bytes,
                    tag: bytes,
                    nonce: bytes,
                    mode: Literal[AES.MODE_GCM, AES.MODE_CCM] = AES.MODE_GCM) -> bytes:
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
        InvalidKeySize: If key size is not valid
        ValueError: If decryption or authentication fails.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    # AES-128 uses 128 bit/16 byte keys
    # AES-256 uses 256 bit/32 byte keys
    if len(key) not in AES_KEY_SIZES:
        raise InvalidKeySize("AES-GCM requires a 16/24/32 bytes key")
    cipher = AES.new(key, mode, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_ChaCha20_Poly1305(key: Union[str, bytes],
                              text: Union[str, bytes],
                              nonce: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using ChaCha20-Poly1305.

    Args:
        key (Union[str, bytes]): The encryption key. Strings will be encoded as UTF-8.
        text (Union[str, bytes]): The plaintext to encrypt.
        nonce (Optional[bytes]): An optional nonce. If None, a new one is generated.

    Returns:
        tuple[bytes, bytes, bytes]: The ciphertext, authentication tag, and nonce.
    """
    if isinstance(text, str):
        text = text.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")

    if len(key) != CHACHA20_KEY_SIZE:  # ChaCha20 uses 256 bit/32 byte keys
        raise InvalidKeySize("CHACHA20-POLY1305 requires a 32-byte key")
    if nonce:
        if len(nonce) != CHACHA20_NONCE_SIZE:  # 92bits/12bytes per RFC7539
            raise InvalidKeySize("CHACHA20-POLY1305 requires a 12-byte nonce per RFC7539")
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
        InvalidKeySize:
        ValueError: If decryption or authentication fails.
    """
    if isinstance(key, str):
        key = key.encode("utf-8")

    if len(key) != CHACHA20_KEY_SIZE:  # ChaCha20 uses 256 bit/32 byte keys
        raise InvalidKeySize("CHACHA20-POLY1305 requires a 32-byte key")
    if nonce:
        if len(nonce) != CHACHA20_NONCE_SIZE:  # 92bits/12bytes per RFC7539
            raise InvalidKeySize("CHACHA20-POLY1305 requires a 12-byte nonce per RFC7539")
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


if __name__ == "__main__":
    from Cryptodome.Random import get_random_bytes

    print("JSON-B64" == SupportedEncodings.JSON_B64)

    key = get_random_bytes(CHACHA20_KEY_SIZE)
    plaintext = b'Attack at dawn'
    ciphertext, tag, nonce = encrypt_ChaCha20_Poly1305(key, plaintext)
    recovered = decrypt_ChaCha20_Poly1305(key, ciphertext, tag, nonce)
    print(recovered)
    assert recovered == plaintext
