import unittest

from Cryptodome.Random import get_random_bytes

from hivemind_bus_client.encryption import (
    encrypt_AES, decrypt_AES_128,
    encrypt_ChaCha20_Poly1305, decrypt_ChaCha20_Poly1305,
    encrypt_bin, decrypt_bin,
    encrypt_as_json, decrypt_from_json,
    SupportedCiphers, SupportedEncodings,
    get_encoder, get_decoder,
    _norm_cipher, _norm_encoding,
    AES_KEY_SIZES, CHACHA20_KEY_SIZE,
)
from hivemind_bus_client.exceptions import (
    InvalidKeySize, EncryptionKeyError, DecryptionKeyError, InvalidEncoding, InvalidCipher
)


class TestNormCipher(unittest.TestCase):
    def test_string_to_enum(self):
        self.assertEqual(_norm_cipher("AES-GCM"), SupportedCiphers.AES_GCM)
        self.assertEqual(_norm_cipher("CHACHA20-POLY1305"), SupportedCiphers.CHACHA20_POLY1305)

    def test_enum_passthrough(self):
        self.assertEqual(_norm_cipher(SupportedCiphers.AES_GCM), SupportedCiphers.AES_GCM)

    def test_invalid_raises(self):
        with self.assertRaises(InvalidCipher):
            _norm_cipher("INVALID-CIPHER")


class TestNormEncoding(unittest.TestCase):
    def test_string_to_enum(self):
        self.assertEqual(_norm_encoding("JSON-B64"), SupportedEncodings.JSON_B64)
        self.assertEqual(_norm_encoding("JSON-HEX"), SupportedEncodings.JSON_HEX)

    def test_enum_passthrough(self):
        self.assertEqual(_norm_encoding(SupportedEncodings.JSON_B64), SupportedEncodings.JSON_B64)

    def test_invalid_raises(self):
        with self.assertRaises(InvalidEncoding):
            _norm_encoding("INVALID-ENCODING")


class TestGetEncoderDecoder(unittest.TestCase):
    def test_all_encodings_have_encoder_and_decoder(self):
        for enc in SupportedEncodings:
            encoder = get_encoder(enc)
            decoder = get_decoder(enc)
            self.callable(encoder)
            self.callable(decoder)

    def callable(self, obj):
        self.assertTrue(callable(obj))

    def test_encoder_decoder_roundtrip(self):
        data = b"test data 12345678"
        for enc in SupportedEncodings:
            encoder = get_encoder(enc)
            decoder = get_decoder(enc)
            encoded = encoder(data)
            decoded = decoder(encoded)
            self.assertEqual(decoded, data, f"roundtrip failed for {enc}")


class TestAESEncryption(unittest.TestCase):
    def test_encrypt_decrypt_16_byte_key(self):
        key = b"a" * 16
        plaintext = b"Attack at dawn!!"
        ciphertext, tag, nonce = encrypt_AES(key, plaintext)
        recovered = decrypt_AES_128(key, ciphertext, tag, nonce)
        self.assertEqual(recovered, plaintext)

    def test_encrypt_decrypt_32_byte_key(self):
        key = b"b" * 32
        plaintext = b"Secret message"
        ciphertext, tag, nonce = encrypt_AES(key, plaintext)
        recovered = decrypt_AES_128(key, ciphertext, tag, nonce)
        self.assertEqual(recovered, plaintext)

    def test_string_key_and_text(self):
        key = "a" * 16
        plaintext = "Hello World"
        ciphertext, tag, nonce = encrypt_AES(key, plaintext)
        recovered = decrypt_AES_128(key, ciphertext, tag, nonce)
        self.assertEqual(recovered, plaintext.encode("utf-8"))

    def test_invalid_key_size_raises(self):
        with self.assertRaises(InvalidKeySize):
            encrypt_AES(b"shortkey", b"data")

    def test_wrong_key_decrypt_raises(self):
        key = b"a" * 16
        wrong_key = b"b" * 16
        plaintext = b"Secret"
        ciphertext, tag, nonce = encrypt_AES(key, plaintext)
        with self.assertRaises(Exception):
            decrypt_AES_128(wrong_key, ciphertext, tag, nonce)

    def test_nonce_is_16_bytes(self):
        key = b"a" * 16
        _, _, nonce = encrypt_AES(key, b"data")
        self.assertEqual(len(nonce), 16)

    def test_empty_plaintext(self):
        key = b"a" * 16
        ciphertext, tag, nonce = encrypt_AES(key, b"")
        recovered = decrypt_AES_128(key, ciphertext, tag, nonce)
        self.assertEqual(recovered, b"")


class TestChaCha20Encryption(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = get_random_bytes(CHACHA20_KEY_SIZE)
        plaintext = b"Attack at dawn"
        ciphertext, tag, nonce = encrypt_ChaCha20_Poly1305(key, plaintext)
        recovered = decrypt_ChaCha20_Poly1305(key, ciphertext, tag, nonce)
        self.assertEqual(recovered, plaintext)

    def test_string_inputs(self):
        key = "a" * 32
        plaintext = "Hello World"
        ciphertext, tag, nonce = encrypt_ChaCha20_Poly1305(key, plaintext)
        recovered = decrypt_ChaCha20_Poly1305(key, ciphertext, tag, nonce)
        self.assertEqual(recovered, plaintext.encode("utf-8"))

    def test_invalid_key_size_raises(self):
        with self.assertRaises(InvalidKeySize):
            encrypt_ChaCha20_Poly1305(b"shortkey", b"data")

    def test_wrong_key_decrypt_raises(self):
        key = get_random_bytes(CHACHA20_KEY_SIZE)
        wrong_key = get_random_bytes(CHACHA20_KEY_SIZE)
        plaintext = b"Secret"
        ciphertext, tag, nonce = encrypt_ChaCha20_Poly1305(key, plaintext)
        with self.assertRaises(Exception):
            decrypt_ChaCha20_Poly1305(wrong_key, ciphertext, tag, nonce)

    def test_nonce_is_12_bytes(self):
        key = get_random_bytes(CHACHA20_KEY_SIZE)
        _, _, nonce = encrypt_ChaCha20_Poly1305(key, b"data")
        self.assertEqual(len(nonce), 12)


class TestEncryptBin(unittest.TestCase):
    def test_aes_gcm_roundtrip(self):
        key = b"a" * 16
        plaintext = b"Hello World"
        ciphertext = encrypt_bin(key, plaintext, SupportedCiphers.AES_GCM)
        recovered = decrypt_bin(key, ciphertext, SupportedCiphers.AES_GCM)
        self.assertEqual(recovered, plaintext)

    def test_chacha20_roundtrip(self):
        key = b"a" * 32
        plaintext = b"Hello World"
        ciphertext = encrypt_bin(key, plaintext, SupportedCiphers.CHACHA20_POLY1305)
        recovered = decrypt_bin(key, ciphertext, SupportedCiphers.CHACHA20_POLY1305)
        self.assertEqual(recovered, plaintext)

    def test_string_cipher_name(self):
        key = b"a" * 16
        plaintext = b"test"
        ciphertext = encrypt_bin(key, plaintext, "AES-GCM")
        recovered = decrypt_bin(key, ciphertext, "AES-GCM")
        self.assertEqual(recovered, plaintext)


class TestEncryptAsJson(unittest.TestCase):
    def _roundtrip(self, key, plaintext, cipher, encoding):
        encrypted = encrypt_as_json(key, plaintext, cipher=cipher, encoding=encoding)
        decrypted = decrypt_from_json(key, encrypted, cipher=cipher, encoding=encoding)
        self.assertEqual(decrypted, plaintext if isinstance(plaintext, str) else plaintext)

    def test_aes_b64_roundtrip(self):
        key = b"a" * 16
        self._roundtrip(key, "Hello World", SupportedCiphers.AES_GCM, SupportedEncodings.JSON_B64)

    def test_aes_hex_roundtrip(self):
        key = b"a" * 16
        self._roundtrip(key, "Hello World", SupportedCiphers.AES_GCM, SupportedEncodings.JSON_HEX)

    def test_aes_z85b_roundtrip(self):
        key = b"a" * 16
        self._roundtrip(key, "Hello World", SupportedCiphers.AES_GCM, SupportedEncodings.JSON_Z85B)

    def test_aes_b91_roundtrip(self):
        key = b"a" * 16
        self._roundtrip(key, "Hello World", SupportedCiphers.AES_GCM, SupportedEncodings.JSON_B91)

    def test_chacha20_b64_roundtrip(self):
        key = b"a" * 32
        self._roundtrip(key, "Secret data", SupportedCiphers.CHACHA20_POLY1305, SupportedEncodings.JSON_B64)

    def test_dict_plaintext(self):
        key = b"a" * 16
        data = {"message": "hello", "lang": "en-us"}
        encrypted = encrypt_as_json(key, data)
        decrypted = decrypt_from_json(key, encrypted)
        import json
        self.assertEqual(json.loads(decrypted), data)

    def test_wrong_key_raises(self):
        key = b"a" * 16
        wrong_key = b"b" * 16
        encrypted = encrypt_as_json(key, "secret")
        with self.assertRaises(DecryptionKeyError):
            decrypt_from_json(wrong_key, encrypted)

    def test_invalid_key_size_raises(self):
        with self.assertRaises(InvalidKeySize):
            encrypt_as_json(b"short", "data", cipher=SupportedCiphers.AES_GCM)

    def test_output_is_json_string(self):
        key = b"a" * 16
        result = encrypt_as_json(key, "test")
        import json
        parsed = json.loads(result)
        self.assertIn("ciphertext", parsed)
        self.assertIn("tag", parsed)
        self.assertIn("nonce", parsed)


if __name__ == "__main__":
    unittest.main()
