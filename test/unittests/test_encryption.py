"""Tests for hivemind_bus_client.encryption — encrypt/decrypt roundtrips and edge cases."""
import json
import pytest
from Cryptodome.Random import get_random_bytes

from hivemind_bus_client.encryption import (
    encrypt_as_json, decrypt_from_json,
    encrypt_bin, decrypt_bin,
    encrypt_AES, decrypt_AES_128,
    encrypt_ChaCha20_Poly1305, decrypt_ChaCha20_Poly1305,
    hybrid_encrypt, hybrid_decrypt,
    SupportedCiphers, SupportedEncodings,
    get_encoder, get_decoder,
    _norm_cipher, _norm_encoding,
    AES_KEY_SIZES, CHACHA20_KEY_SIZE,
)
from hivemind_bus_client.exceptions import (
    EncryptionKeyError, DecryptionKeyError, InvalidEncoding, InvalidCipher, InvalidKeySize,
)


class TestAESEncryption:
    def test_roundtrip_16_byte_key(self):
        key = get_random_bytes(16)
        ct, tag, nonce = encrypt_AES(key, "hello")
        result = decrypt_AES_128(key, ct, tag, nonce)
        assert result == b"hello"

    def test_roundtrip_32_byte_key(self):
        key = get_random_bytes(32)
        ct, tag, nonce = encrypt_AES(key, b"binary data")
        result = decrypt_AES_128(key, ct, tag, nonce)
        assert result == b"binary data"

    def test_invalid_key_size(self):
        with pytest.raises(InvalidKeySize):
            encrypt_AES(b"short", "test")

    def test_string_key(self):
        key = "a" * 16
        ct, tag, nonce = encrypt_AES(key, "test")
        result = decrypt_AES_128(key, ct, tag, nonce)
        assert result == b"test"


class TestChaCha20Encryption:
    def test_roundtrip(self):
        key = get_random_bytes(CHACHA20_KEY_SIZE)
        ct, tag, nonce = encrypt_ChaCha20_Poly1305(key, "hello")
        result = decrypt_ChaCha20_Poly1305(key, ct, tag, nonce)
        assert result == b"hello"

    def test_invalid_key_size(self):
        with pytest.raises(InvalidKeySize):
            encrypt_ChaCha20_Poly1305(b"short", "test")

    def test_invalid_nonce_size(self):
        key = get_random_bytes(CHACHA20_KEY_SIZE)
        with pytest.raises(InvalidKeySize):
            encrypt_ChaCha20_Poly1305(key, "test", nonce=b"short")


class TestBinEncryptDecrypt:
    @pytest.mark.parametrize("cipher", [SupportedCiphers.AES_GCM, SupportedCiphers.CHACHA20_POLY1305])
    def test_roundtrip(self, cipher):
        key = get_random_bytes(32)
        encrypted = encrypt_bin(key, "secret message", cipher)
        decrypted = decrypt_bin(key, encrypted, cipher)
        assert decrypted == b"secret message"

    def test_wrong_key_raises(self):
        key1 = get_random_bytes(32)
        key2 = get_random_bytes(32)
        encrypted = encrypt_bin(key1, "secret", SupportedCiphers.AES_GCM)
        with pytest.raises(DecryptionKeyError):
            decrypt_bin(key2, encrypted, SupportedCiphers.AES_GCM)


class TestJsonEncryptDecrypt:
    @pytest.mark.parametrize("cipher", [SupportedCiphers.AES_GCM, SupportedCiphers.CHACHA20_POLY1305])
    @pytest.mark.parametrize("encoding", [SupportedEncodings.JSON_B64, SupportedEncodings.JSON_HEX,
                                           SupportedEncodings.JSON_B32])
    def test_roundtrip(self, cipher, encoding):
        key = get_random_bytes(32)
        encrypted = encrypt_as_json(key, "hello world", cipher=cipher, encoding=encoding)
        decrypted = decrypt_from_json(key, encrypted, cipher=cipher, encoding=encoding)
        assert decrypted == "hello world"

    def test_dict_plaintext(self):
        key = get_random_bytes(32)
        data = {"utterance": "hello"}
        encrypted = encrypt_as_json(key, data)
        decrypted = decrypt_from_json(key, encrypted)
        assert json.loads(decrypted) == data

    def test_json_output_has_required_fields(self):
        key = get_random_bytes(32)
        encrypted = json.loads(encrypt_as_json(key, "test"))
        assert "ciphertext" in encrypted
        assert "tag" in encrypted
        assert "nonce" in encrypted


class TestNormHelpers:
    def test_norm_cipher_string(self):
        assert _norm_cipher("AES-GCM") == SupportedCiphers.AES_GCM

    def test_norm_cipher_enum(self):
        assert _norm_cipher(SupportedCiphers.AES_GCM) == SupportedCiphers.AES_GCM

    def test_norm_cipher_invalid(self):
        with pytest.raises(InvalidCipher):
            _norm_cipher("INVALID")

    def test_norm_encoding_string(self):
        assert _norm_encoding("JSON-B64") == SupportedEncodings.JSON_B64

    def test_norm_encoding_invalid(self):
        with pytest.raises(InvalidEncoding):
            _norm_encoding("INVALID")


class TestHybridEncryption:
    """Test hybrid RSA+AES-GCM encrypt/decrypt roundtrip."""

    @pytest.fixture(autouse=True)
    def _keys(self):
        from poorman_handshake.asymmetric.utils import create_RSA_key, load_RSA_key
        self.pub_pem, self.priv_key_obj = create_RSA_key()
        self.priv_key = self.priv_key_obj

    def test_roundtrip(self):
        plaintext = b"Hello from satellite!"
        envelope = hybrid_encrypt(self.pub_pem, plaintext, sign_key=self.priv_key)
        assert "encrypted_key" in envelope
        assert "ciphertext" in envelope
        assert "tag" in envelope
        assert "nonce" in envelope
        assert "signature" in envelope
        recovered = hybrid_decrypt(self.priv_key, envelope)
        assert recovered == plaintext

    def test_roundtrip_without_signature(self):
        plaintext = b"No signature"
        envelope = hybrid_encrypt(self.pub_pem, plaintext)
        assert "signature" not in envelope
        recovered = hybrid_decrypt(self.priv_key, envelope)
        assert recovered == plaintext

    def test_string_plaintext(self):
        plaintext = "unicode payload: café"
        envelope = hybrid_encrypt(self.pub_pem, plaintext)
        recovered = hybrid_decrypt(self.priv_key, envelope)
        assert recovered == plaintext.encode("utf-8")

    def test_wrong_key_fails(self):
        from poorman_handshake.asymmetric.utils import create_RSA_key
        other_pub, other_priv = create_RSA_key()
        envelope = hybrid_encrypt(other_pub, b"secret")
        with pytest.raises(Exception):
            hybrid_decrypt(self.priv_key, envelope)


class TestEncoderDecoder:
    @pytest.mark.parametrize("encoding", list(SupportedEncodings))
    def test_roundtrip(self, encoding):
        encoder = get_encoder(encoding)
        decoder = get_decoder(encoding)
        data = b"test data 12345"
        assert decoder(encoder(data)) == data


# ---------------------------------------------------------------------------
# Fix 3: hybrid_decrypt sender authentication
# ---------------------------------------------------------------------------

class TestHybridDecryptSignatureVerification:
    """verify_key parameter in hybrid_decrypt (Fix 3)."""

    @pytest.fixture(scope="class")
    def sender_keys(self):
        from Cryptodome.PublicKey import RSA
        key = RSA.generate(2048)
        return key.public_key().export_key("PEM").decode(), key.export_key("PEM").decode()

    @pytest.fixture(scope="class")
    def recipient_keys(self):
        from Cryptodome.PublicKey import RSA
        key = RSA.generate(2048)
        return key.public_key().export_key("PEM").decode(), key.export_key("PEM").decode()

    def test_verify_key_accepts_valid_signature(self, sender_keys, recipient_keys):
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        import tempfile, os
        _, sender_priv_pem = sender_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(sender_priv_pem)
            tmp = f.name
        try:
            sender_priv = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        recipient_pub, recipient_priv_pem = recipient_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(recipient_priv_pem)
            tmp2 = f.name
        try:
            recipient_priv = load_RSA_key(tmp2)
        finally:
            os.unlink(tmp2)
        envelope = hybrid_encrypt(recipient_pub, b"hello", sign_key=sender_priv)
        plaintext = hybrid_decrypt(recipient_priv, envelope, verify_key=sender_keys[0])
        assert plaintext == b"hello"

    def test_verify_key_rejects_wrong_sender(self, sender_keys, recipient_keys):
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        from Cryptodome.PublicKey import RSA
        import tempfile, os
        _, sender_priv_pem = sender_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(sender_priv_pem)
            tmp = f.name
        try:
            sender_priv = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        recipient_pub, recipient_priv_pem = recipient_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(recipient_priv_pem)
            tmp2 = f.name
        try:
            recipient_priv = load_RSA_key(tmp2)
        finally:
            os.unlink(tmp2)
        envelope = hybrid_encrypt(recipient_pub, b"hello", sign_key=sender_priv)
        wrong_pub = RSA.generate(2048).public_key().export_key("PEM").decode()
        with pytest.raises(ValueError, match="signature verification failed"):
            hybrid_decrypt(recipient_priv, envelope, verify_key=wrong_pub)

    def test_verify_key_requires_signature_present(self, sender_keys, recipient_keys):
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        import tempfile, os
        recipient_pub, recipient_priv_pem = recipient_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(recipient_priv_pem)
            tmp = f.name
        try:
            recipient_priv = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        # Unsigned envelope
        envelope = hybrid_encrypt(recipient_pub, b"hello")
        with pytest.raises(ValueError, match="signature.*absent"):
            hybrid_decrypt(recipient_priv, envelope, verify_key=sender_keys[0])

    def test_no_verify_key_ignores_signature(self, sender_keys, recipient_keys):
        """Without verify_key, a signed envelope still decrypts cleanly."""
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        import tempfile, os
        _, sender_priv_pem = sender_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(sender_priv_pem)
            tmp = f.name
        try:
            sender_priv = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        recipient_pub, recipient_priv_pem = recipient_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(recipient_priv_pem)
            tmp2 = f.name
        try:
            recipient_priv = load_RSA_key(tmp2)
        finally:
            os.unlink(tmp2)
        envelope = hybrid_encrypt(recipient_pub, b"hello", sign_key=sender_priv)
        plaintext = hybrid_decrypt(recipient_priv, envelope)
        assert plaintext == b"hello"


# ---------------------------------------------------------------------------
# Fix 4: hybrid_encrypt/decrypt recipient binding via AAD
# ---------------------------------------------------------------------------

class TestHybridRecipientBinding:
    """recipient_pubkey / expected_recipient AAD binding (Fix 4)."""

    @pytest.fixture(scope="class")
    def recipient_a_keys(self):
        from Cryptodome.PublicKey import RSA
        key = RSA.generate(2048)
        return key.public_key().export_key("PEM").decode(), key.export_key("PEM").decode()

    @pytest.fixture(scope="class")
    def recipient_b_keys(self):
        from Cryptodome.PublicKey import RSA
        key = RSA.generate(2048)
        return key.public_key().export_key("PEM").decode(), key.export_key("PEM").decode()

    def test_correct_recipient_decrypts(self, recipient_a_keys):
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        import tempfile, os
        pub_a, priv_a_pem = recipient_a_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(priv_a_pem)
            tmp = f.name
        try:
            priv_a = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        envelope = hybrid_encrypt(pub_a, b"secret", recipient_pubkey=pub_a)
        assert "recipient_fingerprint" in envelope
        plaintext = hybrid_decrypt(priv_a, envelope, expected_recipient=pub_a)
        assert plaintext == b"secret"

    def test_wrong_recipient_aad_fails(self, recipient_a_keys, recipient_b_keys):
        """Decryption with expected_recipient=B for an envelope bound to A fails GCM auth."""
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        import tempfile, os
        pub_a, _ = recipient_a_keys
        pub_b, priv_b_pem = recipient_b_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(priv_b_pem)
            tmp = f.name
        try:
            priv_b = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        # Encrypt to A, but try to verify as if intended for B
        envelope = hybrid_encrypt(pub_b, b"secret", recipient_pubkey=pub_a)
        with pytest.raises(ValueError):
            hybrid_decrypt(priv_b, envelope, expected_recipient=pub_b)

    def test_no_recipient_binding_still_decrypts(self, recipient_a_keys):
        """Envelope without recipient_fingerprint decrypts even with expected_recipient."""
        from hivemind_bus_client.encryption import hybrid_encrypt, hybrid_decrypt
        from poorman_handshake.asymmetric.utils import load_RSA_key
        import tempfile, os
        pub_a, priv_a_pem = recipient_a_keys
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
            f.write(priv_a_pem)
            tmp = f.name
        try:
            priv_a = load_RSA_key(tmp)
        finally:
            os.unlink(tmp)
        # No recipient_pubkey → no AAD → expected_recipient is ignored
        envelope = hybrid_encrypt(pub_a, b"legacy")
        assert "recipient_fingerprint" not in envelope
        plaintext = hybrid_decrypt(priv_a, envelope, expected_recipient=pub_a)
        assert plaintext == b"legacy"
