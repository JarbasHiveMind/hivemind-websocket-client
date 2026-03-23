"""Tests for INTERCOM verification and execution whitelist utilities."""
import unittest
from unittest.mock import MagicMock, patch

import pybase64
from Cryptodome.PublicKey import RSA

from hivemind_bus_client.intercom_utils import (
    IntercomPolicy,
    IntercomVerificationResult,
    verify_intercom,
    check_execution_whitelist,
)
from hivemind_plugin_manager.database import TrustedPeer, AbstractTrustStore
from poorman_handshake.asymmetric.utils import sign_RSA, hybrid_encrypt_RSA


def _generate_keypair():
    """Generate a 2048-bit RSA key pair for testing."""
    key = RSA.generate(2048)
    return key, key.publickey()


class TestIntercomPolicy(unittest.TestCase):
    """Test IntercomPolicy enum values."""

    def test_enum_values(self):
        """Verify all policy enum values exist."""
        self.assertEqual(IntercomPolicy.SILENT_DROP, "silent_drop")
        self.assertEqual(IntercomPolicy.DELIVER_UNTRUSTED, "deliver_untrusted")
        self.assertEqual(IntercomPolicy.LOG_ONLY, "log_only")

    def test_from_string(self):
        """Verify policies can be constructed from strings."""
        self.assertEqual(IntercomPolicy("silent_drop"), IntercomPolicy.SILENT_DROP)
        self.assertEqual(IntercomPolicy("deliver_untrusted"), IntercomPolicy.DELIVER_UNTRUSTED)
        self.assertEqual(IntercomPolicy("log_only"), IntercomPolicy.LOG_ONLY)


class TestVerifyIntercom(unittest.TestCase):
    """Test verify_intercom() signature verification and trust lookup."""

    @classmethod
    def setUpClass(cls):
        """Generate keys once for all tests."""
        cls.sender_priv, cls.sender_pub = _generate_keypair()
        cls.receiver_priv, cls.receiver_pub = _generate_keypair()
        cls.sender_pem = cls.sender_pub.export_key().decode()

    def _make_payload(self, message: bytes = b"test message",
                      sender_pem: str = None, use_wrong_key: bool = False):
        """Build an INTERCOM payload dict with ciphertext + signature."""
        sender_pem = sender_pem or self.sender_pem
        ciphertext = hybrid_encrypt_RSA(self.receiver_pub, message)
        if use_wrong_key:
            other_priv, _ = _generate_keypair()
            signature = sign_RSA(other_priv, ciphertext)
        else:
            signature = sign_RSA(self.sender_priv, ciphertext)
        return {
            "ciphertext": pybase64.b64encode(ciphertext),
            "signature": pybase64.b64encode(signature),
            "sender_pubkey": sender_pem,
        }

    def test_valid_signature_no_trust_store(self):
        """Valid signature without trust store: sig_valid=True, trusted=False."""
        pload = self._make_payload()
        result = verify_intercom(pload, None)
        self.assertTrue(result.signature_valid)
        self.assertFalse(result.trusted)
        self.assertEqual(result.sender_pubkey, self.sender_pem)
        self.assertIsNone(result.peer)

    def test_valid_signature_trusted(self):
        """Valid signature with matching trust store entry."""
        peer = TrustedPeer(peer_id="test", public_key=self.sender_pem, name="Test")
        trust_store = MagicMock(spec=AbstractTrustStore)
        trust_store.get_peer_by_pubkey.return_value = peer

        pload = self._make_payload()
        result = verify_intercom(pload, trust_store)
        self.assertTrue(result.signature_valid)
        self.assertTrue(result.trusted)
        self.assertEqual(result.peer, peer)

    def test_valid_signature_untrusted(self):
        """Valid signature but key not in trust store."""
        trust_store = MagicMock(spec=AbstractTrustStore)
        trust_store.get_peer_by_pubkey.return_value = None

        pload = self._make_payload()
        result = verify_intercom(pload, trust_store)
        self.assertTrue(result.signature_valid)
        self.assertFalse(result.trusted)

    def test_invalid_signature(self):
        """Invalid signature (wrong key)."""
        pload = self._make_payload(use_wrong_key=True)
        result = verify_intercom(pload, None)
        self.assertFalse(result.signature_valid)
        self.assertFalse(result.trusted)

    def test_missing_sender_pubkey(self):
        """No sender_pubkey in payload — treated as unsigned."""
        pload = self._make_payload()
        del pload["sender_pubkey"]
        result = verify_intercom(pload, None)
        self.assertFalse(result.signature_valid)
        self.assertFalse(result.trusted)
        self.assertIsNone(result.sender_pubkey)

    def test_corrupted_ciphertext(self):
        """Corrupted base64 in payload — signature invalid."""
        pload = self._make_payload()
        pload["ciphertext"] = "not-valid-base64!!!"
        result = verify_intercom(pload, None)
        self.assertFalse(result.signature_valid)


class TestCheckExecutionWhitelist(unittest.TestCase):
    """Test check_execution_whitelist() two-tier filtering."""

    def test_empty_lists_allow_all(self):
        """Empty global + empty peer lists = allow everything."""
        self.assertTrue(check_execution_whitelist("anything", None, []))

    def test_global_whitelist_blocks(self):
        """Global whitelist blocks unlisted types."""
        self.assertFalse(check_execution_whitelist(
            "speak", None, ["recognizer_loop:utterance"]))

    def test_global_whitelist_allows(self):
        """Global whitelist allows listed types."""
        self.assertTrue(check_execution_whitelist(
            "recognizer_loop:utterance", None, ["recognizer_loop:utterance"]))

    def test_peer_whitelist_blocks(self):
        """Per-peer whitelist blocks unlisted types."""
        peer = TrustedPeer(peer_id="x", public_key="", allowed_types=["speak"])
        self.assertFalse(check_execution_whitelist("other_type", peer, []))

    def test_peer_whitelist_allows(self):
        """Per-peer whitelist allows listed types."""
        peer = TrustedPeer(peer_id="x", public_key="", allowed_types=["speak"])
        self.assertTrue(check_execution_whitelist("speak", peer, []))

    def test_both_whitelists_must_pass(self):
        """Type must pass both global AND per-peer whitelists."""
        peer = TrustedPeer(peer_id="x", public_key="",
                           allowed_types=["speak", "recognizer_loop:utterance"])
        # passes peer but not global
        self.assertFalse(check_execution_whitelist(
            "speak", peer, ["recognizer_loop:utterance"]))
        # passes both
        self.assertTrue(check_execution_whitelist(
            "recognizer_loop:utterance", peer, ["recognizer_loop:utterance"]))

    def test_peer_empty_allows_all(self):
        """Peer with empty allowed_types = allow all (only global applies)."""
        peer = TrustedPeer(peer_id="x", public_key="", allowed_types=[])
        self.assertTrue(check_execution_whitelist("anything", peer, []))

    def test_no_peer_only_global(self):
        """No peer (None) — only global whitelist applies."""
        self.assertTrue(check_execution_whitelist("speak", None, ["speak"]))
        self.assertFalse(check_execution_whitelist("other", None, ["speak"]))


if __name__ == "__main__":
    unittest.main()
