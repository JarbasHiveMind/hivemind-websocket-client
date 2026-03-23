"""INTERCOM signature verification and execution whitelist utilities."""
from dataclasses import dataclass
from enum import Enum
from typing import Optional, List

import pybase64
from ovos_utils.log import LOG

from hivemind_plugin_manager.database import AbstractTrustStore, TrustedPeer
from poorman_handshake.asymmetric.utils import verify_RSA


class IntercomPolicy(str, Enum):
    """Policy for handling INTERCOM messages from untrusted senders."""
    SILENT_DROP = "silent_drop"
    DELIVER_UNTRUSTED = "deliver_untrusted"
    LOG_ONLY = "log_only"


@dataclass
class IntercomVerificationResult:
    """Result of INTERCOM signature verification and trust lookup.

    Attributes:
        signature_valid: Whether the RSA signature is cryptographically valid.
        trusted: Whether the sender's public key is in the trust store.
        sender_pubkey: The sender's PEM public key (if provided).
        peer: The matching TrustedPeer entry (if trusted).
    """
    signature_valid: bool
    trusted: bool
    sender_pubkey: Optional[str] = None
    peer: Optional[TrustedPeer] = None


def verify_intercom(pload: dict,
                    trust_store: Optional[AbstractTrustStore]
                    ) -> IntercomVerificationResult:
    """Verify INTERCOM payload signature and check trust store.

    Extracts ``sender_pubkey`` from the payload, verifies the RSA-PSS
    signature over the ciphertext, then looks up the key in the trust
    store.

    Args:
        pload: INTERCOM payload dict with ``ciphertext``, ``signature``,
               and optionally ``sender_pubkey``.
        trust_store: Trust store instance (may be None).

    Returns:
        IntercomVerificationResult with verification details.
    """
    sender_pubkey = pload.get("sender_pubkey")
    if not sender_pubkey:
        return IntercomVerificationResult(signature_valid=False, trusted=False)

    try:
        ciphertext = pybase64.b64decode(pload["ciphertext"])
        signature = pybase64.b64decode(pload["signature"])
    except Exception:
        LOG.warning("INTERCOM: failed to decode ciphertext/signature for verification")
        return IntercomVerificationResult(
            signature_valid=False, trusted=False, sender_pubkey=sender_pubkey)

    sig_valid = verify_RSA(sender_pubkey, ciphertext, signature)

    trusted = False
    peer = None
    if sig_valid and trust_store:
        peer = trust_store.get_peer_by_pubkey(sender_pubkey)
        trusted = peer is not None

    return IntercomVerificationResult(
        signature_valid=sig_valid, trusted=trusted,
        sender_pubkey=sender_pubkey, peer=peer)


def check_execution_whitelist(bus_msg_type: str,
                              peer: Optional[TrustedPeer],
                              global_allowed: List[str]) -> bool:
    """Check if a BUS message type passes both global and per-peer whitelists.

    An empty whitelist means "allow all".

    Args:
        bus_msg_type: The BUS message type string to check.
        peer: The TrustedPeer (may be None for untrusted senders).
        global_allowed: Global whitelist from config (empty = allow all).

    Returns:
        True if the message type is allowed.
    """
    if global_allowed and bus_msg_type not in global_allowed:
        return False
    if peer and peer.allowed_types and bus_msg_type not in peer.allowed_types:
        return False
    return True
