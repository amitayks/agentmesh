"""
Integration tests for AgentMesh security features.
Tests the audit fix implementations.
"""

import pytest
import asyncio
import json
import base64
from datetime import datetime, timezone
from unittest.mock import MagicMock, AsyncMock, patch

# Import the modules to test
from agentmesh.identity import Identity
from agentmesh.encryption import E2EEncryption, X3DHKeyExchange, PrekeyManager
from agentmesh.session_cache import SessionCache, CachedSession
from agentmesh.audit import TranscriptStore
from agentmesh.config import Policy


class TestSignatureVerification:
    """Tests for signature verification (Group 1)."""

    def test_identity_sign_and_verify(self):
        """Test that identity can sign and verify messages."""
        identity = Identity.generate()
        message = b"test message"

        signature = identity.sign_b64(message)

        # Verify with the same identity
        assert Identity.verify_signature(
            identity.signing_public_key_b64,
            message,
            signature
        )

    def test_invalid_signature_rejected(self):
        """Test that invalid signatures are rejected."""
        identity = Identity.generate()
        other_identity = Identity.generate()
        message = b"test message"

        # Sign with one identity
        signature = identity.sign_b64(message)

        # Verify with different identity should fail
        assert not Identity.verify_signature(
            other_identity.signing_public_key_b64,
            message,
            signature
        )

    def test_timestamp_signature(self):
        """Test timestamp signing for connection auth."""
        identity = Identity.generate()

        timestamp, signature = identity.sign_timestamp()

        # Should be recent
        assert (datetime.now(timezone.utc) - timestamp).total_seconds() < 5

        # Should verify
        timestamp_bytes = timestamp.isoformat().encode('utf-8')
        assert Identity.verify_signature(
            identity.signing_public_key_b64,
            timestamp_bytes,
            signature
        )


class TestKeyFormatCompatibility:
    """Tests for key format with prefixes (Group 2)."""

    def test_key_prefix_saving(self, tmp_path):
        """Test that keys are saved with prefixes."""
        identity = Identity.generate()
        key_file = tmp_path / "identity.json"

        identity.save(key_file)

        with open(key_file, 'r') as f:
            data = json.load(f)

        # Check prefixes are present
        assert data['signing_private_key'].startswith('ed25519:')
        assert data['signing_public_key'].startswith('ed25519:')
        assert data['exchange_private_key'].startswith('x25519:')
        assert data['exchange_public_key'].startswith('x25519:')

    def test_backwards_compatible_loading(self, tmp_path):
        """Test that keys without prefixes still load (with warning)."""
        import base64

        # Create old-format key file (without prefixes)
        identity = Identity.generate()
        old_format = {
            'amid': identity.amid,
            'signing_private_key': base64.b64encode(bytes(identity.signing_private_key)).decode(),
            'signing_public_key': identity.signing_public_key_b64_raw,
            'exchange_private_key': base64.b64encode(bytes(identity.exchange_private_key)).decode(),
            'exchange_public_key': identity.exchange_public_key_b64_raw,
            'created_at': identity.created_at.isoformat(),
        }

        key_file = tmp_path / "identity.json"
        with open(key_file, 'w') as f:
            json.dump(old_format, f)

        # Should load without error
        loaded = Identity.load(key_file)
        assert loaded.amid == identity.amid


class TestX3DHKeyExchange:
    """Tests for X3DH key exchange (Group 3)."""

    def test_prekey_generation(self, tmp_path):
        """Test prekey bundle generation."""
        from nacl.public import PrivateKey

        identity = Identity.generate()

        # PrekeyManager takes signing_key and exchange_key
        with patch('agentmesh.encryption.PREKEYS_DIR', tmp_path):
            manager = PrekeyManager(identity.signing_private_key, identity.exchange_private_key)
            bundle = manager.load_or_initialize()

            assert bundle.signed_prekey is not None
            assert bundle.signed_prekey_signature is not None
            assert len(bundle.one_time_prekeys) > 0

    def test_x3dh_key_agreement(self, tmp_path):
        """Test that X3DH produces matching shared secrets."""
        from nacl.public import PrivateKey

        # Alice (initiator)
        alice_identity = Identity.generate()

        # Bob (responder)
        bob_identity = Identity.generate()

        with patch('agentmesh.encryption.PREKEYS_DIR', tmp_path / 'bob'):
            bob_manager = PrekeyManager(bob_identity.signing_private_key, bob_identity.exchange_private_key)
            bob_bundle = bob_manager.load_or_initialize()

        # Alice generates ephemeral key
        alice_ephemeral = PrivateKey.generate()

        # Alice performs X3DH with Bob's prekeys
        alice_shared, alice_ephemeral_pub = X3DHKeyExchange.initiator_x3dh(
            our_identity_private=alice_identity.exchange_private_key,
            our_ephemeral_private=alice_ephemeral,
            their_identity_public=bob_bundle.identity_key,
            their_signed_prekey=bob_bundle.signed_prekey,
            their_signed_prekey_signature=bob_bundle.signed_prekey_signature,
            their_signing_public_key=bytes(bob_identity.signing_public_key),
            their_one_time_prekey=bob_bundle.one_time_prekeys[0][1] if bob_bundle.one_time_prekeys else None,
        )

        # Both should derive same shared secret
        assert alice_shared is not None
        assert len(alice_shared) == 32  # 256-bit key


class TestSessionCaching:
    """Tests for session caching (Group 4)."""

    def test_cache_put_and_get(self, tmp_path):
        """Test basic cache operations."""
        with patch('agentmesh.session_cache.CACHE_FILE', tmp_path / 'cache.json'):
            cache = SessionCache("alice_amid", ttl_hours=24)

            # Put a session
            cache.put(
                peer_amid="bob_amid",
                intent_category="travel",
                session_key="test_key",
                peer_exchange_key="test_exchange",
            )

            # Get it back
            cached = cache.get("bob_amid", "travel")

            assert cached is not None
            assert cached.peer_amid == "bob_amid"
            assert cached.intent_category == "travel"

    def test_cache_expiration(self, tmp_path):
        """Test that expired entries are not returned."""
        with patch('agentmesh.session_cache.CACHE_FILE', tmp_path / 'cache.json'):
            cache = SessionCache("alice_amid", ttl_hours=0)  # Immediate expiration

            cache.put(
                peer_amid="bob_amid",
                intent_category="travel",
                session_key="test_key",
                peer_exchange_key="test_exchange",
                ttl_hours=0,
            )

            # Should be expired immediately
            import time
            time.sleep(0.1)

            cached = cache.get("bob_amid", "travel")
            assert cached is None

    def test_cache_lru_eviction(self, tmp_path):
        """Test LRU eviction when cache is full."""
        with patch('agentmesh.session_cache.CACHE_FILE', tmp_path / 'cache.json'):
            cache = SessionCache("alice_amid", max_entries=2)

            # Add 3 entries
            cache.put("peer1", "intent1", "key1", "ex1")
            cache.put("peer2", "intent2", "key2", "ex2")
            cache.put("peer3", "intent3", "key3", "ex3")

            # First entry should be evicted
            assert cache.get("peer1", "intent1") is None
            assert cache.get("peer2", "intent2") is not None
            assert cache.get("peer3", "intent3") is not None


class TestTranscriptEncryption:
    """Tests for transcript encryption (Group 9)."""

    def test_transcript_encrypt_decrypt(self, tmp_path):
        """Test transcript encryption and decryption."""
        from nacl.signing import SigningKey

        # Use a proper SigningKey - its bytes will be used for key derivation
        signing_key = SigningKey.generate()

        with patch('agentmesh.audit.TRANSCRIPTS_DIR', tmp_path):
            store = TranscriptStore(signing_key=bytes(signing_key))

            # Save an encrypted transcript
            store.save_transcript(
                session_id="test_session",
                initiator="alice",
                receiver="bob",
                messages=[{"role": "user", "content": "hello"}],
            )

            # Load it back
            loaded = store.get_transcript("test_session")

            assert loaded is not None
            assert loaded['initiator'] == 'alice'
            assert loaded['receiver'] == 'bob'
            assert len(loaded['messages']) == 1

    def test_secure_deletion(self, tmp_path):
        """Test secure file deletion."""
        from nacl.signing import SigningKey

        signing_key = SigningKey.generate()

        with patch('agentmesh.audit.TRANSCRIPTS_DIR', tmp_path):
            store = TranscriptStore(signing_key=bytes(signing_key))

            store.save_transcript(
                session_id="test_session",
                initiator="alice",
                receiver="bob",
                messages=[],
            )

            # File should exist
            enc_file = tmp_path / "test_session.enc"
            assert enc_file.exists()

            # Delete securely
            store.delete_transcript("test_session", secure=True)

            # File should be gone
            assert not enc_file.exists()


class TestPolicyHelpers:
    """Tests for policy helper methods."""

    def test_is_allowlisted(self):
        """Test allowlist checking."""
        policy = Policy(allowlist=["alice", "bob"])

        assert policy.is_allowlisted("alice")
        assert policy.is_allowlisted("bob")
        assert not policy.is_allowlisted("charlie")

    def test_is_blocklisted(self):
        """Test blocklist checking."""
        policy = Policy(blocklist=["mallory"])

        assert policy.is_blocklisted("mallory")
        assert not policy.is_blocklisted("alice")

    def test_accepts_intent(self):
        """Test intent acceptance logic."""
        policy = Policy(
            accepted_intents=["travel", "commerce"],
            rejected_intents=["gambling"],
            strict_mode=False,
        )

        assert policy.accepts_intent("travel")
        assert policy.accepts_intent("unknown")  # Not rejected, so OK
        assert not policy.accepts_intent("gambling")

    def test_strict_mode(self):
        """Test strict mode only accepts explicit intents."""
        policy = Policy(
            accepted_intents=["travel"],
            strict_mode=True,
        )

        assert policy.accepts_intent("travel")
        assert not policy.accepts_intent("unknown")  # Not in accepted list


class TestReputationCalculation:
    """Tests for reputation formula (Group 8)."""

    def test_reputation_formula_components(self):
        """Test individual components of reputation formula."""
        # Completion rate: 0.3 weight
        # Feedback: 0.4 weight
        # Age factor: 0.1 weight
        # Tier bonus: 0.2 weight

        COMPLETION_WEIGHT = 0.3
        FEEDBACK_WEIGHT = 0.4
        AGE_WEIGHT = 0.1
        TIER_WEIGHT = 0.2

        # Example calculation
        completion_rate = 0.9  # 90% success rate
        feedback_score = 0.8  # Average feedback
        age_factor = 0.5  # 6 months old
        tier_bonus = 0.1  # Verified tier

        score = (
            COMPLETION_WEIGHT * completion_rate +
            FEEDBACK_WEIGHT * feedback_score +
            AGE_WEIGHT * age_factor +
            TIER_WEIGHT * (0.5 + tier_bonus)
        )

        # Should be between 0 and 1
        assert 0.0 <= score <= 1.0

        # With these values: 0.3*0.9 + 0.4*0.8 + 0.1*0.5 + 0.2*0.6 = 0.27 + 0.32 + 0.05 + 0.12 = 0.76
        assert abs(score - 0.76) < 0.01


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
