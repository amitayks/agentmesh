"""
End-to-end encryption using the Signal Protocol (X3DH + Double Ratchet).
Implements full X3DH key exchange with signed prekeys and one-time prekeys.
"""

import json
import base64
import logging
import hmac
from hashlib import sha256
from typing import Optional, Dict, Tuple, List
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import SigningKey, VerifyKey
from nacl.utils import random
from nacl.bindings import crypto_scalarmult

logger = logging.getLogger(__name__)

# Check if python-olm is available for full Double Ratchet
try:
    from olm import Account, Session as OlmSession
    DOUBLE_RATCHET_AVAILABLE = True
    logger.info("python-olm available - full Double Ratchet enabled")
except ImportError:
    DOUBLE_RATCHET_AVAILABLE = False
    logger.warning("python-olm not installed - using X3DH-only mode with simplified ratcheting")

# Key storage paths
AGENTMESH_DIR = Path.home() / ".agentmesh"
SESSION_KEYS_DIR = AGENTMESH_DIR / "sessions"
PREKEYS_DIR = AGENTMESH_DIR / "prekeys"
PREKEY_COUNTER_FILE = AGENTMESH_DIR / "prekey_counter"

# Prekey configuration
ONE_TIME_PREKEY_COUNT = 100
PREKEY_LOW_THRESHOLD = 20
SIGNED_PREKEY_ROTATION_DAYS = 7
SIGNED_PREKEY_GRACE_PERIOD_HOURS = 24
PREKEY_CHECK_INTERVAL_HOURS = 6
PREKEY_UPLOAD_MAX_RETRIES = 5
PREKEY_UPLOAD_BASE_DELAY = 1.0  # seconds

# Session configuration
SESSION_INACTIVITY_CLEANUP_DAYS = 7
SESSION_CLEANUP_INTERVAL_HOURS = 6
SESSION_FILE_VERSION = 1


def ensure_directories() -> None:
    """Create required directories with proper permissions on startup."""
    for dir_path in [AGENTMESH_DIR, SESSION_KEYS_DIR, PREKEYS_DIR]:
        dir_path.mkdir(parents=True, exist_ok=True)
        # Set directory permissions to 0700 (owner only)
        dir_path.chmod(0o700)


@dataclass
class PrekeyBundle:
    """
    X3DH Prekey Bundle - published to registry for offline key exchange.

    Contains:
    - Identity key (long-term signing key's corresponding X25519 key)
    - Signed prekey (medium-term, rotated every ~7 days)
    - Signed prekey signature (proving ownership)
    - One-time prekeys (consumed on each new session)
    """
    identity_key: bytes  # X25519 public key derived from signing key
    signed_prekey: bytes  # X25519 public key
    signed_prekey_signature: bytes  # Ed25519 signature over signed_prekey
    signed_prekey_id: int
    one_time_prekeys: List[Tuple[int, bytes]]  # (id, public_key) pairs
    uploaded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        """Serialize for upload to registry."""
        return {
            'identity_key': base64.b64encode(self.identity_key).decode(),
            'signed_prekey': base64.b64encode(self.signed_prekey).decode(),
            'signed_prekey_signature': base64.b64encode(self.signed_prekey_signature).decode(),
            'signed_prekey_id': self.signed_prekey_id,
            'one_time_prekeys': [
                {'id': pk_id, 'key': base64.b64encode(pk).decode()}
                for pk_id, pk in self.one_time_prekeys
            ],
            'uploaded_at': self.uploaded_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PrekeyBundle":
        """Deserialize from registry response."""
        return cls(
            identity_key=base64.b64decode(data['identity_key']),
            signed_prekey=base64.b64decode(data['signed_prekey']),
            signed_prekey_signature=base64.b64decode(data['signed_prekey_signature']),
            signed_prekey_id=data['signed_prekey_id'],
            one_time_prekeys=[
                (pk['id'], base64.b64decode(pk['key']))
                for pk in data.get('one_time_prekeys', [])
            ],
            uploaded_at=datetime.fromisoformat(data['uploaded_at']) if 'uploaded_at' in data else datetime.now(timezone.utc),
        )


@dataclass
class PrekeyState:
    """Local storage for prekey private keys."""
    signed_prekey_id: int
    signed_prekey_private: bytes
    signed_prekey_created: datetime
    one_time_prekey_privates: Dict[int, bytes]  # id -> private key
    next_prekey_id: int = 1
    consumed_prekey_ids: List[int] = field(default_factory=list)  # Track consumed prekeys
    old_signed_prekey_private: Optional[bytes] = None  # Grace period for old signed prekey
    old_signed_prekey_id: Optional[int] = None
    old_signed_prekey_expires: Optional[datetime] = None

    def to_dict(self) -> dict:
        result = {
            'signed_prekey_id': self.signed_prekey_id,
            'signed_prekey_private': base64.b64encode(self.signed_prekey_private).decode(),
            'signed_prekey_created': self.signed_prekey_created.isoformat(),
            'one_time_prekey_privates': {
                str(k): base64.b64encode(v).decode()
                for k, v in self.one_time_prekey_privates.items()
            },
            'next_prekey_id': self.next_prekey_id,
            'consumed_prekey_ids': self.consumed_prekey_ids,
        }
        if self.old_signed_prekey_private:
            result['old_signed_prekey_private'] = base64.b64encode(self.old_signed_prekey_private).decode()
            result['old_signed_prekey_id'] = self.old_signed_prekey_id
            result['old_signed_prekey_expires'] = self.old_signed_prekey_expires.isoformat() if self.old_signed_prekey_expires else None
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "PrekeyState":
        old_expires = None
        if data.get('old_signed_prekey_expires'):
            old_expires = datetime.fromisoformat(data['old_signed_prekey_expires'])
        return cls(
            signed_prekey_id=data['signed_prekey_id'],
            signed_prekey_private=base64.b64decode(data['signed_prekey_private']),
            signed_prekey_created=datetime.fromisoformat(data['signed_prekey_created']),
            one_time_prekey_privates={
                int(k): base64.b64decode(v)
                for k, v in data.get('one_time_prekey_privates', {}).items()
            },
            next_prekey_id=data.get('next_prekey_id', 1),
            consumed_prekey_ids=data.get('consumed_prekey_ids', []),
            old_signed_prekey_private=base64.b64decode(data['old_signed_prekey_private']) if data.get('old_signed_prekey_private') else None,
            old_signed_prekey_id=data.get('old_signed_prekey_id'),
            old_signed_prekey_expires=old_expires,
        )

    def save(self, path: Path) -> None:
        """Save prekey state to disk."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        path.chmod(0o600)

    @classmethod
    def load(cls, path: Path) -> Optional["PrekeyState"]:
        """Load prekey state from disk."""
        if not path.exists():
            return None
        try:
            with open(path, 'r') as f:
                return cls.from_dict(json.load(f))
        except Exception as e:
            logger.error(f"Failed to load prekey state: {e}")
            return None


@dataclass
class SessionKeys:
    """Encryption keys for a session."""
    session_id: str
    peer_amid: str
    shared_secret: bytes
    send_chain_key: bytes
    recv_chain_key: bytes
    send_message_number: int = 0
    recv_message_number: int = 0
    created_at: datetime = None
    last_used: datetime = None
    ratchet_state: Optional[Dict] = None  # For full Double Ratchet persistence

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)
        if self.last_used is None:
            self.last_used = self.created_at

    def touch(self) -> None:
        """Update last_used timestamp."""
        self.last_used = datetime.now(timezone.utc)

    def is_stale(self, days: int = SESSION_INACTIVITY_CLEANUP_DAYS) -> bool:
        """Check if session is stale (no activity for specified days)."""
        if self.last_used is None:
            return True
        age = datetime.now(timezone.utc) - self.last_used
        return age.days >= days


class PrekeyManager:
    """
    Manages X3DH prekeys - generation, storage, and rotation.

    Features:
    - Automatic prekey replenishment when count < PREKEY_LOW_THRESHOLD
    - Signed prekey rotation every SIGNED_PREKEY_ROTATION_DAYS
    - 24-hour grace period for old signed prekeys
    - Consumed prekey tracking
    - Upload with exponential backoff retry
    """

    def __init__(self, signing_key: SigningKey, exchange_key: PrivateKey, registry_url: Optional[str] = None):
        self.signing_key = signing_key
        self.exchange_key = exchange_key
        self.registry_url = registry_url
        self.state: Optional[PrekeyState] = None
        self._state_path = PREKEYS_DIR / "prekey_state.json"
        self._counter_path = PREKEY_COUNTER_FILE

    def load_or_initialize(self) -> PrekeyBundle:
        """Load existing prekeys or generate new ones."""
        ensure_directories()
        self.state = PrekeyState.load(self._state_path)

        if self.state is None:
            return self._generate_initial_prekeys()

        # Clean up expired old signed prekey
        self._cleanup_old_signed_prekey()

        # Check if signed prekey needs rotation
        age = datetime.now(timezone.utc) - self.state.signed_prekey_created
        if age > timedelta(days=SIGNED_PREKEY_ROTATION_DAYS):
            logger.info("Rotating signed prekey (older than 7 days)")
            return self._rotate_signed_prekey()

        # Check if prekeys need replenishment
        if self.needs_replenishment():
            count_to_generate = ONE_TIME_PREKEY_COUNT - self.remaining_prekey_count()
            self.generate_additional_prekeys(count_to_generate)
            logger.info(f"Replenished {count_to_generate} one-time prekeys on startup")

        return self._build_bundle()

    def check_and_replenish(self) -> Optional[List[Tuple[int, bytes]]]:
        """
        Check prekey count and replenish if needed.

        Called periodically (every 6 hours) and on low_prekeys notification.
        Returns the new prekeys if replenishment occurred, None otherwise.
        """
        if self.state is None:
            return None

        # Clean up expired old signed prekey
        self._cleanup_old_signed_prekey()

        # Check for signed prekey rotation
        age = datetime.now(timezone.utc) - self.state.signed_prekey_created
        if age > timedelta(days=SIGNED_PREKEY_ROTATION_DAYS):
            self._rotate_signed_prekey()
            logger.info("Rotated signed prekey during periodic check")

        # Check if replenishment needed
        if not self.needs_replenishment():
            return None

        count_to_generate = ONE_TIME_PREKEY_COUNT - self.remaining_prekey_count()
        new_prekeys = self.generate_additional_prekeys(count_to_generate)
        logger.info(f"Generated {count_to_generate} prekeys during periodic check")
        return new_prekeys

    def _cleanup_old_signed_prekey(self) -> None:
        """Remove old signed prekey after grace period expires."""
        if not self.state:
            return

        if self.state.old_signed_prekey_expires:
            if datetime.now(timezone.utc) >= self.state.old_signed_prekey_expires:
                logger.info(f"Removing expired old signed prekey {self.state.old_signed_prekey_id}")
                self.state.old_signed_prekey_private = None
                self.state.old_signed_prekey_id = None
                self.state.old_signed_prekey_expires = None
                self.state.save(self._state_path)

    def _generate_initial_prekeys(self) -> PrekeyBundle:
        """Generate initial set of prekeys."""
        logger.info("Generating initial prekey bundle")

        # Generate signed prekey
        signed_prekey_private = PrivateKey.generate()
        signed_prekey_public = bytes(signed_prekey_private.public_key)

        # Sign the prekey
        signature = self.signing_key.sign(signed_prekey_public).signature

        # Generate one-time prekeys
        one_time_privates = {}
        one_time_publics = []
        for i in range(1, ONE_TIME_PREKEY_COUNT + 1):
            pk_private = PrivateKey.generate()
            one_time_privates[i] = bytes(pk_private)
            one_time_publics.append((i, bytes(pk_private.public_key)))

        # Save state
        self.state = PrekeyState(
            signed_prekey_id=1,
            signed_prekey_private=bytes(signed_prekey_private),
            signed_prekey_created=datetime.now(timezone.utc),
            one_time_prekey_privates=one_time_privates,
            next_prekey_id=ONE_TIME_PREKEY_COUNT + 1,
        )
        self.state.save(self._state_path)

        # Build bundle
        return PrekeyBundle(
            identity_key=bytes(self.exchange_key.public_key),
            signed_prekey=signed_prekey_public,
            signed_prekey_signature=signature,
            signed_prekey_id=1,
            one_time_prekeys=one_time_publics,
        )

    def _rotate_signed_prekey(self) -> PrekeyBundle:
        """
        Rotate the signed prekey while preserving one-time prekeys.

        The old signed prekey is kept for a 24-hour grace period to handle
        in-flight KNOCK messages that may still reference it.
        """
        # Save old prekey for grace period
        self.state.old_signed_prekey_private = self.state.signed_prekey_private
        self.state.old_signed_prekey_id = self.state.signed_prekey_id
        self.state.old_signed_prekey_expires = datetime.now(timezone.utc) + timedelta(hours=SIGNED_PREKEY_GRACE_PERIOD_HOURS)

        # Generate new signed prekey
        new_signed_private = PrivateKey.generate()
        new_signed_public = bytes(new_signed_private.public_key)
        signature = self.signing_key.sign(new_signed_public).signature

        new_id = self.state.signed_prekey_id + 1
        self.state.signed_prekey_id = new_id
        self.state.signed_prekey_private = bytes(new_signed_private)
        self.state.signed_prekey_created = datetime.now(timezone.utc)
        self.state.save(self._state_path)

        logger.info(f"Rotated signed prekey to ID {new_id}, old key valid until {self.state.old_signed_prekey_expires}")

        return self._build_bundle()

    def get_signed_prekey_private(self, prekey_id: int) -> Optional[bytes]:
        """
        Get private key for a signed prekey by ID.

        Returns the current signed prekey or old prekey during grace period.
        """
        if self.state is None:
            return None

        if prekey_id == self.state.signed_prekey_id:
            return self.state.signed_prekey_private

        # Check old prekey during grace period
        if self.state.old_signed_prekey_id == prekey_id:
            if self.state.old_signed_prekey_expires and datetime.now(timezone.utc) < self.state.old_signed_prekey_expires:
                return self.state.old_signed_prekey_private

        return None

    def _build_bundle(self) -> PrekeyBundle:
        """Build bundle from current state."""
        signed_prekey_public = bytes(PrivateKey(self.state.signed_prekey_private).public_key)
        signature = self.signing_key.sign(signed_prekey_public).signature

        one_time_publics = [
            (pk_id, bytes(PrivateKey(pk_private).public_key))
            for pk_id, pk_private in self.state.one_time_prekey_privates.items()
        ]

        return PrekeyBundle(
            identity_key=bytes(self.exchange_key.public_key),
            signed_prekey=signed_prekey_public,
            signed_prekey_signature=signature,
            signed_prekey_id=self.state.signed_prekey_id,
            one_time_prekeys=one_time_publics,
        )

    def generate_additional_prekeys(self, count: int) -> List[Tuple[int, bytes]]:
        """Generate additional one-time prekeys when running low."""
        if self.state is None:
            raise ValueError("Prekey state not initialized")

        new_prekeys = []
        for _ in range(count):
            pk_id = self.state.next_prekey_id
            pk_private = PrivateKey.generate()
            self.state.one_time_prekey_privates[pk_id] = bytes(pk_private)
            new_prekeys.append((pk_id, bytes(pk_private.public_key)))
            self.state.next_prekey_id += 1

        self.state.save(self._state_path)
        logger.info(f"Generated {count} additional one-time prekeys")
        return new_prekeys

    def get_prekey_private(self, prekey_id: int) -> Optional[bytes]:
        """Get private key for a one-time prekey (consumed after use)."""
        if self.state is None:
            return None
        return self.state.one_time_prekey_privates.get(prekey_id)

    def consume_prekey(self, prekey_id: int) -> None:
        """Mark a one-time prekey as consumed."""
        if self.state and prekey_id in self.state.one_time_prekey_privates:
            del self.state.one_time_prekey_privates[prekey_id]
            # Track consumed prekey IDs (keep last 1000)
            self.state.consumed_prekey_ids.append(prekey_id)
            if len(self.state.consumed_prekey_ids) > 1000:
                self.state.consumed_prekey_ids = self.state.consumed_prekey_ids[-1000:]
            self.state.save(self._state_path)
            logger.debug(f"Consumed one-time prekey {prekey_id}")

    def is_prekey_consumed(self, prekey_id: int) -> bool:
        """Check if a prekey has been consumed."""
        if self.state is None:
            return False
        return prekey_id in self.state.consumed_prekey_ids

    async def upload_prekeys_with_retry(
        self,
        prekeys: List[Tuple[int, bytes]],
        include_signed: bool = False,
    ) -> bool:
        """
        Upload prekeys to registry with exponential backoff retry.

        Args:
            prekeys: List of (id, public_key) tuples to upload
            include_signed: Whether to include the signed prekey

        Returns:
            True if upload successful, False otherwise
        """
        import asyncio
        import aiohttp

        if not self.registry_url:
            logger.warning("No registry URL configured for prekey upload")
            return False

        # Build upload payload
        payload = {
            'identity_key': base64.b64encode(bytes(self.exchange_key.public_key)).decode(),
            'one_time_prekeys': [
                {'id': pk_id, 'key': base64.b64encode(pk).decode()}
                for pk_id, pk in prekeys
            ],
        }

        if include_signed and self.state:
            signed_public = bytes(PrivateKey(self.state.signed_prekey_private).public_key)
            signature = self.signing_key.sign(signed_public).signature
            payload['signed_prekey'] = base64.b64encode(signed_public).decode()
            payload['signed_prekey_signature'] = base64.b64encode(signature).decode()
            payload['signed_prekey_id'] = self.state.signed_prekey_id

        # Retry with exponential backoff
        delay = PREKEY_UPLOAD_BASE_DELAY
        for attempt in range(PREKEY_UPLOAD_MAX_RETRIES):
            try:
                async with aiohttp.ClientSession() as session:
                    url = f"{self.registry_url}/prekeys"
                    async with session.post(url, json=payload) as response:
                        if response.status == 200:
                            logger.info(f"Uploaded {len(prekeys)} prekeys to registry")
                            return True
                        else:
                            text = await response.text()
                            logger.warning(f"Prekey upload failed (attempt {attempt + 1}): {response.status} - {text}")

            except Exception as e:
                logger.warning(f"Prekey upload error (attempt {attempt + 1}): {e}")

            if attempt < PREKEY_UPLOAD_MAX_RETRIES - 1:
                await asyncio.sleep(delay)
                delay *= 2  # Exponential backoff

        logger.error(f"Prekey upload failed after {PREKEY_UPLOAD_MAX_RETRIES} attempts")
        return False

    def handle_low_prekeys_notification(self) -> None:
        """
        Handle low_prekeys notification from registry.

        Triggers immediate replenishment check.
        """
        logger.info("Received low_prekeys notification from registry")
        new_prekeys = self.check_and_replenish()
        if new_prekeys:
            # Schedule async upload (caller should await this)
            logger.info(f"Generated {len(new_prekeys)} prekeys in response to notification")

    def remaining_prekey_count(self) -> int:
        """Get count of remaining one-time prekeys."""
        if self.state is None:
            return 0
        return len(self.state.one_time_prekey_privates)

    def needs_replenishment(self) -> bool:
        """Check if prekeys need replenishment."""
        return self.remaining_prekey_count() < PREKEY_LOW_THRESHOLD


class X3DHKeyExchange:
    """
    Extended Triple Diffie-Hellman key exchange.
    Implements the full X3DH protocol with prekeys for offline messaging.

    The X3DH shared secret is computed as:
    DH1 = DH(IKa, SPKb)  - Our identity key with their signed prekey
    DH2 = DH(EKa, IKb)   - Our ephemeral key with their identity key
    DH3 = DH(EKa, SPKb)  - Our ephemeral key with their signed prekey
    DH4 = DH(EKa, OPKb)  - Our ephemeral key with their one-time prekey (if available)

    SK = HKDF(DH1 || DH2 || DH3 || DH4)
    """

    @staticmethod
    def _dh(private_key: bytes, public_key: bytes) -> bytes:
        """Perform X25519 Diffie-Hellman."""
        return crypto_scalarmult(private_key, public_key)

    @staticmethod
    def compute_shared_secret(
        our_private_key: PrivateKey,
        their_public_key: bytes,
    ) -> bytes:
        """
        Simple X25519 key exchange (fallback when no prekeys available).
        """
        their_key = PublicKey(their_public_key)
        box = Box(our_private_key, their_key)
        return box.shared_key()

    @staticmethod
    def initiator_x3dh(
        our_identity_private: PrivateKey,
        our_ephemeral_private: PrivateKey,
        their_identity_public: bytes,
        their_signed_prekey: bytes,
        their_signed_prekey_signature: bytes,
        their_signing_public_key: bytes,
        their_one_time_prekey: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Perform X3DH as the initiator (Alice).

        Returns:
            Tuple of (shared_secret, ephemeral_public_key)
        """
        # Verify signed prekey signature
        try:
            verify_key = VerifyKey(their_signing_public_key)
            verify_key.verify(their_signed_prekey, their_signed_prekey_signature)
        except Exception as e:
            raise ValueError(f"Invalid signed prekey signature: {e}")

        # Compute DH values
        dh1 = X3DHKeyExchange._dh(bytes(our_identity_private), their_signed_prekey)
        dh2 = X3DHKeyExchange._dh(bytes(our_ephemeral_private), their_identity_public)
        dh3 = X3DHKeyExchange._dh(bytes(our_ephemeral_private), their_signed_prekey)

        # Combine DH outputs
        if their_one_time_prekey:
            dh4 = X3DHKeyExchange._dh(bytes(our_ephemeral_private), their_one_time_prekey)
            dh_concat = dh1 + dh2 + dh3 + dh4
        else:
            dh_concat = dh1 + dh2 + dh3

        # Derive shared secret using HKDF
        shared_secret = X3DHKeyExchange._hkdf(dh_concat, b"X3DH", 32)

        return shared_secret, bytes(our_ephemeral_private.public_key)

    @staticmethod
    def responder_x3dh(
        our_identity_private: PrivateKey,
        our_signed_prekey_private: PrivateKey,
        our_one_time_prekey_private: Optional[PrivateKey],
        their_identity_public: bytes,
        their_ephemeral_public: bytes,
    ) -> bytes:
        """
        Perform X3DH as the responder (Bob).

        Returns:
            shared_secret
        """
        # Compute DH values (reversed from initiator)
        dh1 = X3DHKeyExchange._dh(bytes(our_signed_prekey_private), their_identity_public)
        dh2 = X3DHKeyExchange._dh(bytes(our_identity_private), their_ephemeral_public)
        dh3 = X3DHKeyExchange._dh(bytes(our_signed_prekey_private), their_ephemeral_public)

        # Combine DH outputs
        if our_one_time_prekey_private:
            dh4 = X3DHKeyExchange._dh(bytes(our_one_time_prekey_private), their_ephemeral_public)
            dh_concat = dh1 + dh2 + dh3 + dh4
        else:
            dh_concat = dh1 + dh2 + dh3

        # Derive shared secret using HKDF
        shared_secret = X3DHKeyExchange._hkdf(dh_concat, b"X3DH", 32)

        return shared_secret

    @staticmethod
    def _hkdf(input_key_material: bytes, info: bytes, length: int) -> bytes:
        """Simple HKDF implementation using HMAC-SHA256."""
        # Extract
        salt = b'\x00' * 32
        prk = hmac.new(salt, input_key_material, sha256).digest()

        # Expand
        t = b''
        okm = b''
        for i in range((length + 31) // 32):
            t = hmac.new(prk, t + info + bytes([i + 1]), sha256).digest()
            okm += t

        return okm[:length]

    @staticmethod
    def generate_ephemeral_keypair() -> Tuple[PrivateKey, PublicKey]:
        """Generate an ephemeral keypair for this session."""
        private_key = PrivateKey.generate()
        public_key = private_key.public_key
        return private_key, public_key


# Maximum number of skipped message keys to store
MAX_SKIP = 1000


@dataclass
class DoubleRatchetState:
    """
    State for the Double Ratchet algorithm.

    Maintains:
    - DH ratchet keypair
    - Root key, send chain key, receive chain key
    - Message numbers
    - Skipped message keys for out-of-order handling
    """
    # DH ratchet keys
    dh_private: bytes
    dh_public: bytes
    peer_dh_public: Optional[bytes] = None

    # Root key for DH ratchet steps
    root_key: bytes = None

    # Chain keys
    send_chain_key: bytes = None
    recv_chain_key: bytes = None

    # Message numbers
    send_message_number: int = 0
    recv_message_number: int = 0

    # Previous chain message number (for skipped keys)
    prev_send_chain_length: int = 0

    # Skipped message keys: {(dh_public, message_number): message_key}
    skipped_keys: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize state for persistence."""
        return {
            'dh_private': base64.b64encode(self.dh_private).decode(),
            'dh_public': base64.b64encode(self.dh_public).decode(),
            'peer_dh_public': base64.b64encode(self.peer_dh_public).decode() if self.peer_dh_public else None,
            'root_key': base64.b64encode(self.root_key).decode() if self.root_key else None,
            'send_chain_key': base64.b64encode(self.send_chain_key).decode() if self.send_chain_key else None,
            'recv_chain_key': base64.b64encode(self.recv_chain_key).decode() if self.recv_chain_key else None,
            'send_message_number': self.send_message_number,
            'recv_message_number': self.recv_message_number,
            'prev_send_chain_length': self.prev_send_chain_length,
            'skipped_keys': {
                f"{base64.b64encode(k[0]).decode()}:{k[1]}": base64.b64encode(v).decode()
                for k, v in self.skipped_keys.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "DoubleRatchetState":
        """Deserialize state."""
        skipped = {}
        for k, v in data.get('skipped_keys', {}).items():
            dh_pub, msg_num = k.rsplit(':', 1)
            skipped[(base64.b64decode(dh_pub), int(msg_num))] = base64.b64decode(v)

        return cls(
            dh_private=base64.b64decode(data['dh_private']),
            dh_public=base64.b64decode(data['dh_public']),
            peer_dh_public=base64.b64decode(data['peer_dh_public']) if data.get('peer_dh_public') else None,
            root_key=base64.b64decode(data['root_key']) if data.get('root_key') else None,
            send_chain_key=base64.b64decode(data['send_chain_key']) if data.get('send_chain_key') else None,
            recv_chain_key=base64.b64decode(data['recv_chain_key']) if data.get('recv_chain_key') else None,
            send_message_number=data.get('send_message_number', 0),
            recv_message_number=data.get('recv_message_number', 0),
            prev_send_chain_length=data.get('prev_send_chain_length', 0),
            skipped_keys=skipped,
        )


class DoubleRatchetSession:
    """
    Full Signal Protocol Double Ratchet implementation.

    Provides:
    - Perfect forward secrecy (past message keys deleted)
    - Break-in recovery (new DH keys regenerated)
    - Out-of-order message handling (skipped keys stored)
    """

    def __init__(self, shared_secret: bytes, is_initiator: bool):
        """
        Initialize from X3DH shared secret.

        Args:
            shared_secret: The shared secret from X3DH key exchange
            is_initiator: True if we initiated the session
        """
        # Generate initial DH ratchet keypair
        dh_private = PrivateKey.generate()

        self.state = DoubleRatchetState(
            dh_private=bytes(dh_private),
            dh_public=bytes(dh_private.public_key),
            root_key=shared_secret,
        )

        self.is_initiator = is_initiator

    def initialize_as_responder(self, peer_dh_public: bytes) -> None:
        """
        Initialize receiving chain when we're the responder.
        Called when we receive the first message with the peer's ratchet public key.
        """
        self.state.peer_dh_public = peer_dh_public
        self._dh_ratchet_step()

    def get_ratchet_public_key(self) -> bytes:
        """Get our current ratchet public key to send to peer."""
        return self.state.dh_public

    def _kdf_rk(self, root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """
        Derive new root key and chain key from root key and DH output.
        Uses HKDF with SHA-256.
        """
        info = b"agentmesh_rk"
        # HKDF-Extract
        prk = hmac.new(root_key, dh_output, sha256).digest()
        # HKDF-Expand for 64 bytes (32 for root key, 32 for chain key)
        t1 = hmac.new(prk, info + b'\x01', sha256).digest()
        t2 = hmac.new(prk, t1 + info + b'\x02', sha256).digest()
        return t1, t2  # new_root_key, new_chain_key

    def _kdf_ck(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Derive message key and new chain key from chain key.
        """
        msg_key = hmac.new(chain_key, b'\x01', sha256).digest()
        new_chain_key = hmac.new(chain_key, b'\x02', sha256).digest()
        return msg_key, new_chain_key

    def _dh_ratchet_step(self) -> None:
        """
        Perform a DH ratchet step when receiving a new ratchet public key.
        """
        if not self.state.peer_dh_public or not self.state.root_key:
            return

        # DH with our current private key and their new public key
        dh_output = crypto_scalarmult(self.state.dh_private, self.state.peer_dh_public)

        # Derive new receiving chain key
        new_root, recv_chain = self._kdf_rk(self.state.root_key, dh_output)
        self.state.recv_chain_key = recv_chain

        # Generate new DH keypair for sending
        new_dh_private = PrivateKey.generate()
        self.state.dh_private = bytes(new_dh_private)
        self.state.dh_public = bytes(new_dh_private.public_key)

        # DH with new private key and their public key
        dh_output2 = crypto_scalarmult(self.state.dh_private, self.state.peer_dh_public)

        # Derive new sending chain key
        final_root, send_chain = self._kdf_rk(new_root, dh_output2)
        self.state.root_key = final_root
        self.state.send_chain_key = send_chain

        # Reset message counters for new chains
        self.state.prev_send_chain_length = self.state.send_message_number
        self.state.send_message_number = 0
        self.state.recv_message_number = 0

    def _skip_message_keys(self, until: int) -> None:
        """
        Store skipped message keys for out-of-order handling.

        Raises:
            ValueError: If too many messages would be skipped
        """
        if until - self.state.recv_message_number > MAX_SKIP:
            raise ValueError(f"Too many skipped messages ({until - self.state.recv_message_number} > {MAX_SKIP})")

        while self.state.recv_message_number < until:
            msg_key, new_chain = self._kdf_ck(self.state.recv_chain_key)
            self.state.skipped_keys[
                (self.state.peer_dh_public, self.state.recv_message_number)
            ] = msg_key
            self.state.recv_chain_key = new_chain
            self.state.recv_message_number += 1

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, int, bytes]:
        """
        Encrypt a message.

        Returns:
            Tuple of (ciphertext, message_number, ratchet_public_key)
        """
        from nacl.secret import SecretBox

        # Initialize send chain if needed
        if self.state.send_chain_key is None:
            # First message - derive chain from root key
            dh_output = crypto_scalarmult(
                self.state.dh_private,
                self.state.peer_dh_public if self.state.peer_dh_public else self.state.root_key[:32]
            )
            _, self.state.send_chain_key = self._kdf_rk(self.state.root_key, dh_output)

        # Derive message key
        msg_key, new_chain = self._kdf_ck(self.state.send_chain_key)

        # Encrypt
        box = SecretBox(msg_key)
        ciphertext = box.encrypt(plaintext)

        # Update state
        msg_num = self.state.send_message_number
        self.state.send_chain_key = new_chain
        self.state.send_message_number += 1

        # Delete used message key (forward secrecy)
        del msg_key

        return ciphertext, msg_num, self.state.dh_public

    def decrypt(self, ciphertext: bytes, message_number: int, ratchet_public_key: bytes) -> bytes:
        """
        Decrypt a message.

        Args:
            ciphertext: The encrypted message
            message_number: The message sequence number
            ratchet_public_key: The sender's ratchet public key

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If message cannot be decrypted
        """
        from nacl.secret import SecretBox

        # Check if we have a skipped key for this message
        skipped_key = self.state.skipped_keys.pop((ratchet_public_key, message_number), None)
        if skipped_key:
            box = SecretBox(skipped_key)
            return box.decrypt(ciphertext)

        # Check if this is a new ratchet public key (DH ratchet step needed)
        if ratchet_public_key != self.state.peer_dh_public:
            # Skip any remaining messages from the old chain
            if self.state.recv_chain_key is not None:
                self._skip_message_keys(self.state.recv_message_number + MAX_SKIP)

            # Perform DH ratchet step
            self.state.peer_dh_public = ratchet_public_key
            self._dh_ratchet_step()

        # Skip to the message if needed
        if message_number > self.state.recv_message_number:
            self._skip_message_keys(message_number)

        # Derive message key
        msg_key, new_chain = self._kdf_ck(self.state.recv_chain_key)

        # Decrypt
        box = SecretBox(msg_key)
        plaintext = box.decrypt(ciphertext)

        # Update state
        self.state.recv_chain_key = new_chain
        self.state.recv_message_number = message_number + 1

        # Delete used message key (forward secrecy)
        del msg_key

        return plaintext

    def get_state(self) -> DoubleRatchetState:
        """Get the current ratchet state for persistence."""
        return self.state

    @classmethod
    def from_state(cls, state: DoubleRatchetState, is_initiator: bool) -> "DoubleRatchetSession":
        """Restore session from persisted state."""
        session = object.__new__(cls)
        session.state = state
        session.is_initiator = is_initiator
        return session


class DoubleRatchet:
    """
    Simplified Double Ratchet for backwards compatibility.
    Each message uses a new key derived from the chain ratchet.

    For full Signal Protocol Double Ratchet, use DoubleRatchetSession.
    """

    def __init__(self, session_keys: SessionKeys):
        self.keys = session_keys

    def derive_message_key(self, chain_key: bytes, message_num: int) -> bytes:
        """Derive a message key from the chain key."""
        # HKDF-like key derivation
        info = f"agentmesh_msg_{message_num}".encode()
        return hmac.new(chain_key, info, sha256).digest()

    def advance_chain(self, chain_key: bytes) -> bytes:
        """Advance the chain key."""
        return hmac.new(chain_key, b"agentmesh_chain", sha256).digest()

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, int]:
        """
        Encrypt a message using the current send chain.
        Returns (ciphertext, message_number).
        """
        from nacl.secret import SecretBox

        # Derive message key
        msg_key = self.derive_message_key(
            self.keys.send_chain_key,
            self.keys.send_message_number
        )

        # Encrypt
        box = SecretBox(msg_key)
        ciphertext = box.encrypt(plaintext)

        # Advance chain
        msg_num = self.keys.send_message_number
        self.keys.send_chain_key = self.advance_chain(self.keys.send_chain_key)
        self.keys.send_message_number += 1

        return ciphertext, msg_num

    def decrypt(self, ciphertext: bytes, message_number: int) -> bytes:
        """
        Decrypt a message.
        """
        from nacl.secret import SecretBox

        # Derive message key
        msg_key = self.derive_message_key(
            self.keys.recv_chain_key,
            message_number
        )

        # Decrypt
        box = SecretBox(msg_key)
        plaintext = box.decrypt(ciphertext)

        # Advance chain if this is the expected message
        if message_number >= self.keys.recv_message_number:
            # Advance chain for each message
            for _ in range(message_number - self.keys.recv_message_number + 1):
                self.keys.recv_chain_key = self.advance_chain(self.keys.recv_chain_key)
            self.keys.recv_message_number = message_number + 1

        return plaintext


class E2EEncryption:
    """
    High-level E2E encryption manager.
    Handles session key storage and message encryption/decryption.

    Features:
    - Session key persistence with encryption
    - Automatic cleanup of stale sessions
    - Session resumption without new KNOCK
    """

    def __init__(self, our_private_key: PrivateKey, encryption_key: Optional[bytes] = None):
        """
        Initialize E2E encryption manager.

        Args:
            our_private_key: Our X25519 private key for key exchange
            encryption_key: Optional 32-byte key for encrypting session files
                          (derived from signing key if not provided)
        """
        self.our_private_key = our_private_key
        self.sessions: Dict[str, SessionKeys] = {}
        self.ratchets: Dict[str, DoubleRatchet] = {}
        self._encryption_key = encryption_key or self._derive_encryption_key()

        # Ensure directories exist
        ensure_directories()

    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key for session files from our private key."""
        return hmac.new(
            bytes(self.our_private_key),
            b"agentmesh_session_encryption",
            sha256
        ).digest()

    def establish_session(
        self,
        session_id: str,
        peer_amid: str,
        peer_public_key: bytes,
    ) -> SessionKeys:
        """
        Establish a new encrypted session with a peer.
        """
        # Compute shared secret using X3DH
        shared_secret = X3DHKeyExchange.compute_shared_secret(
            self.our_private_key,
            peer_public_key,
        )

        # Derive initial chain keys
        from hashlib import sha256
        import hmac

        send_chain = hmac.new(shared_secret, b"agentmesh_send", sha256).digest()
        recv_chain = hmac.new(shared_secret, b"agentmesh_recv", sha256).digest()

        # Create session keys
        keys = SessionKeys(
            session_id=session_id,
            peer_amid=peer_amid,
            shared_secret=shared_secret,
            send_chain_key=send_chain,
            recv_chain_key=recv_chain,
        )

        self.sessions[session_id] = keys
        self.ratchets[session_id] = DoubleRatchet(keys)

        # Persist session keys
        self._save_session(keys)

        logger.info(f"Established E2E session {session_id} with {peer_amid}")
        return keys

    def encrypt_message(
        self,
        session_id: str,
        plaintext: dict,
    ) -> Optional[str]:
        """
        Encrypt a message for a session.
        Returns base64-encoded ciphertext.
        """
        if session_id not in self.ratchets:
            logger.error(f"No session found: {session_id}")
            return None

        ratchet = self.ratchets[session_id]

        # Serialize and encrypt
        plaintext_bytes = json.dumps(plaintext).encode('utf-8')
        ciphertext, msg_num = ratchet.encrypt(plaintext_bytes)

        # Update last_used timestamp
        if session_id in self.sessions:
            self.sessions[session_id].touch()

        # Package with message number
        package = {
            'n': msg_num,
            'c': base64.b64encode(ciphertext).decode('ascii'),
        }

        return base64.b64encode(json.dumps(package).encode()).decode('ascii')

    def decrypt_message(
        self,
        session_id: str,
        encrypted: str,
    ) -> Optional[dict]:
        """
        Decrypt a message from a session.
        """
        if session_id not in self.ratchets:
            logger.error(f"No session found: {session_id}")
            return None

        try:
            ratchet = self.ratchets[session_id]

            # Unpackage
            package = json.loads(base64.b64decode(encrypted))
            msg_num = package['n']
            ciphertext = base64.b64decode(package['c'])

            # Decrypt
            plaintext_bytes = ratchet.decrypt(ciphertext, msg_num)

            # Update last_used timestamp
            if session_id in self.sessions:
                self.sessions[session_id].touch()

            return json.loads(plaintext_bytes.decode('utf-8'))

        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    def _save_session(self, keys: SessionKeys) -> None:
        """
        Persist session keys to disk with encryption.

        File format:
        - 1 byte: version
        - 24 bytes: nonce
        - remaining: encrypted JSON data
        """
        from nacl.secret import SecretBox

        SESSION_KEYS_DIR.mkdir(parents=True, exist_ok=True)

        # Prepare session data
        data = {
            'session_id': keys.session_id,
            'peer_amid': keys.peer_amid,
            'shared_secret': base64.b64encode(keys.shared_secret).decode(),
            'send_chain_key': base64.b64encode(keys.send_chain_key).decode(),
            'recv_chain_key': base64.b64encode(keys.recv_chain_key).decode(),
            'send_message_number': keys.send_message_number,
            'recv_message_number': keys.recv_message_number,
            'created_at': keys.created_at.isoformat(),
            'last_used': keys.last_used.isoformat() if keys.last_used else keys.created_at.isoformat(),
        }

        # Add ratchet state if available
        if keys.ratchet_state:
            data['ratchet_state'] = keys.ratchet_state

        # Encrypt the session data
        box = SecretBox(self._encryption_key)
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext = box.encrypt(plaintext)

        # Write with version byte
        path = SESSION_KEYS_DIR / f"{keys.session_id}.session"
        with open(path, 'wb') as f:
            f.write(bytes([SESSION_FILE_VERSION]))
            f.write(ciphertext)

        path.chmod(0o600)

    def _save_session_unencrypted(self, keys: SessionKeys) -> None:
        """Save session as unencrypted JSON (for backwards compatibility)."""
        path = SESSION_KEYS_DIR / f"{keys.session_id}.json"
        data = {
            'session_id': keys.session_id,
            'peer_amid': keys.peer_amid,
            'shared_secret': base64.b64encode(keys.shared_secret).decode(),
            'send_chain_key': base64.b64encode(keys.send_chain_key).decode(),
            'recv_chain_key': base64.b64encode(keys.recv_chain_key).decode(),
            'send_message_number': keys.send_message_number,
            'recv_message_number': keys.recv_message_number,
            'created_at': keys.created_at.isoformat(),
            'last_used': keys.last_used.isoformat() if keys.last_used else keys.created_at.isoformat(),
        }

        with open(path, 'w') as f:
            json.dump(data, f)

        path.chmod(0o600)

    def load_session(self, session_id: str) -> Optional[SessionKeys]:
        """
        Load session keys from disk.

        Handles both encrypted (.session) and legacy unencrypted (.json) formats.
        Returns None if session not found or corrupted.
        """
        from nacl.secret import SecretBox

        # Try encrypted format first
        encrypted_path = SESSION_KEYS_DIR / f"{session_id}.session"
        if encrypted_path.exists():
            try:
                with open(encrypted_path, 'rb') as f:
                    content = f.read()

                if len(content) < 2:
                    logger.warning(f"Session file too short: {session_id}")
                    return None

                # Check version
                version = content[0]
                if version != SESSION_FILE_VERSION:
                    logger.warning(f"Unknown session file version {version} for {session_id}")
                    # Try to decrypt anyway for forward compatibility

                # Decrypt
                box = SecretBox(self._encryption_key)
                plaintext = box.decrypt(content[1:])
                data = json.loads(plaintext.decode('utf-8'))

                return self._load_session_from_data(session_id, data)

            except Exception as e:
                logger.warning(f"Failed to load encrypted session {session_id}: {e}")
                # Fall through to try legacy format

        # Try legacy unencrypted format
        legacy_path = SESSION_KEYS_DIR / f"{session_id}.json"
        if legacy_path.exists():
            try:
                with open(legacy_path, 'r') as f:
                    data = json.load(f)

                keys = self._load_session_from_data(session_id, data)

                if keys:
                    # Upgrade to encrypted format
                    self._save_session(keys)
                    legacy_path.unlink()
                    logger.info(f"Upgraded session {session_id} to encrypted format")

                return keys

            except Exception as e:
                logger.warning(f"Failed to load legacy session {session_id}: {e}")
                return None

        return None

    def _load_session_from_data(self, session_id: str, data: dict) -> Optional[SessionKeys]:
        """Load session from parsed data dict."""
        try:
            keys = SessionKeys(
                session_id=data['session_id'],
                peer_amid=data['peer_amid'],
                shared_secret=base64.b64decode(data['shared_secret']),
                send_chain_key=base64.b64decode(data['send_chain_key']),
                recv_chain_key=base64.b64decode(data['recv_chain_key']),
                send_message_number=data.get('send_message_number', 0),
                recv_message_number=data.get('recv_message_number', 0),
                created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else None,
                last_used=datetime.fromisoformat(data['last_used']) if 'last_used' in data else None,
                ratchet_state=data.get('ratchet_state'),
            )

            self.sessions[session_id] = keys
            self.ratchets[session_id] = DoubleRatchet(keys)

            return keys

        except Exception as e:
            logger.error(f"Failed to parse session data for {session_id}: {e}")
            return None

    def load_all_sessions(self) -> int:
        """
        Load all persisted sessions on agent startup.

        Returns the number of sessions successfully loaded.
        Skips corrupted session files with a warning.
        """
        loaded = 0

        if not SESSION_KEYS_DIR.exists():
            return 0

        # Load encrypted sessions
        for path in SESSION_KEYS_DIR.glob("*.session"):
            session_id = path.stem
            if self.load_session(session_id):
                loaded += 1

        # Load legacy sessions
        for path in SESSION_KEYS_DIR.glob("*.json"):
            session_id = path.stem
            if session_id not in self.sessions:
                if self.load_session(session_id):
                    loaded += 1

        logger.info(f"Loaded {loaded} persisted sessions")
        return loaded

    def get_session_by_peer(self, peer_amid: str) -> Optional[SessionKeys]:
        """
        Find an active session with a specific peer.

        Used for session resumption without new KNOCK.
        """
        for keys in self.sessions.values():
            if keys.peer_amid == peer_amid and not keys.is_stale():
                return keys
        return None

    def resume_session(self, peer_amid: str) -> Optional[SessionKeys]:
        """
        Resume an existing session with a peer.

        Returns the session keys if a valid session exists,
        or None if no session found (requires new KNOCK).
        """
        keys = self.get_session_by_peer(peer_amid)
        if keys:
            keys.touch()
            self._save_session(keys)
            logger.info(f"Resumed session {keys.session_id} with {peer_amid}")
            return keys
        return None

    def cleanup_stale_sessions(self) -> int:
        """
        Remove sessions inactive for more than SESSION_INACTIVITY_CLEANUP_DAYS.

        Uses secure deletion by overwriting file contents before removal.
        Returns the number of sessions cleaned up.
        """
        cleaned = 0
        stale_ids = []

        # Find stale sessions in memory
        for session_id, keys in self.sessions.items():
            if keys.is_stale():
                stale_ids.append(session_id)

        # Also check disk for sessions not in memory
        if SESSION_KEYS_DIR.exists():
            for path in SESSION_KEYS_DIR.glob("*.session"):
                session_id = path.stem
                if session_id not in self.sessions:
                    # Load to check staleness
                    keys = self.load_session(session_id)
                    if keys and keys.is_stale():
                        stale_ids.append(session_id)

            for path in SESSION_KEYS_DIR.glob("*.json"):
                session_id = path.stem
                if session_id not in self.sessions:
                    keys = self.load_session(session_id)
                    if keys and keys.is_stale():
                        stale_ids.append(session_id)

        # Clean up stale sessions
        for session_id in set(stale_ids):
            self._secure_delete_session(session_id)
            cleaned += 1

        if cleaned > 0:
            logger.info(f"Cleaned up {cleaned} stale sessions")

        return cleaned

    def _secure_delete_session(self, session_id: str) -> None:
        """
        Securely delete a session file by overwriting before removal.
        """
        # Remove from memory
        self.sessions.pop(session_id, None)
        self.ratchets.pop(session_id, None)

        # Secure delete from disk
        for suffix in ['.session', '.json']:
            path = SESSION_KEYS_DIR / f"{session_id}{suffix}"
            if path.exists():
                try:
                    # Overwrite with random data
                    size = path.stat().st_size
                    with open(path, 'wb') as f:
                        f.write(random(size))
                        f.flush()
                    # Then delete
                    path.unlink()
                    logger.debug(f"Securely deleted session file: {path}")
                except Exception as e:
                    logger.warning(f"Failed to securely delete {path}: {e}")
                    # Try simple delete as fallback
                    try:
                        path.unlink()
                    except Exception:
                        pass

    def close_session(self, session_id: str, secure_delete: bool = True) -> None:
        """
        Close and clean up a session.

        Args:
            session_id: The session to close
            secure_delete: If True, overwrite file before deletion
        """
        if secure_delete:
            self._secure_delete_session(session_id)
        else:
            # Simple cleanup
            self.sessions.pop(session_id, None)
            self.ratchets.pop(session_id, None)

            # Delete session files
            for suffix in ['.session', '.json']:
                path = SESSION_KEYS_DIR / f"{session_id}{suffix}"
                if path.exists():
                    try:
                        path.unlink()
                    except Exception as e:
                        logger.warning(f"Failed to delete {path}: {e}")

        logger.info(f"Closed session {session_id}")


class SessionNotFoundError(Exception):
    """Raised when trying to use a session that doesn't exist."""

    def __init__(self, session_id: str, peer_amid: Optional[str] = None):
        self.session_id = session_id
        self.peer_amid = peer_amid
        msg = f"Session not found: {session_id}"
        if peer_amid:
            msg += f" (peer: {peer_amid})"
        super().__init__(msg)


class SessionCleanupTask:
    """
    Periodic task for cleaning up stale sessions.

    Runs every SESSION_CLEANUP_INTERVAL_HOURS (default: 6 hours).
    """

    def __init__(self, encryption: E2EEncryption):
        self.encryption = encryption
        self._running = False
        self._task = None

    async def start(self) -> None:
        """Start the periodic cleanup task."""
        import asyncio

        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Started session cleanup task")

    async def stop(self) -> None:
        """Stop the periodic cleanup task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass
        logger.info("Stopped session cleanup task")

    async def _run_loop(self) -> None:
        """Main loop that runs cleanup periodically."""
        import asyncio

        interval_seconds = SESSION_CLEANUP_INTERVAL_HOURS * 3600

        while self._running:
            try:
                # Run cleanup
                cleaned = self.encryption.cleanup_stale_sessions()
                if cleaned > 0:
                    logger.info(f"Periodic cleanup removed {cleaned} stale sessions")
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

            # Wait for next interval
            await asyncio.sleep(interval_seconds)

    def run_now(self) -> int:
        """Run cleanup immediately (synchronous)."""
        return self.encryption.cleanup_stale_sessions()


class PrekeyAutomationTask:
    """
    Periodic task for prekey management automation.

    Runs every PREKEY_CHECK_INTERVAL_HOURS (default: 6 hours).
    Handles:
    - Checking prekey count and replenishing when low
    - Rotating signed prekey when expired
    - Uploading new prekeys to registry
    """

    def __init__(self, prekey_manager: PrekeyManager):
        self.prekey_manager = prekey_manager
        self._running = False
        self._task = None

    async def start(self) -> None:
        """Start the periodic prekey check task."""
        import asyncio

        if self._running:
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Started prekey automation task")

    async def stop(self) -> None:
        """Stop the periodic prekey check task."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except Exception:
                pass
        logger.info("Stopped prekey automation task")

    async def _run_loop(self) -> None:
        """Main loop that checks prekeys periodically."""
        import asyncio

        interval_seconds = PREKEY_CHECK_INTERVAL_HOURS * 3600

        while self._running:
            try:
                # Check and replenish prekeys
                new_prekeys = self.prekey_manager.check_and_replenish()

                if new_prekeys:
                    # Upload new prekeys to registry
                    success = await self.prekey_manager.upload_prekeys_with_retry(new_prekeys)
                    if success:
                        logger.info(f"Uploaded {len(new_prekeys)} new prekeys to registry")
                    else:
                        logger.warning("Failed to upload new prekeys to registry")

            except Exception as e:
                logger.error(f"Prekey automation error: {e}")

            # Wait for next interval
            await asyncio.sleep(interval_seconds)

    async def run_check_now(self) -> Optional[List[Tuple[int, bytes]]]:
        """
        Run prekey check immediately.

        Returns the new prekeys if replenishment occurred.
        """
        new_prekeys = self.prekey_manager.check_and_replenish()
        if new_prekeys:
            await self.prekey_manager.upload_prekeys_with_retry(new_prekeys)
        return new_prekeys

    async def handle_low_prekeys(self) -> None:
        """Handle low_prekeys notification from registry."""
        logger.info("Handling low_prekeys notification")
        await self.run_check_now()
