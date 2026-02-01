"""
Identity management for AgentMesh agents.
Handles key generation, AMID derivation, and signatures.
"""

import json
import hashlib
import base64
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey
from nacl.encoding import Base64Encoder


def derive_amid(signing_public_key: bytes) -> str:
    """
    Derive AgentMesh ID from signing public key.
    AMID = base58(sha256(public_key)[:20])
    """
    hash_bytes = hashlib.sha256(signing_public_key).digest()[:20]

    # Base58 encoding (Bitcoin-style alphabet)
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    n = int.from_bytes(hash_bytes, 'big')
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(ALPHABET[remainder])

    # Add leading zeros for leading zero bytes
    for byte in hash_bytes:
        if byte == 0:
            result.append(ALPHABET[0])
        else:
            break

    return ''.join(reversed(result))


@dataclass
class Identity:
    """Cryptographic identity for an AgentMesh agent."""

    # Ed25519 signing keys
    signing_private_key: SigningKey
    signing_public_key: VerifyKey

    # X25519 key exchange keys
    exchange_private_key: PrivateKey
    exchange_public_key: PublicKey

    # Derived AgentMesh ID
    amid: str

    # Metadata
    created_at: datetime
    framework: str = "openclaw"
    framework_version: str = "0.4.2"

    @classmethod
    def generate(cls) -> "Identity":
        """Generate a new cryptographic identity."""
        # Generate signing keypair
        signing_private = SigningKey.generate()
        signing_public = signing_private.verify_key

        # Generate exchange keypair
        exchange_private = PrivateKey.generate()
        exchange_public = exchange_private.public_key

        # Derive AMID
        amid = derive_amid(bytes(signing_public))

        return cls(
            signing_private_key=signing_private,
            signing_public_key=signing_public,
            exchange_private_key=exchange_private,
            exchange_public_key=exchange_public,
            amid=amid,
            created_at=datetime.now(timezone.utc),
        )

    @classmethod
    def _strip_key_prefix(cls, key_str: str, expected_prefix: str) -> str:
        """Strip key type prefix if present. Logs deprecation warning if missing."""
        import logging
        logger = logging.getLogger(__name__)

        if key_str.startswith(expected_prefix):
            return key_str[len(expected_prefix):]
        elif ':' in key_str:
            # Has a prefix but wrong type - could be an error
            prefix, rest = key_str.split(':', 1)
            logger.warning(f"Key has unexpected prefix '{prefix}:', expected '{expected_prefix}'")
            return rest
        else:
            # No prefix - backwards compatibility, but warn
            logger.warning(
                f"Key without type prefix detected. This is deprecated. "
                f"Keys should be prefixed with '{expected_prefix}'"
            )
            return key_str

    @classmethod
    def load(cls, path: Path) -> "Identity":
        """Load identity from file.

        Accepts keys with or without type prefixes for backwards compatibility.
        Logs deprecation warning for keys without prefixes.
        """
        with open(path, 'r') as f:
            data = json.load(f)

        signing_key_b64 = cls._strip_key_prefix(data['signing_private_key'], 'ed25519:')
        exchange_key_b64 = cls._strip_key_prefix(data['exchange_private_key'], 'x25519:')

        signing_private = SigningKey(
            base64.b64decode(signing_key_b64)
        )
        exchange_private = PrivateKey(
            base64.b64decode(exchange_key_b64)
        )

        return cls(
            signing_private_key=signing_private,
            signing_public_key=signing_private.verify_key,
            exchange_private_key=exchange_private,
            exchange_public_key=exchange_private.public_key,
            amid=data['amid'],
            created_at=datetime.fromisoformat(data['created_at']),
            framework=data.get('framework', 'openclaw'),
            framework_version=data.get('framework_version', '0.4.2'),
        )

    def save(self, path: Path) -> None:
        """Save identity to file (with restricted permissions).

        Keys are saved with type prefixes (ed25519: / x25519:) per protocol spec.
        """
        data = {
            'amid': self.amid,
            'signing_private_key': 'ed25519:' + base64.b64encode(
                bytes(self.signing_private_key)
            ).decode(),
            'signing_public_key': 'ed25519:' + base64.b64encode(
                bytes(self.signing_public_key)
            ).decode(),
            'exchange_private_key': 'x25519:' + base64.b64encode(
                bytes(self.exchange_private_key)
            ).decode(),
            'exchange_public_key': 'x25519:' + base64.b64encode(
                bytes(self.exchange_public_key)
            ).decode(),
            'created_at': self.created_at.isoformat(),
            'framework': self.framework,
            'framework_version': self.framework_version,
        }

        # Write with restrictive permissions
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
        path.chmod(0o600)

    @property
    def signing_public_key_b64(self) -> str:
        """Get signing public key as base64 with type prefix."""
        return 'ed25519:' + base64.b64encode(bytes(self.signing_public_key)).decode()

    @property
    def signing_public_key_b64_raw(self) -> str:
        """Get signing public key as base64 without prefix (for signature verification)."""
        return base64.b64encode(bytes(self.signing_public_key)).decode()

    @property
    def exchange_public_key_b64(self) -> str:
        """Get exchange public key as base64 with type prefix."""
        return 'x25519:' + base64.b64encode(bytes(self.exchange_public_key)).decode()

    @property
    def exchange_public_key_b64_raw(self) -> str:
        """Get exchange public key as base64 without prefix."""
        return base64.b64encode(bytes(self.exchange_public_key)).decode()

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the signing key."""
        return self.signing_private_key.sign(message).signature

    def sign_b64(self, message: bytes) -> str:
        """Sign a message and return base64-encoded signature."""
        return base64.b64encode(self.sign(message)).decode()

    def sign_timestamp(self) -> tuple[datetime, str]:
        """Sign the current timestamp for authentication."""
        now = datetime.now(timezone.utc)
        message = now.isoformat().encode()
        signature = self.sign_b64(message)
        return now, signature

    @staticmethod
    def verify_signature(
        public_key_b64: str,
        message: bytes,
        signature_b64: str
    ) -> bool:
        """Verify a signature from another agent.

        Accepts public keys with or without type prefix.
        """
        try:
            # Strip prefix if present
            key_b64 = public_key_b64
            if key_b64.startswith('ed25519:'):
                key_b64 = key_b64[8:]
            elif key_b64.startswith('x25519:'):
                key_b64 = key_b64[7:]

            public_key = VerifyKey(base64.b64decode(key_b64))
            signature = base64.b64decode(signature_b64)
            public_key.verify(message, signature)
            return True
        except Exception:
            return False

    def to_public_info(self) -> dict:
        """Get public information for registration/discovery."""
        return {
            'amid': self.amid,
            'signing_public_key': self.signing_public_key_b64,
            'exchange_public_key': self.exchange_public_key_b64,
            'framework': self.framework,
            'framework_version': self.framework_version,
        }

    def rotate_keys(self) -> None:
        """
        Rotate cryptographic keys.

        This generates new signing and exchange keypairs and updates the AMID.
        The old keys are discarded - any active sessions using the old keys
        will continue to work (they use established session keys), but new
        sessions will use the new identity.

        Note: After rotation, you must re-register with the registry to update
        your public keys and invalidate any cached session lookups.
        """
        import logging
        logger = logging.getLogger(__name__)

        old_amid = self.amid

        # Generate new signing keypair
        self.signing_private_key = SigningKey.generate()
        self.signing_public_key = self.signing_private_key.verify_key

        # Generate new exchange keypair
        self.exchange_private_key = PrivateKey.generate()
        self.exchange_public_key = self.exchange_private_key.public_key

        # Derive new AMID
        self.amid = derive_amid(bytes(self.signing_public_key))

        logger.info(f"Key rotation completed: {old_amid} -> {self.amid}")
