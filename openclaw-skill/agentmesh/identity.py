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
    def load(cls, path: Path) -> "Identity":
        """Load identity from file."""
        with open(path, 'r') as f:
            data = json.load(f)

        signing_private = SigningKey(
            base64.b64decode(data['signing_private_key'])
        )
        exchange_private = PrivateKey(
            base64.b64decode(data['exchange_private_key'])
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
        """Save identity to file (with restricted permissions)."""
        data = {
            'amid': self.amid,
            'signing_private_key': base64.b64encode(
                bytes(self.signing_private_key)
            ).decode(),
            'signing_public_key': base64.b64encode(
                bytes(self.signing_public_key)
            ).decode(),
            'exchange_private_key': base64.b64encode(
                bytes(self.exchange_private_key)
            ).decode(),
            'exchange_public_key': base64.b64encode(
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
        """Get signing public key as base64."""
        return base64.b64encode(bytes(self.signing_public_key)).decode()

    @property
    def exchange_public_key_b64(self) -> str:
        """Get exchange public key as base64."""
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
        """Verify a signature from another agent."""
        try:
            public_key = VerifyKey(base64.b64decode(public_key_b64))
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
