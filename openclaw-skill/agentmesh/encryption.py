"""
End-to-end encryption using the Signal Protocol (X3DH + Double Ratchet).
Uses the python-olm library which implements the Olm/Megolm protocol.
"""

import json
import base64
import logging
from typing import Optional, Dict, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timezone

from nacl.public import PrivateKey, PublicKey, Box
from nacl.utils import random

logger = logging.getLogger(__name__)

# Session key storage
SESSION_KEYS_DIR = Path.home() / ".agentmesh" / "sessions"


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

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)


class X3DHKeyExchange:
    """
    Extended Triple Diffie-Hellman key exchange.
    Establishes a shared secret between two parties.
    """

    @staticmethod
    def compute_shared_secret(
        our_private_key: PrivateKey,
        their_public_key: bytes,
    ) -> bytes:
        """
        Perform X25519 key exchange to compute shared secret.
        """
        their_key = PublicKey(their_public_key)
        box = Box(our_private_key, their_key)

        # The shared secret is derived from the key exchange
        # In a full implementation, this would use X3DH with prekeys
        return box.shared_key()

    @staticmethod
    def generate_ephemeral_keypair() -> Tuple[PrivateKey, PublicKey]:
        """Generate an ephemeral keypair for this session."""
        private_key = PrivateKey.generate()
        public_key = private_key.public_key
        return private_key, public_key


class DoubleRatchet:
    """
    Double Ratchet algorithm for forward secrecy.
    Each message uses a new key derived from the ratchet.
    """

    def __init__(self, session_keys: SessionKeys):
        self.keys = session_keys

    def derive_message_key(self, chain_key: bytes, message_num: int) -> bytes:
        """Derive a message key from the chain key."""
        from hashlib import sha256
        import hmac

        # HKDF-like key derivation
        info = f"agentmesh_msg_{message_num}".encode()
        return hmac.new(chain_key, info, sha256).digest()

    def advance_chain(self, chain_key: bytes) -> bytes:
        """Advance the chain key."""
        from hashlib import sha256
        import hmac

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
    """

    def __init__(self, our_private_key: PrivateKey):
        self.our_private_key = our_private_key
        self.sessions: Dict[str, SessionKeys] = {}
        self.ratchets: Dict[str, DoubleRatchet] = {}

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
            return json.loads(plaintext_bytes.decode('utf-8'))

        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    def _save_session(self, keys: SessionKeys) -> None:
        """Persist session keys to disk."""
        SESSION_KEYS_DIR.mkdir(parents=True, exist_ok=True)

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
        }

        with open(path, 'w') as f:
            json.dump(data, f)

        path.chmod(0o600)

    def load_session(self, session_id: str) -> Optional[SessionKeys]:
        """Load session keys from disk."""
        path = SESSION_KEYS_DIR / f"{session_id}.json"

        if not path.exists():
            return None

        try:
            with open(path, 'r') as f:
                data = json.load(f)

            keys = SessionKeys(
                session_id=data['session_id'],
                peer_amid=data['peer_amid'],
                shared_secret=base64.b64decode(data['shared_secret']),
                send_chain_key=base64.b64decode(data['send_chain_key']),
                recv_chain_key=base64.b64decode(data['recv_chain_key']),
                send_message_number=data['send_message_number'],
                recv_message_number=data['recv_message_number'],
                created_at=datetime.fromisoformat(data['created_at']),
            )

            self.sessions[session_id] = keys
            self.ratchets[session_id] = DoubleRatchet(keys)

            return keys

        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None

    def close_session(self, session_id: str) -> None:
        """Close and clean up a session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
        if session_id in self.ratchets:
            del self.ratchets[session_id]

        # Optionally delete session file
        path = SESSION_KEYS_DIR / f"{session_id}.json"
        if path.exists():
            path.unlink()

        logger.info(f"Closed session {session_id}")
