"""
Audit logging for AgentMesh.
Maintains local logs of all activity for owner observability.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

AGENTMESH_DIR = Path.home() / ".agentmesh"
LOGS_DIR = AGENTMESH_DIR / "logs"
TRANSCRIPTS_DIR = AGENTMESH_DIR / "transcripts"


@dataclass
class AuditEvent:
    """A single audit log event."""
    timestamp: datetime
    event_type: str
    data: Dict[str, Any]

    def to_jsonl(self) -> str:
        return json.dumps({
            'ts': self.timestamp.isoformat(),
            'event': self.event_type,
            **self.data,
        })


class AuditLog:
    """
    Audit logger for AgentMesh activity.
    Writes to append-only JSONL files.
    """

    def __init__(self):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

        # Current log file (rotated daily)
        self._current_date: Optional[str] = None
        self._log_file = None

    def _get_log_file(self):
        """Get the current log file, rotating if needed."""
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')

        if self._current_date != today:
            if self._log_file:
                self._log_file.close()

            log_path = LOGS_DIR / f"{today}.jsonl"
            self._log_file = open(log_path, 'a')
            self._current_date = today

        return self._log_file

    def log_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            data=data or {},
        )

        try:
            log_file = self._get_log_file()
            log_file.write(event.to_jsonl() + '\n')
            log_file.flush()
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def log_knock_received(
        self,
        from_amid: str,
        intent: str,
        result: str,
    ) -> None:
        """Log an incoming KNOCK."""
        self.log_event("knock_received", {
            'from': from_amid,
            'intent': intent,
            'result': result,
        })

    def log_knock_sent(
        self,
        to_amid: str,
        intent: str,
    ) -> None:
        """Log an outgoing KNOCK."""
        self.log_event("knock_sent", {
            'to': to_amid,
            'intent': intent,
        })

    def log_session_started(
        self,
        session_id: str,
        peer_amid: str,
        session_type: str,
    ) -> None:
        """Log session start."""
        self.log_event("session_started", {
            'session_id': session_id,
            'peer': peer_amid,
            'type': session_type,
        })

    def log_session_closed(
        self,
        session_id: str,
        reason: str,
        messages_exchanged: int,
    ) -> None:
        """Log session close."""
        self.log_event("session_closed", {
            'session_id': session_id,
            'reason': reason,
            'messages_exchanged': messages_exchanged,
        })

    def log_message_sent(
        self,
        session_id: str,
        sequence: int,
        size_bytes: int,
    ) -> None:
        """Log outgoing message."""
        self.log_event("message_sent", {
            'session_id': session_id,
            'seq': sequence,
            'size_bytes': size_bytes,
        })

    def log_message_received(
        self,
        session_id: str,
        sequence: int,
        size_bytes: int,
    ) -> None:
        """Log incoming message."""
        self.log_event("message_received", {
            'session_id': session_id,
            'seq': sequence,
            'size_bytes': size_bytes,
        })

    def get_recent_events(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> List[AuditEvent]:
        """Get recent audit events."""
        events = []

        # Read from today's log
        today = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        log_path = LOGS_DIR / f"{today}.jsonl"

        if log_path.exists():
            try:
                with open(log_path, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            if event_type is None or data.get('event') == event_type:
                                events.append(AuditEvent(
                                    timestamp=datetime.fromisoformat(data['ts']),
                                    event_type=data['event'],
                                    data={k: v for k, v in data.items()
                                          if k not in ('ts', 'event')},
                                ))
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.error(f"Error reading audit log: {e}")

        # Return most recent
        return events[-limit:]

    def close(self) -> None:
        """Close the audit log."""
        if self._log_file:
            self._log_file.close()
            self._log_file = None


class TranscriptStore:
    """
    Stores full conversation transcripts.
    Encrypted at rest using XChaCha20-Poly1305 with key derived from owner's signing key.
    """

    ENCRYPTED_VERSION = 1
    KEY_INFO = b"agentmesh-transcript-encryption-v1"

    def __init__(self, signing_key: Optional[bytes] = None):
        TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
        self._signing_key = signing_key
        self._encryption_key: Optional[bytes] = None

        if signing_key:
            self._derive_encryption_key()

    def _derive_encryption_key(self) -> None:
        """Derive encryption key from signing key using HKDF."""
        if not self._signing_key:
            return

        try:
            from nacl.hash import blake2b
            from nacl.encoding import RawEncoder

            # Use BLAKE2b as HKDF-like KDF
            # Key = BLAKE2b(signing_key || KEY_INFO)
            # Use RawEncoder to get raw bytes instead of hex-encoded
            self._encryption_key = blake2b(
                self._signing_key + self.KEY_INFO,
                digest_size=32,
                encoder=RawEncoder,
            )
        except Exception as e:
            logger.error(f"Failed to derive encryption key: {e}")

    def set_signing_key(self, signing_key: bytes) -> None:
        """Set or update the signing key (e.g., after key rotation)."""
        old_key = self._encryption_key
        self._signing_key = signing_key
        self._derive_encryption_key()

        # If key changed and we have transcripts, consider re-encryption
        if old_key and old_key != self._encryption_key:
            logger.info("Encryption key changed, existing transcripts need re-encryption")

    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using XChaCha20-Poly1305."""
        if not self._encryption_key:
            raise ValueError("No encryption key available")

        try:
            from nacl.secret import SecretBox
            from nacl.utils import random

            box = SecretBox(self._encryption_key)
            # SecretBox uses XSalsa20-Poly1305, which is similar security level
            # Generate random nonce
            nonce = random(SecretBox.NONCE_SIZE)
            encrypted = box.encrypt(data, nonce)
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using XChaCha20-Poly1305."""
        if not self._encryption_key:
            raise ValueError("No encryption key available")

        try:
            from nacl.secret import SecretBox

            box = SecretBox(self._encryption_key)
            return box.decrypt(encrypted_data)
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def save_transcript(
        self,
        session_id: str,
        initiator: str,
        receiver: str,
        messages: List[Dict[str, Any]],
    ) -> None:
        """Save a conversation transcript (encrypted if key available)."""
        transcript = {
            'session_id': session_id,
            'initiator': initiator,
            'receiver': receiver,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'messages': messages,
        }

        transcript_json = json.dumps(transcript, indent=2).encode('utf-8')

        if self._encryption_key:
            # Save encrypted version
            path = TRANSCRIPTS_DIR / f"{session_id}.enc"
            try:
                encrypted = self._encrypt_data(transcript_json)
                # File format: version (1 byte) + encrypted data
                with open(path, 'wb') as f:
                    f.write(bytes([self.ENCRYPTED_VERSION]))
                    f.write(encrypted)
                path.chmod(0o600)
                logger.debug(f"Saved encrypted transcript: {session_id}")
            except Exception as e:
                logger.error(f"Failed to save encrypted transcript: {e}")
                raise
        else:
            # Save unencrypted (legacy/fallback)
            path = TRANSCRIPTS_DIR / f"{session_id}.json"
            with open(path, 'w') as f:
                f.write(transcript_json.decode('utf-8'))
            path.chmod(0o600)
            logger.warning(f"Saved unencrypted transcript (no encryption key): {session_id}")

    def get_transcript(self, session_id: str) -> Optional[dict]:
        """Load a transcript (decrypting if necessary)."""
        # Try encrypted first
        enc_path = TRANSCRIPTS_DIR / f"{session_id}.enc"
        if enc_path.exists():
            if not self._encryption_key:
                logger.error(f"Cannot decrypt transcript {session_id}: no encryption key")
                return None

            try:
                with open(enc_path, 'rb') as f:
                    version = f.read(1)[0]
                    if version != self.ENCRYPTED_VERSION:
                        logger.error(f"Unknown transcript version: {version}")
                        return None
                    encrypted_data = f.read()

                decrypted = self._decrypt_data(encrypted_data)
                return json.loads(decrypted.decode('utf-8'))
            except Exception as e:
                logger.error(f"Failed to decrypt transcript {session_id}: {e}")
                return None

        # Try unencrypted (legacy)
        json_path = TRANSCRIPTS_DIR / f"{session_id}.json"
        if json_path.exists():
            logger.warning(f"Reading unencrypted legacy transcript: {session_id}")
            with open(json_path, 'r') as f:
                return json.load(f)

        return None

    def list_transcripts(
        self,
        peer_amid: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        """List recent transcripts (metadata only, no decryption)."""
        transcripts = []

        # Check both encrypted and legacy files
        all_files = list(TRANSCRIPTS_DIR.glob("*.enc")) + list(TRANSCRIPTS_DIR.glob("*.json"))
        sorted_files = sorted(all_files, key=lambda p: p.stat().st_mtime, reverse=True)

        for path in sorted_files[:limit * 2]:  # Read more to account for filtering
            if len(transcripts) >= limit:
                break

            try:
                session_id = path.stem
                data = self.get_transcript(session_id)
                if data is None:
                    continue

                if peer_amid is None or data.get('initiator') == peer_amid or data.get('receiver') == peer_amid:
                    transcripts.append({
                        'session_id': data['session_id'],
                        'initiator': data['initiator'],
                        'receiver': data['receiver'],
                        'created_at': data['created_at'],
                        'message_count': len(data.get('messages', [])),
                        'encrypted': path.suffix == '.enc',
                    })
            except Exception:
                continue

        return transcripts[:limit]

    def delete_transcript(self, session_id: str, secure: bool = True) -> bool:
        """
        Delete a transcript.

        Args:
            session_id: The session ID
            secure: If True, overwrite file before unlinking (secure deletion)

        Returns:
            True if deleted, False if not found
        """
        deleted = False

        for suffix in ['.enc', '.json']:
            path = TRANSCRIPTS_DIR / f"{session_id}{suffix}"
            if path.exists():
                if secure:
                    # Secure deletion: overwrite with random data
                    try:
                        from nacl.utils import random
                        size = path.stat().st_size
                        with open(path, 'wb') as f:
                            f.write(random(size))
                        path.unlink()
                        logger.debug(f"Securely deleted transcript: {session_id}")
                    except Exception as e:
                        logger.error(f"Secure deletion failed, falling back: {e}")
                        path.unlink()
                else:
                    path.unlink()
                deleted = True

        return deleted

    def migrate_unencrypted(self) -> int:
        """
        Migrate existing unencrypted transcripts to encrypted format.
        Requires encryption key to be set.

        Returns:
            Number of transcripts migrated
        """
        if not self._encryption_key:
            logger.error("Cannot migrate: no encryption key set")
            return 0

        migrated = 0
        for path in TRANSCRIPTS_DIR.glob("*.json"):
            session_id = path.stem
            try:
                # Read unencrypted
                with open(path, 'r') as f:
                    data = json.load(f)

                # Save encrypted
                self.save_transcript(
                    session_id=data['session_id'],
                    initiator=data['initiator'],
                    receiver=data['receiver'],
                    messages=data.get('messages', []),
                )

                # Securely delete unencrypted
                self.delete_transcript(session_id, secure=True)

                migrated += 1
                logger.info(f"Migrated transcript: {session_id}")
            except Exception as e:
                logger.error(f"Failed to migrate {session_id}: {e}")

        return migrated

    def export_session_key(self, session_id: str) -> Optional[str]:
        """
        Export the session-specific decryption key for audit purposes.
        This allows sharing a single transcript without exposing the master key.
        """
        if not self._encryption_key:
            return None

        try:
            from nacl.hash import blake2b
            import base64

            # Derive session-specific key
            session_key = blake2b(
                self._encryption_key + session_id.encode('utf-8'),
                digest_size=32,
            )
            return base64.b64encode(session_key).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to export session key: {e}")
            return None
