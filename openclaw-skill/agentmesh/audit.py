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
    Encrypted at rest with owner's key.
    """

    def __init__(self):
        TRANSCRIPTS_DIR.mkdir(parents=True, exist_ok=True)

    def save_transcript(
        self,
        session_id: str,
        initiator: str,
        receiver: str,
        messages: List[Dict[str, Any]],
    ) -> None:
        """Save a conversation transcript."""
        transcript = {
            'session_id': session_id,
            'initiator': initiator,
            'receiver': receiver,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'messages': messages,
        }

        path = TRANSCRIPTS_DIR / f"{session_id}.json"

        # TODO: Encrypt with owner's key
        with open(path, 'w') as f:
            json.dump(transcript, f, indent=2)

        path.chmod(0o600)

    def get_transcript(self, session_id: str) -> Optional[dict]:
        """Load a transcript."""
        path = TRANSCRIPTS_DIR / f"{session_id}.json"

        if not path.exists():
            return None

        with open(path, 'r') as f:
            return json.load(f)

    def list_transcripts(
        self,
        peer_amid: Optional[str] = None,
        limit: int = 50,
    ) -> List[dict]:
        """List recent transcripts."""
        transcripts = []

        for path in sorted(TRANSCRIPTS_DIR.glob("*.json"), reverse=True)[:limit]:
            try:
                with open(path, 'r') as f:
                    data = json.load(f)

                if peer_amid is None or data.get('initiator') == peer_amid or data.get('receiver') == peer_amid:
                    transcripts.append({
                        'session_id': data['session_id'],
                        'initiator': data['initiator'],
                        'receiver': data['receiver'],
                        'created_at': data['created_at'],
                        'message_count': len(data.get('messages', [])),
                    })
            except Exception:
                continue

        return transcripts
