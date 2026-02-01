"""
Session management and KNOCK protocol implementation.
"""

import json
import uuid
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List
from enum import Enum

from .identity import Identity
from .config import Policy

logger = logging.getLogger(__name__)


class SessionType(Enum):
    REQUEST_RESPONSE = "request_response"
    CONVERSATION = "conversation"
    STREAM = "stream"


class SessionState(Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CLOSED = "closed"
    REJECTED = "rejected"


@dataclass
class Intent:
    """Structured intent for KNOCK messages."""
    category: str
    subcategory: Optional[str] = None
    action: Optional[str] = None
    urgency: str = "normal"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> "Intent":
        return cls(**data)


@dataclass
class SessionRequest:
    """Session parameters for KNOCK."""
    session_type: SessionType = SessionType.REQUEST_RESPONSE
    expected_messages: Optional[int] = None
    ttl_seconds: int = 300

    def to_dict(self) -> dict:
        return {
            'type': self.session_type.value,
            'expected_messages': self.expected_messages,
            'ttl_seconds': self.ttl_seconds,
        }


@dataclass
class KnockMessage:
    """
    KNOCK message - the first step in establishing a session.
    Contains identity, intent, and session parameters without the actual payload.
    """
    protocol_version: str
    from_amid: str
    from_tier: int
    from_display_name: Optional[str]
    from_reputation: float
    intent: Intent
    session_request: SessionRequest
    timestamp: datetime
    signature: str

    def to_dict(self) -> dict:
        return {
            'type': 'knock',
            'protocol_version': self.protocol_version,
            'from': {
                'amid': self.from_amid,
                'tier': self.from_tier,
                'display_name': self.from_display_name,
                'reputation_score': self.from_reputation,
            },
            'intent': self.intent.to_dict(),
            'session_request': self.session_request.to_dict(),
            'timestamp': self.timestamp.isoformat(),
            'signature': self.signature,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "KnockMessage":
        from_data = data['from']
        return cls(
            protocol_version=data['protocol_version'],
            from_amid=from_data['amid'],
            from_tier=from_data['tier'],
            from_display_name=from_data.get('display_name'),
            from_reputation=from_data.get('reputation_score', 0.5),
            intent=Intent.from_dict(data['intent']),
            session_request=SessionRequest(
                session_type=SessionType(data['session_request']['type']),
                expected_messages=data['session_request'].get('expected_messages'),
                ttl_seconds=data['session_request']['ttl_seconds'],
            ),
            timestamp=datetime.fromisoformat(data['timestamp']),
            signature=data['signature'],
        )


@dataclass
class Session:
    """Active communication session between two agents."""
    id: str
    initiator_amid: str
    receiver_amid: str
    session_type: SessionType
    session_key: str  # Shared secret for E2EE
    state: SessionState
    created_at: datetime
    expires_at: datetime
    sequence: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    intent: Optional[Intent] = None

    def next_sequence(self) -> int:
        """Get and increment sequence number."""
        seq = self.sequence
        self.sequence += 1
        return seq


class KnockEvaluator:
    """
    Evaluates incoming KNOCK messages against security policy.
    This is DETERMINISTIC CODE, not LLM-based, for security.
    """

    def __init__(self, policy: Policy, active_sessions: int = 0):
        self.policy = policy
        self.active_sessions = active_sessions
        self._rate_limit_state: Dict[str, List[datetime]] = {}

    def evaluate(self, knock: KnockMessage) -> tuple[bool, Optional[str]]:
        """
        Evaluate a KNOCK message.
        Returns (accept, rejection_reason).
        """
        # 1. Check blocklist
        if knock.from_amid in self.policy.blocklist:
            logger.info(f"KNOCK rejected: {knock.from_amid} is blocklisted")
            return False, "blocked"

        # 2. Check tier policy
        tier_value = knock.from_tier
        if tier_value not in [int(t) for t in self.policy.accept_tiers]:
            # Check for tier 1.5
            if tier_value != 1 or 1.5 not in self.policy.accept_tiers:
                logger.info(f"KNOCK rejected: tier {tier_value} not accepted")
                return False, "insufficient_trust"

        # 3. Check reputation
        if knock.from_reputation < self.policy.min_reputation:
            logger.info(
                f"KNOCK rejected: reputation {knock.from_reputation} "
                f"< {self.policy.min_reputation}"
            )
            return False, "low_reputation"

        # 4. Check intent policy
        intent_category = knock.intent.category
        if self.policy.rejected_intents and intent_category in self.policy.rejected_intents:
            logger.info(f"KNOCK rejected: intent {intent_category} is rejected")
            return False, "intent_not_accepted"

        if self.policy.accepted_intents and intent_category not in self.policy.accepted_intents:
            logger.info(f"KNOCK rejected: intent {intent_category} not in accepted list")
            return False, "intent_not_accepted"

        # 5. Check strict mode (allowlist only)
        if self.policy.strict_mode:
            if knock.from_amid not in self.policy.allowlist:
                logger.info(f"KNOCK rejected: {knock.from_amid} not in allowlist (strict mode)")
                return False, "not_in_allowlist"

        # 6. Check capacity
        if self.active_sessions >= self.policy.max_concurrent_sessions:
            logger.info("KNOCK rejected: at capacity")
            return False, "at_capacity"

        # 7. Rate limiting
        if not self._check_rate_limit(knock.from_amid):
            logger.info(f"KNOCK rejected: {knock.from_amid} rate limited")
            return False, "rate_limited"

        # All checks passed
        logger.info(f"KNOCK accepted from {knock.from_amid}")
        return True, None

    def _check_rate_limit(self, amid: str) -> bool:
        """Check if KNOCK is within rate limits."""
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - 60  # 1 minute window

        # Get/initialize state for this AMID
        if amid not in self._rate_limit_state:
            self._rate_limit_state[amid] = []

        # Filter to recent knocks
        recent = [t for t in self._rate_limit_state[amid] if t.timestamp() > cutoff]
        self._rate_limit_state[amid] = recent

        # Check limit
        if len(recent) >= self.policy.rate_limit.knocks_per_minute:
            return False

        # Record this knock
        self._rate_limit_state[amid].append(now)
        return True


class SessionManager:
    """Manages active sessions."""

    def __init__(self, identity: Identity, policy: Policy):
        self.identity = identity
        self.policy = policy
        self.sessions: Dict[str, Session] = {}
        self.evaluator = KnockEvaluator(policy)

    def create_knock(
        self,
        to_amid: str,
        intent: Intent,
        session_type: SessionType = SessionType.REQUEST_RESPONSE,
        expected_messages: Optional[int] = None,
        ttl_seconds: int = 300,
    ) -> KnockMessage:
        """Create a KNOCK message to initiate a session."""
        timestamp = datetime.now(timezone.utc)

        # Sign the knock content
        knock_data = {
            'from': self.identity.amid,
            'to': to_amid,
            'intent': intent.to_dict(),
            'timestamp': timestamp.isoformat(),
        }
        signature = self.identity.sign_b64(json.dumps(knock_data).encode())

        return KnockMessage(
            protocol_version="agentmesh/0.1",
            from_amid=self.identity.amid,
            from_tier=2,  # Assume anonymous until verified
            from_display_name=None,
            from_reputation=0.5,  # Default
            intent=intent,
            session_request=SessionRequest(
                session_type=session_type,
                expected_messages=expected_messages,
                ttl_seconds=ttl_seconds,
            ),
            timestamp=timestamp,
            signature=signature,
        )

    def evaluate_knock(self, knock: KnockMessage) -> tuple[bool, Optional[str]]:
        """Evaluate an incoming KNOCK."""
        self.evaluator.active_sessions = len(self.sessions)
        return self.evaluator.evaluate(knock)

    def accept_session(
        self,
        knock: KnockMessage,
        session_key: str,
    ) -> Session:
        """Create and store a new session from an accepted KNOCK."""
        now = datetime.now(timezone.utc)
        ttl = knock.session_request.ttl_seconds

        session = Session(
            id=str(uuid.uuid4()),
            initiator_amid=knock.from_amid,
            receiver_amid=self.identity.amid,
            session_type=knock.session_request.session_type,
            session_key=session_key,
            state=SessionState.ACTIVE,
            created_at=now,
            expires_at=datetime.fromtimestamp(
                now.timestamp() + ttl,
                tz=timezone.utc
            ),
            intent=knock.intent,
        )

        self.sessions[session.id] = session
        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self.sessions.get(session_id)

    def close_session(self, session_id: str, reason: str = "completed") -> bool:
        """Close a session."""
        if session_id in self.sessions:
            self.sessions[session_id].state = SessionState.CLOSED
            logger.info(f"Session {session_id} closed: {reason}")
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired sessions."""
        now = datetime.now(timezone.utc)
        expired = [
            sid for sid, session in self.sessions.items()
            if session.expires_at < now
        ]
        for sid in expired:
            del self.sessions[sid]
        return len(expired)
