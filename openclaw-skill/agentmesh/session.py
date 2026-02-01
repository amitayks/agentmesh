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
from . import certs

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
    certificate_chain: Optional[List[bytes]] = None  # PEM-encoded certs for verified agents
    offered_capabilities: Optional[List[str]] = None  # For capability negotiation

    def to_dict(self) -> dict:
        result = {
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
        if self.certificate_chain:
            result['certificate_chain'] = [c.decode() if isinstance(c, bytes) else c
                                           for c in self.certificate_chain]
        if self.offered_capabilities:
            result['offered_capabilities'] = self.offered_capabilities
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "KnockMessage":
        from_data = data['from']
        cert_chain = data.get('certificate_chain')
        if cert_chain:
            cert_chain = [c.encode() if isinstance(c, str) else c for c in cert_chain]
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
            certificate_chain=cert_chain,
            offered_capabilities=data.get('offered_capabilities'),
        )


@dataclass
class AcceptMessage:
    """
    ACCEPT message - response to a successful KNOCK.
    Contains session parameters, capability negotiation results, and key material.
    """
    session_id: str
    protocol_version: str
    from_amid: str
    timestamp: datetime
    signature: str
    ephemeral_key: str  # Base64-encoded ephemeral public key for X3DH
    accepted_capabilities: Optional[List[str]] = None
    rejected_capabilities: Optional[List[str]] = None
    certificate_chain: Optional[List[bytes]] = None

    def to_dict(self) -> dict:
        result = {
            'type': 'accept',
            'session_id': self.session_id,
            'protocol_version': self.protocol_version,
            'from': {'amid': self.from_amid},
            'timestamp': self.timestamp.isoformat(),
            'signature': self.signature,
            'ephemeral_key': self.ephemeral_key,
        }
        if self.accepted_capabilities:
            result['accepted_capabilities'] = self.accepted_capabilities
        if self.rejected_capabilities:
            result['rejected_capabilities'] = self.rejected_capabilities
        if self.certificate_chain:
            result['certificate_chain'] = [c.decode() if isinstance(c, bytes) else c
                                           for c in self.certificate_chain]
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "AcceptMessage":
        cert_chain = data.get('certificate_chain')
        if cert_chain:
            cert_chain = [c.encode() if isinstance(c, str) else c for c in cert_chain]
        return cls(
            session_id=data['session_id'],
            protocol_version=data['protocol_version'],
            from_amid=data['from']['amid'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            signature=data['signature'],
            ephemeral_key=data['ephemeral_key'],
            accepted_capabilities=data.get('accepted_capabilities'),
            rejected_capabilities=data.get('rejected_capabilities'),
            certificate_chain=cert_chain,
        )


@dataclass
class RejectMessage:
    """REJECT message - response to a failed KNOCK."""
    reason: str
    protocol_version: str
    from_amid: str
    timestamp: datetime
    signature: str
    retry_after: Optional[int] = None  # Seconds to wait before retry
    message: Optional[str] = None  # Human-readable explanation

    def to_dict(self) -> dict:
        result = {
            'type': 'reject',
            'reason': self.reason,
            'protocol_version': self.protocol_version,
            'from': {'amid': self.from_amid},
            'timestamp': self.timestamp.isoformat(),
            'signature': self.signature,
        }
        if self.retry_after is not None:
            result['retry_after'] = self.retry_after
        if self.message:
            result['message'] = self.message
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class CapabilityError(Exception):
    """Raised when a required capability is not supported."""
    def __init__(self, capability: str, message: str = None):
        self.capability = capability
        self.message = message or f"Required capability not supported: {capability}"
        super().__init__(self.message)


# =============================================================================
# Payload Types (Group 11)
# =============================================================================

class MessageType(Enum):
    """Standard message types for AgentMesh protocol."""
    REQUEST = "request"
    RESPONSE = "response"
    STATUS = "status"
    ERROR = "error"
    CLOSE = "close"


class Priority(Enum):
    """Message priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class ErrorCode(Enum):
    """Standard error codes for ERROR payloads."""
    # General errors (1xx)
    UNKNOWN_ERROR = "unknown_error"
    INTERNAL_ERROR = "internal_error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

    # Request errors (2xx)
    INVALID_REQUEST = "invalid_request"
    MISSING_PARAMETER = "missing_parameter"
    INVALID_PARAMETER = "invalid_parameter"
    UNSUPPORTED_OPERATION = "unsupported_operation"

    # Authorization errors (3xx)
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    QUOTA_EXCEEDED = "quota_exceeded"
    RATE_LIMITED = "rate_limited"

    # Resource errors (4xx)
    NOT_FOUND = "not_found"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    UNAVAILABLE = "unavailable"

    # Session errors (5xx)
    SESSION_EXPIRED = "session_expired"
    SESSION_NOT_FOUND = "session_not_found"
    CAPABILITY_NOT_SUPPORTED = "capability_not_supported"

    # External errors (6xx)
    EXTERNAL_SERVICE_ERROR = "external_service_error"
    NETWORK_ERROR = "network_error"


class CloseReason(Enum):
    """Standard close reason codes for CLOSE payloads."""
    COMPLETED = "completed"
    CANCELLED_BY_INITIATOR = "cancelled_by_initiator"
    CANCELLED_BY_RECEIVER = "cancelled_by_receiver"
    TIMEOUT = "timeout"
    ERROR = "error"
    SESSION_EXPIRED = "session_expired"
    BUDGET_EXCEEDED = "budget_exceeded"
    CAPACITY_EXCEEDED = "capacity_exceeded"
    POLICY_VIOLATION = "policy_violation"
    MAINTENANCE = "maintenance"


@dataclass
class Budget:
    """Budget constraints for REQUEST payloads."""
    amount: float  # Budget amount
    currency: str = "USD"  # ISO 4217 currency code
    max_cost: Optional[float] = None  # Maximum cost for this request

    def to_dict(self) -> dict:
        result = {
            'amount': self.amount,
            'currency': self.currency,
        }
        if self.max_cost is not None:
            result['max_cost'] = self.max_cost
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "Budget":
        return cls(
            amount=data['amount'],
            currency=data.get('currency', 'USD'),
            max_cost=data.get('max_cost'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate budget values."""
        if self.amount < 0:
            return False, "amount must be non-negative"
        if self.max_cost is not None and self.max_cost < 0:
            return False, "max_cost must be non-negative"
        if self.max_cost is not None and self.max_cost > self.amount:
            return False, "max_cost cannot exceed amount"
        return True, None


@dataclass
class StatusPayload:
    """
    STATUS payload - Progress updates during request processing.

    Used to inform the initiator about processing progress.
    """
    progress: float  # 0.0 to 1.0
    message: Optional[str] = None
    phase: Optional[str] = None  # e.g., "searching", "processing", "finalizing"
    estimated_completion_seconds: Optional[int] = None

    def to_dict(self) -> dict:
        result = {
            'type': MessageType.STATUS.value,
            'progress': self.progress,
        }
        if self.message:
            result['message'] = self.message
        if self.phase:
            result['phase'] = self.phase
        if self.estimated_completion_seconds is not None:
            result['estimated_completion_seconds'] = self.estimated_completion_seconds
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "StatusPayload":
        return cls(
            progress=data['progress'],
            message=data.get('message'),
            phase=data.get('phase'),
            estimated_completion_seconds=data.get('estimated_completion_seconds'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate STATUS payload."""
        if not 0.0 <= self.progress <= 1.0:
            return False, f"progress must be between 0.0 and 1.0, got {self.progress}"
        if self.estimated_completion_seconds is not None and self.estimated_completion_seconds < 0:
            return False, "estimated_completion_seconds must be non-negative"
        return True, None


@dataclass
class ErrorPayload:
    """
    ERROR payload - Error information during request processing.

    Used to report errors that occurred during processing.
    """
    code: ErrorCode  # Error code enum
    message: str  # Human-readable error message
    retry_after_seconds: Optional[int] = None  # When to retry (for rate limiting)
    fallback_amid: Optional[str] = None  # Alternative agent to try
    details: Optional[Dict[str, Any]] = None  # Additional error context

    def to_dict(self) -> dict:
        result = {
            'type': MessageType.ERROR.value,
            'code': self.code.value if isinstance(self.code, ErrorCode) else self.code,
            'message': self.message,
        }
        if self.retry_after_seconds is not None:
            result['retry_after_seconds'] = self.retry_after_seconds
        if self.fallback_amid:
            result['fallback_amid'] = self.fallback_amid
        if self.details:
            result['details'] = self.details
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ErrorPayload":
        code_str = data['code']
        try:
            code = ErrorCode(code_str)
        except ValueError:
            code = ErrorCode.UNKNOWN_ERROR
            logger.warning(f"Unknown error code: {code_str}")

        return cls(
            code=code,
            message=data['message'],
            retry_after_seconds=data.get('retry_after_seconds'),
            fallback_amid=data.get('fallback_amid'),
            details=data.get('details'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate ERROR payload."""
        if not self.message:
            return False, "message is required"
        if self.retry_after_seconds is not None and self.retry_after_seconds < 0:
            return False, "retry_after_seconds must be non-negative"
        return True, None


@dataclass
class ClosePayload:
    """
    CLOSE payload - Session termination information.

    Used to gracefully close a session with summary and optional feedback.
    """
    reason: CloseReason
    summary: Optional[str] = None  # Brief summary of what was accomplished
    reputation_feedback: Optional[float] = None  # 0.0 to 1.0, optional rating

    def to_dict(self) -> dict:
        result = {
            'type': MessageType.CLOSE.value,
            'reason': self.reason.value if isinstance(self.reason, CloseReason) else self.reason,
        }
        if self.summary:
            result['summary'] = self.summary
        if self.reputation_feedback is not None:
            result['reputation_feedback'] = self.reputation_feedback
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ClosePayload":
        reason_str = data['reason']
        try:
            reason = CloseReason(reason_str)
        except ValueError:
            reason = CloseReason.COMPLETED
            logger.warning(f"Unknown close reason: {reason_str}")

        return cls(
            reason=reason,
            summary=data.get('summary'),
            reputation_feedback=data.get('reputation_feedback'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate CLOSE payload."""
        if self.reputation_feedback is not None:
            if not 0.0 <= self.reputation_feedback <= 1.0:
                return False, f"reputation_feedback must be between 0.0 and 1.0, got {self.reputation_feedback}"
        return True, None


@dataclass
class RequestPayload:
    """
    REQUEST payload - Initial request from initiator.

    Contains the actual request content along with priority and budget.
    """
    content: Any  # The actual request content (schema-validated)
    priority: Priority = Priority.NORMAL
    budget: Optional[Budget] = None
    schema: Optional[str] = None  # Schema ID for content validation

    def to_dict(self) -> dict:
        result = {
            'type': MessageType.REQUEST.value,
            'content': self.content,
            'priority': self.priority.value if isinstance(self.priority, Priority) else self.priority,
        }
        if self.budget:
            result['budget'] = self.budget.to_dict()
        if self.schema:
            result['schema'] = self.schema
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "RequestPayload":
        priority_str = data.get('priority', 'normal')
        try:
            priority = Priority(priority_str)
        except ValueError:
            priority = Priority.NORMAL
            logger.warning(f"Unknown priority: {priority_str}")

        budget = None
        if 'budget' in data:
            budget = Budget.from_dict(data['budget'])

        return cls(
            content=data['content'],
            priority=priority,
            budget=budget,
            schema=data.get('schema'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate REQUEST payload."""
        if self.content is None:
            return False, "content is required"
        if self.budget:
            valid, error = self.budget.validate()
            if not valid:
                return False, f"invalid budget: {error}"
        return True, None


@dataclass
class ResponsePayload:
    """
    RESPONSE payload - Response from receiver.

    Contains the actual response content along with processing metadata.
    """
    content: Any  # The actual response content (schema-validated)
    processing_time_ms: Optional[int] = None  # How long processing took
    completed_at: Optional[datetime] = None  # When processing completed
    schema: Optional[str] = None  # Schema ID for content validation

    def to_dict(self) -> dict:
        result = {
            'type': MessageType.RESPONSE.value,
            'content': self.content,
        }
        if self.processing_time_ms is not None:
            result['processing_time_ms'] = self.processing_time_ms
        if self.completed_at:
            result['completed_at'] = self.completed_at.isoformat()
        if self.schema:
            result['schema'] = self.schema
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "ResponsePayload":
        completed_at = None
        if 'completed_at' in data:
            completed_at = datetime.fromisoformat(data['completed_at'])

        return cls(
            content=data['content'],
            processing_time_ms=data.get('processing_time_ms'),
            completed_at=completed_at,
            schema=data.get('schema'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate RESPONSE payload."""
        if self.content is None:
            return False, "content is required"
        if self.processing_time_ms is not None and self.processing_time_ms < 0:
            return False, "processing_time_ms must be non-negative"
        return True, None


@dataclass
class MessageEnvelope:
    """
    Message envelope containing type, session info, and payload.

    This wraps all message content in a standard format.
    """
    type: MessageType
    session_id: str
    sequence: int
    timestamp: datetime
    payload: Any  # One of the payload types above
    schema: Optional[str] = None  # Schema for payload validation

    def to_dict(self) -> dict:
        payload_dict = self.payload
        if hasattr(self.payload, 'to_dict'):
            payload_dict = self.payload.to_dict()

        result = {
            'type': self.type.value if isinstance(self.type, MessageType) else self.type,
            'session_id': self.session_id,
            'sequence': self.sequence,
            'timestamp': self.timestamp.isoformat(),
            'payload': payload_dict,
        }
        if self.schema:
            result['schema'] = self.schema
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "MessageEnvelope":
        type_str = data['type']
        try:
            msg_type = MessageType(type_str)
        except ValueError:
            msg_type = MessageType.REQUEST
            logger.warning(f"Unknown message type: {type_str}, defaulting to REQUEST")

        # Parse payload based on type
        payload_data = data['payload']
        payload = payload_data  # Default: raw dict

        if msg_type == MessageType.STATUS:
            payload = StatusPayload.from_dict(payload_data)
        elif msg_type == MessageType.ERROR:
            payload = ErrorPayload.from_dict(payload_data)
        elif msg_type == MessageType.CLOSE:
            payload = ClosePayload.from_dict(payload_data)
        elif msg_type == MessageType.REQUEST:
            payload = RequestPayload.from_dict(payload_data)
        elif msg_type == MessageType.RESPONSE:
            payload = ResponsePayload.from_dict(payload_data)

        return cls(
            type=msg_type,
            session_id=data['session_id'],
            sequence=data['sequence'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            payload=payload,
            schema=data.get('schema'),
        )

    def validate(self) -> tuple[bool, Optional[str]]:
        """Validate the message envelope and its payload."""
        if not self.session_id:
            return False, "session_id is required"
        if self.sequence < 0:
            return False, "sequence must be non-negative"

        # Validate payload if it has a validate method
        if hasattr(self.payload, 'validate'):
            valid, error = self.payload.validate()
            if not valid:
                return False, f"invalid payload: {error}"

        return True, None


def parse_message(data: dict) -> Optional[MessageEnvelope]:
    """
    Parse a message from raw dictionary data.

    Handles unknown message types gracefully by logging a warning
    and returning None.
    """
    try:
        return MessageEnvelope.from_dict(data)
    except KeyError as e:
        logger.warning(f"Missing required field in message: {e}")
        return None
    except Exception as e:
        logger.warning(f"Failed to parse message: {e}")
        return None


def validate_payload_type(payload: Any, expected_type: MessageType) -> tuple[bool, Optional[str]]:
    """
    Validate that a payload matches the expected type.

    Args:
        payload: The payload to validate
        expected_type: The expected MessageType

    Returns:
        Tuple of (is_valid, error_message)
    """
    type_mapping = {
        MessageType.STATUS: StatusPayload,
        MessageType.ERROR: ErrorPayload,
        MessageType.CLOSE: ClosePayload,
        MessageType.REQUEST: RequestPayload,
        MessageType.RESPONSE: ResponsePayload,
    }

    expected_class = type_mapping.get(expected_type)
    if expected_class is None:
        return False, f"Unknown message type: {expected_type}"

    if not isinstance(payload, expected_class):
        return False, f"Expected {expected_class.__name__}, got {type(payload).__name__}"

    # Run payload-specific validation
    if hasattr(payload, 'validate'):
        return payload.validate()

    return True, None


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
    negotiated_capabilities: Optional[List[str]] = None  # Agreed capabilities

    def next_sequence(self) -> int:
        """Get and increment sequence number."""
        seq = self.sequence
        self.sequence += 1
        return seq

    def has_capability(self, capability: str) -> bool:
        """Check if a capability was negotiated for this session."""
        if self.negotiated_capabilities is None:
            return False
        return capability in self.negotiated_capabilities


class KnockEvaluator:
    """
    Evaluates incoming KNOCK messages against security policy.
    This is DETERMINISTIC CODE, not LLM-based, for security.
    """

    def __init__(self, policy: Policy, active_sessions: int = 0, registry_url: Optional[str] = None):
        self.policy = policy
        self.active_sessions = active_sessions
        self.registry_url = registry_url
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

        # 2. Validate certificate chain (for verified agents)
        if knock.from_tier in [1, 1.5] and knock.certificate_chain:
            is_valid, error = self._validate_certificate_chain(knock)
            if not is_valid:
                logger.info(f"KNOCK rejected: certificate validation failed - {error}")
                return False, error

        # 3. Check tier policy
        tier_value = knock.from_tier
        if tier_value not in [int(t) for t in self.policy.accept_tiers]:
            # Check for tier 1.5
            if tier_value != 1 or 1.5 not in self.policy.accept_tiers:
                logger.info(f"KNOCK rejected: tier {tier_value} not accepted")
                return False, "insufficient_trust"

        # 4. Check reputation
        if knock.from_reputation < self.policy.min_reputation:
            logger.info(
                f"KNOCK rejected: reputation {knock.from_reputation} "
                f"< {self.policy.min_reputation}"
            )
            return False, "low_reputation"

        # 5. Check intent policy
        intent_category = knock.intent.category
        if self.policy.rejected_intents and intent_category in self.policy.rejected_intents:
            logger.info(f"KNOCK rejected: intent {intent_category} is rejected")
            return False, "intent_not_accepted"

        if self.policy.accepted_intents and intent_category not in self.policy.accepted_intents:
            logger.info(f"KNOCK rejected: intent {intent_category} not in accepted list")
            return False, "intent_not_accepted"

        # 6. Check strict mode (allowlist only)
        if self.policy.strict_mode:
            if knock.from_amid not in self.policy.allowlist:
                logger.info(f"KNOCK rejected: {knock.from_amid} not in allowlist (strict mode)")
                return False, "not_in_allowlist"

        # 7. Check capacity
        if self.active_sessions >= self.policy.max_concurrent_sessions:
            logger.info("KNOCK rejected: at capacity")
            return False, "at_capacity"

        # 8. Rate limiting
        if not self._check_rate_limit(knock.from_amid):
            logger.info(f"KNOCK rejected: {knock.from_amid} rate limited")
            return False, "rate_limited"

        # All checks passed
        logger.info(f"KNOCK accepted from {knock.from_amid}")
        return True, None

    def _validate_certificate_chain(self, knock: KnockMessage) -> tuple[bool, Optional[str]]:
        """
        Validate the certificate chain from a KNOCK message.

        Returns (is_valid, error_reason).
        """
        if not knock.certificate_chain:
            # No chain provided - acceptable for anonymous tier
            if knock.from_tier == 2:
                return True, None
            # Verified agents should have certificates
            logger.warning(f"Verified agent {knock.from_amid} missing certificate chain")
            return True, None  # Warn but allow for backwards compatibility

        try:
            # Validate the chain
            is_valid, error = certs.validate_agent_certificate_chain(
                knock.certificate_chain,
                expected_amid=knock.from_amid,
            )

            if not is_valid:
                return False, error or "certificate_invalid"

            # Check for revocation (if registry URL configured)
            if self.registry_url:
                chain = certs.CertificateChain(knock.certificate_chain)
                if chain.leaf and chain.leaf.serial_number:
                    import asyncio
                    # Run revocation check synchronously
                    try:
                        loop = asyncio.get_event_loop()
                        is_revoked, _ = loop.run_until_complete(
                            certs.check_certificate_revocation(
                                chain.leaf.serial_number,
                                self.registry_url,
                            )
                        )
                        if is_revoked:
                            return False, "certificate_revoked"
                    except Exception as e:
                        logger.warning(f"Revocation check failed: {e}")
                        # Continue if revocation check fails

            return True, None

        except Exception as e:
            logger.error(f"Certificate validation error: {e}")
            return False, "certificate_expired"

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
            protocol_version="agentmesh/0.2",
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


class SessionCapabilityNegotiator:
    """
    Handles capability negotiation during session establishment.

    Negotiates:
    - Schemas (selects highest common version)
    - Message types (text, json, binary)
    - Protocol features
    """

    # Standard capabilities supported by this implementation
    STANDARD_CAPABILITIES = [
        "text",
        "json",
        "binary",
        "agentmesh/travel/flight-search/v1",
        "agentmesh/commerce/product-search/v1",
        "agentmesh/marketplace/skill-bid/v1",
    ]

    def __init__(self, supported_capabilities: Optional[List[str]] = None):
        """
        Initialize the negotiator.

        Args:
            supported_capabilities: List of capabilities this agent supports.
                                   Defaults to STANDARD_CAPABILITIES.
        """
        self.supported = supported_capabilities or self.STANDARD_CAPABILITIES.copy()

    def negotiate(
        self,
        offered_capabilities: Optional[List[str]],
        required_capabilities: Optional[List[str]] = None,
    ) -> tuple[List[str], List[str]]:
        """
        Negotiate capabilities with peer.

        Args:
            offered_capabilities: Capabilities offered by the peer
            required_capabilities: Capabilities that MUST be supported

        Returns:
            Tuple of (accepted_capabilities, rejected_capabilities)

        Raises:
            CapabilityError: If a required capability is not supported
        """
        if not offered_capabilities:
            logger.warning("Peer offered no capabilities - accepting basic text/json")
            return ["text", "json"], []

        accepted = []
        rejected = []

        for cap in offered_capabilities:
            if cap in self.supported or self._version_matches(cap):
                accepted.append(cap)
            else:
                rejected.append(cap)

        # Check required capabilities
        if required_capabilities:
            for req in required_capabilities:
                if req not in accepted:
                    raise CapabilityError(req)

        # Log warning if no common capabilities
        if not accepted:
            logger.warning(f"No common capabilities with peer. Offered: {offered_capabilities}, Supported: {self.supported}")

        return accepted, rejected

    def _version_matches(self, capability: str) -> bool:
        """
        Check if capability matches with version negotiation.

        Handles version suffixes like /v1, /v2 by selecting
        the highest common version.
        """
        if '/' not in capability:
            return False

        parts = capability.rsplit('/v', 1)
        if len(parts) != 2:
            return False

        base = parts[0]
        try:
            offered_version = int(parts[1])
        except ValueError:
            return False

        # Check if we support any version of this capability
        for supported in self.supported:
            if supported.startswith(base + '/v'):
                try:
                    supported_version = int(supported.rsplit('/v', 1)[1])
                    # We can accept if we support >= the offered version
                    if supported_version >= offered_version:
                        return True
                except ValueError:
                    continue

        return False

    def select_common_version(
        self,
        capability_base: str,
        offered_versions: List[int],
    ) -> Optional[int]:
        """
        Select the highest common version of a capability.

        Args:
            capability_base: Base capability path (e.g., "agentmesh/travel/flight-search")
            offered_versions: List of versions offered by peer

        Returns:
            The highest common version, or None if no match
        """
        our_versions = []
        for cap in self.supported:
            if cap.startswith(capability_base + '/v'):
                try:
                    version = int(cap.rsplit('/v', 1)[1])
                    our_versions.append(version)
                except ValueError:
                    continue

        if not our_versions:
            return None

        common = set(offered_versions) & set(our_versions)
        if not common:
            # Use lowest common as fallback for forward compatibility
            min_offered = min(offered_versions) if offered_versions else 0
            min_ours = min(our_versions)
            return min(min_offered, min_ours) if min_offered > 0 and min_ours > 0 else None

        return max(common)

    def add_capability(self, capability: str) -> None:
        """Add a capability to the supported list."""
        if capability not in self.supported:
            self.supported.append(capability)

    def remove_capability(self, capability: str) -> bool:
        """Remove a capability from the supported list."""
        if capability in self.supported:
            self.supported.remove(capability)
            return True
        return False
