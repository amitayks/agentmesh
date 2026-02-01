"""
Message Schemas for AgentMesh.
Provides schema validation, sequence tracking, and capability negotiation.
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Set
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)

AGENTMESH_DIR = Path.home() / ".agentmesh"
SCHEMAS_DIR = AGENTMESH_DIR / "schemas"

# Check if jsonschema is available
try:
    import jsonschema
    from jsonschema import Draft7Validator, ValidationError
    JSONSCHEMA_AVAILABLE = True
    logger.info("jsonschema library available - full JSON Schema validation enabled")
except ImportError:
    JSONSCHEMA_AVAILABLE = False
    logger.warning("jsonschema not installed - using basic validation fallback")


class ValidationMode(Enum):
    """Schema validation modes."""
    SILENT = "silent"      # No logging, no rejection
    WARNING = "warning"    # Log warnings but don't reject (default)
    STRICT = "strict"      # Reject invalid messages

# Standard schema definitions
STANDARD_SCHEMAS = {
    "agentmesh/travel/flight-search/v1": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Flight Search Request/Response",
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["search", "book", "cancel"]},
            "origin": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "destination": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "departure_date": {"type": "string", "format": "date"},
            "return_date": {"type": "string", "format": "date"},
            "passengers": {"type": "integer", "minimum": 1, "maximum": 9},
            "cabin_class": {"type": "string", "enum": ["economy", "business", "first"]},
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "flight_number": {"type": "string"},
                        "airline": {"type": "string"},
                        "price": {"type": "number"},
                        "currency": {"type": "string"},
                        "departure_time": {"type": "string", "format": "date-time"},
                        "arrival_time": {"type": "string", "format": "date-time"},
                    },
                },
            },
        },
    },
    "agentmesh/commerce/product-search/v1": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Product Search Request/Response",
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["search", "details", "purchase"]},
            "query": {"type": "string"},
            "category": {"type": "string"},
            "min_price": {"type": "number", "minimum": 0},
            "max_price": {"type": "number", "minimum": 0},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "product_id": {"type": "string"},
                        "name": {"type": "string"},
                        "price": {"type": "number"},
                        "currency": {"type": "string"},
                        "description": {"type": "string"},
                        "in_stock": {"type": "boolean"},
                    },
                },
            },
        },
    },
    "agentmesh/marketplace/skill-bid/v1": {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "Skill Marketplace Bid",
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["request", "bid", "accept", "reject"]},
            "task_id": {"type": "string"},
            "skill_required": {"type": "string"},
            "description": {"type": "string"},
            "budget": {
                "type": "object",
                "properties": {
                    "amount": {"type": "number", "minimum": 0},
                    "currency": {"type": "string"},
                },
            },
            "deadline": {"type": "string", "format": "date-time"},
            "bid_amount": {"type": "number", "minimum": 0},
            "estimated_completion": {"type": "string", "format": "date-time"},
            "bidder_reputation": {"type": "number", "minimum": 0, "maximum": 1},
        },
    },
}


@dataclass
class ValidationError:
    """A single validation error with details."""
    path: str           # JSON path to the error (e.g., ".passengers")
    message: str        # Human-readable error message
    schema_id: str      # Schema ID that was validated against
    schema_path: str = ""  # Path in schema where violation occurred

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


@dataclass
class ValidationResult:
    """Result of schema validation."""
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    schema_id: Optional[str] = None

    @property
    def error_messages(self) -> List[str]:
        """Get list of error messages as strings."""
        return [str(e) for e in self.errors]


@dataclass
class SequenceState:
    """Tracks sequence numbers for a session."""
    session_id: str
    last_sent: int = 0
    last_received: int = 0
    received_sequences: Set[int] = field(default_factory=set)
    out_of_order_count: int = 0
    duplicate_count: int = 0


class SchemaValidator:
    """
    Validates messages against JSON schemas.

    Features:
    - Uses jsonschema library with Draft-07 when available
    - Graceful fallback to basic validation when jsonschema not installed
    - Configurable validation modes (warning, strict, silent)
    - Collects multiple validation errors
    - Schema caching for performance
    """

    def __init__(self, mode: ValidationMode = ValidationMode.WARNING):
        """
        Initialize schema validator.

        Args:
            mode: Validation mode (WARNING, STRICT, or SILENT)
        """
        self.mode = mode
        self._schemas: Dict[str, dict] = {}
        self._validators: Dict[str, Any] = {}  # Cache compiled validators
        self._load_standard_schemas()
        self._load_custom_schemas()

    @property
    def strict_mode(self) -> bool:
        """Backwards compatibility property."""
        return self.mode == ValidationMode.STRICT

    @strict_mode.setter
    def strict_mode(self, value: bool) -> None:
        """Backwards compatibility setter."""
        self.mode = ValidationMode.STRICT if value else ValidationMode.WARNING

    def _load_standard_schemas(self) -> None:
        """Load built-in standard schemas."""
        for schema_id, schema in STANDARD_SCHEMAS.items():
            self._schemas[schema_id] = schema
            self._cache_validator(schema_id, schema)
        logger.debug(f"Loaded {len(STANDARD_SCHEMAS)} standard schemas")

    def _load_custom_schemas(self) -> None:
        """Load custom schemas from disk."""
        if not SCHEMAS_DIR.exists():
            SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)
            return

        for schema_file in SCHEMAS_DIR.glob("**/*.json"):
            try:
                with open(schema_file, 'r') as f:
                    schema = json.load(f)

                # Derive schema ID from path
                relative_path = schema_file.relative_to(SCHEMAS_DIR)
                schema_id = str(relative_path).replace('/', '.').replace('.json', '')

                # Or use $id from schema if present
                if "$id" in schema:
                    schema_id = schema["$id"]

                self._schemas[schema_id] = schema
                self._cache_validator(schema_id, schema)
                logger.debug(f"Loaded custom schema: {schema_id}")

            except Exception as e:
                logger.warning(f"Failed to load schema {schema_file}: {e}")

    def _cache_validator(self, schema_id: str, schema: dict) -> None:
        """Cache a compiled validator for performance."""
        if JSONSCHEMA_AVAILABLE:
            try:
                self._validators[schema_id] = Draft7Validator(schema)
            except Exception as e:
                logger.warning(f"Failed to compile validator for {schema_id}: {e}")

    def register_schema(self, schema_id: str, schema: dict, persist: bool = True) -> None:
        """
        Register a custom schema.

        Args:
            schema_id: Unique identifier for the schema
            schema: JSON Schema dictionary
            persist: If True, save to disk
        """
        self._schemas[schema_id] = schema
        self._cache_validator(schema_id, schema)

        if persist:
            # Save to disk
            schema_path = SCHEMAS_DIR / f"{schema_id.replace('/', '_')}.json"
            schema_path.parent.mkdir(parents=True, exist_ok=True)

            with open(schema_path, 'w') as f:
                json.dump(schema, f, indent=2)

        logger.info(f"Registered schema: {schema_id}")

    def get_schema(self, schema_id: str) -> Optional[dict]:
        """Get a schema by ID."""
        return self._schemas.get(schema_id)

    def list_schemas(self) -> List[str]:
        """List all available schema IDs."""
        return list(self._schemas.keys())

    def validate(self, schema_id: str, message: dict) -> ValidationResult:
        """
        Validate a message against a schema.

        Args:
            schema_id: ID of the schema to validate against
            message: Message data to validate

        Returns:
            ValidationResult with validation status and any errors/warnings
        """
        schema = self._schemas.get(schema_id)

        if not schema:
            # Unknown schema - just warn, don't reject
            if self.mode != ValidationMode.SILENT:
                logger.warning(f"Unknown schema: {schema_id}")
            return ValidationResult(
                valid=True,
                warnings=[f"Unknown schema: {schema_id}"],
                schema_id=schema_id,
            )

        # Use jsonschema library if available
        if JSONSCHEMA_AVAILABLE:
            return self._validate_with_jsonschema(schema_id, schema, message)
        else:
            return self._validate_fallback(schema_id, schema, message)

    def _validate_with_jsonschema(
        self,
        schema_id: str,
        schema: dict,
        message: dict,
    ) -> ValidationResult:
        """Validate using jsonschema library."""
        errors = []

        try:
            # Use cached validator if available
            validator = self._validators.get(schema_id)
            if validator is None:
                validator = Draft7Validator(schema)
                self._validators[schema_id] = validator

            # Collect all errors (not just the first)
            for error in validator.iter_errors(message):
                path = "/" + "/".join(str(p) for p in error.absolute_path) if error.absolute_path else "/"
                schema_path = "/" + "/".join(str(p) for p in error.absolute_schema_path) if error.absolute_schema_path else "/"

                errors.append(ValidationError(
                    path=path,
                    message=error.message,
                    schema_id=schema_id,
                    schema_path=schema_path,
                ))

        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            return ValidationResult(
                valid=True,  # Don't reject on validation errors
                warnings=[f"Validation error: {str(e)}"],
                schema_id=schema_id,
            )

        return self._process_validation_result(errors, schema_id)

    def _validate_fallback(
        self,
        schema_id: str,
        schema: dict,
        message: dict,
    ) -> ValidationResult:
        """Fallback validation when jsonschema not installed."""
        errors = []
        warnings = []

        try:
            self._validate_against_schema(message, schema, "", errors, schema_id)
        except Exception as e:
            logger.error(f"Schema validation failed: {e}")
            return ValidationResult(
                valid=True,
                warnings=[f"Validation error: {str(e)}"],
                schema_id=schema_id,
            )

        return self._process_validation_result(errors, schema_id)

    def _process_validation_result(
        self,
        errors: List[ValidationError],
        schema_id: str,
    ) -> ValidationResult:
        """Process errors according to validation mode."""
        if not errors:
            return ValidationResult(valid=True, errors=[], warnings=[], schema_id=schema_id)

        if self.mode == ValidationMode.STRICT:
            return ValidationResult(
                valid=False,
                errors=errors,
                warnings=[],
                schema_id=schema_id,
            )
        elif self.mode == ValidationMode.WARNING:
            # Log warnings but don't reject
            for error in errors:
                logger.warning(f"Schema validation: {error}")
            return ValidationResult(
                valid=True,
                errors=[],
                warnings=[str(e) for e in errors],
                schema_id=schema_id,
            )
        else:  # SILENT
            return ValidationResult(
                valid=True,
                errors=[],
                warnings=[],
                schema_id=schema_id,
            )

    def _validate_against_schema(
        self,
        data: Any,
        schema: dict,
        path: str,
        errors: List[ValidationError],
        schema_id: str,
    ) -> None:
        """Recursively validate data against schema (fallback)."""
        schema_type = schema.get("type")

        if schema_type == "object":
            if not isinstance(data, dict):
                errors.append(ValidationError(
                    path=path or "/",
                    message=f"expected object, got {type(data).__name__}",
                    schema_id=schema_id,
                ))
                return

            # Check required properties
            for required in schema.get("required", []):
                if required not in data:
                    errors.append(ValidationError(
                        path=f"{path}/{required}",
                        message="required property missing",
                        schema_id=schema_id,
                    ))

            # Validate properties
            properties = schema.get("properties", {})
            for key, value in data.items():
                if key in properties:
                    self._validate_against_schema(
                        value,
                        properties[key],
                        f"{path}/{key}",
                        errors,
                        schema_id,
                    )

        elif schema_type == "array":
            if not isinstance(data, list):
                errors.append(ValidationError(
                    path=path or "/",
                    message=f"expected array, got {type(data).__name__}",
                    schema_id=schema_id,
                ))
                return

            items_schema = schema.get("items")
            if items_schema:
                for i, item in enumerate(data):
                    self._validate_against_schema(
                        item,
                        items_schema,
                        f"{path}/{i}",
                        errors,
                        schema_id,
                    )

        elif schema_type == "string":
            if not isinstance(data, str):
                errors.append(ValidationError(
                    path=path or "/",
                    message=f"expected string, got {type(data).__name__}",
                    schema_id=schema_id,
                ))

            # Check enum
            if "enum" in schema and data not in schema["enum"]:
                errors.append(ValidationError(
                    path=path or "/",
                    message=f"value must be one of {schema['enum']}",
                    schema_id=schema_id,
                ))

            # Check pattern
            if "pattern" in schema:
                import re
                if not re.match(schema["pattern"], str(data)):
                    errors.append(ValidationError(
                        path=path or "/",
                        message=f"value doesn't match pattern {schema['pattern']}",
                        schema_id=schema_id,
                    ))

        elif schema_type == "number" or schema_type == "integer":
            if not isinstance(data, (int, float)):
                errors.append(ValidationError(
                    path=path or "/",
                    message=f"expected number, got {type(data).__name__}",
                    schema_id=schema_id,
                ))
            else:
                if "minimum" in schema and data < schema["minimum"]:
                    errors.append(ValidationError(
                        path=path or "/",
                        message=f"value must be >= {schema['minimum']}",
                        schema_id=schema_id,
                    ))
                if "maximum" in schema and data > schema["maximum"]:
                    errors.append(ValidationError(
                        path=path or "/",
                        message=f"value must be <= {schema['maximum']}",
                        schema_id=schema_id,
                    ))

        elif schema_type == "boolean":
            if not isinstance(data, bool):
                errors.append(ValidationError(
                    path=path or "/",
                    message=f"expected boolean, got {type(data).__name__}",
                    schema_id=schema_id,
                ))


class SequenceTracker:
    """
    Tracks message sequence numbers per session.
    Detects out-of-order messages and duplicates.
    """

    def __init__(self):
        self._sessions: Dict[str, SequenceState] = {}

    def get_next_sequence(self, session_id: str) -> int:
        """Get the next sequence number to send."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SequenceState(session_id=session_id)

        state = self._sessions[session_id]
        state.last_sent += 1
        return state.last_sent

    def validate_sequence(
        self,
        session_id: str,
        sequence: int,
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a received sequence number.
        Returns (is_valid, warning_message).
        """
        if session_id not in self._sessions:
            self._sessions[session_id] = SequenceState(session_id=session_id)

        state = self._sessions[session_id]

        # Check for duplicate
        if sequence in state.received_sequences:
            state.duplicate_count += 1
            logger.warning(f"Duplicate sequence {sequence} in session {session_id[:16]}...")
            return False, f"Duplicate sequence number: {sequence}"

        # Check for out-of-order
        expected = state.last_received + 1
        if sequence != expected and state.last_received > 0:
            state.out_of_order_count += 1
            warning = f"Out-of-order: expected {expected}, got {sequence}"
            logger.warning(f"{warning} in session {session_id[:16]}...")
            # Don't reject, just warn
        else:
            warning = None

        # Update state
        state.received_sequences.add(sequence)
        if sequence > state.last_received:
            state.last_received = sequence

        return True, warning

    def get_stats(self, session_id: str) -> Dict[str, Any]:
        """Get sequence tracking stats for a session."""
        if session_id not in self._sessions:
            return {'error': 'Session not found'}

        state = self._sessions[session_id]
        return {
            'last_sent': state.last_sent,
            'last_received': state.last_received,
            'out_of_order_count': state.out_of_order_count,
            'duplicate_count': state.duplicate_count,
        }

    def clear_session(self, session_id: str) -> None:
        """Clear tracking state for a session."""
        self._sessions.pop(session_id, None)


@dataclass
class CapabilityNegotiationRequest:
    """Request to negotiate capabilities for a session."""
    message_type: str = "capability_negotiation_request"
    offered_schemas: List[str] = field(default_factory=list)
    offered_capabilities: List[str] = field(default_factory=list)
    protocol_version: str = "agentmesh/0.2"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CapabilityNegotiationRequest":
        return cls(
            message_type=data.get("message_type", "capability_negotiation_request"),
            offered_schemas=data.get("offered_schemas", []),
            offered_capabilities=data.get("offered_capabilities", []),
            protocol_version=data.get("protocol_version", "agentmesh/0.2"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class CapabilityNegotiationResponse:
    """Response to capability negotiation request."""
    message_type: str = "capability_negotiation_response"
    accepted_schemas: List[str] = field(default_factory=list)
    accepted_capabilities: List[str] = field(default_factory=list)
    rejected_schemas: List[str] = field(default_factory=list)
    rejected_capabilities: List[str] = field(default_factory=list)
    protocol_version: str = "agentmesh/0.2"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "CapabilityNegotiationResponse":
        return cls(
            message_type=data.get("message_type", "capability_negotiation_response"),
            accepted_schemas=data.get("accepted_schemas", []),
            accepted_capabilities=data.get("accepted_capabilities", []),
            rejected_schemas=data.get("rejected_schemas", []),
            rejected_capabilities=data.get("rejected_capabilities", []),
            protocol_version=data.get("protocol_version", "agentmesh/0.2"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
        )


class CapabilityNegotiator:
    """Handles capability negotiation between agents."""

    def __init__(self, supported_schemas: Optional[List[str]] = None):
        self.supported_schemas = supported_schemas or list(STANDARD_SCHEMAS.keys())
        self.supported_capabilities = ["text", "json", "binary"]

    def create_request(self) -> CapabilityNegotiationRequest:
        """Create a capability negotiation request."""
        return CapabilityNegotiationRequest(
            offered_schemas=self.supported_schemas,
            offered_capabilities=self.supported_capabilities,
        )

    def process_request(
        self,
        request: CapabilityNegotiationRequest,
    ) -> CapabilityNegotiationResponse:
        """Process a capability negotiation request and create response."""
        accepted_schemas = [
            s for s in request.offered_schemas
            if s in self.supported_schemas
        ]
        rejected_schemas = [
            s for s in request.offered_schemas
            if s not in self.supported_schemas
        ]

        accepted_capabilities = [
            c for c in request.offered_capabilities
            if c in self.supported_capabilities
        ]
        rejected_capabilities = [
            c for c in request.offered_capabilities
            if c not in self.supported_capabilities
        ]

        return CapabilityNegotiationResponse(
            accepted_schemas=accepted_schemas,
            accepted_capabilities=accepted_capabilities,
            rejected_schemas=rejected_schemas,
            rejected_capabilities=rejected_capabilities,
        )

    def process_response(
        self,
        response: CapabilityNegotiationResponse,
    ) -> Dict[str, List[str]]:
        """Process a capability negotiation response."""
        return {
            'accepted_schemas': response.accepted_schemas,
            'accepted_capabilities': response.accepted_capabilities,
            'rejected_schemas': response.rejected_schemas,
            'rejected_capabilities': response.rejected_capabilities,
        }


def ensure_schemas_directory() -> Path:
    """Ensure the schemas directory exists."""
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)
    return SCHEMAS_DIR
