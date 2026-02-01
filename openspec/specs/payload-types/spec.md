## MODIFIED Requirements

### Requirement: STATUS payload structure
STATUS payloads SHALL follow a formal structure.

#### Scenario: STATUS payload includes required fields
- **WHEN** a STATUS message is sent
- **THEN** it SHALL include: progress (0.0-1.0), estimated_completion_seconds, message (optional), phase (optional)

#### Scenario: STATUS progress validated
- **WHEN** a STATUS message is received
- **THEN** the progress field SHALL be validated to be between 0.0 and 1.0

### Requirement: ERROR payload structure
ERROR payloads SHALL follow a formal structure.

#### Scenario: ERROR payload includes required fields
- **WHEN** an ERROR message is sent
- **THEN** it SHALL include: code (string), message (string), retry_after_seconds (optional), fallback_amid (optional), details (optional object)

#### Scenario: Standard error codes defined
- **WHEN** an ERROR is generated
- **THEN** the code SHALL be one of:
  - "invalid_request", "unauthorized", "forbidden", "not_found"
  - "rate_limited", "timeout", "internal_error", "service_unavailable"
  - "session_expired", "capability_mismatch", "schema_validation_failed"

### Requirement: CLOSE payload structure
CLOSE payloads SHALL follow a formal structure.

#### Scenario: CLOSE payload includes required fields
- **WHEN** a CLOSE message is sent
- **THEN** it SHALL include: reason (string), summary (optional string), reputation_feedback (optional object)

#### Scenario: CLOSE reason codes defined
- **WHEN** a session is closed
- **THEN** the reason SHALL be one of:
  - "completed", "cancelled", "timeout", "error"
  - "policy_violation", "rate_limited", "user_requested"

### Requirement: REQUEST payload enhancements
REQUEST payloads SHALL include additional metadata.

#### Scenario: REQUEST includes priority
- **WHEN** a REQUEST message is sent
- **THEN** it MAY include a "priority" field with values: "low", "normal", "high", "urgent"

#### Scenario: REQUEST includes budget
- **WHEN** a REQUEST message is sent
- **THEN** it MAY include a "budget" object with: amount (number), currency (string), max_cost (boolean)

### Requirement: RESPONSE payload enhancements
RESPONSE payloads SHALL include additional metadata.

#### Scenario: RESPONSE includes timing
- **WHEN** a RESPONSE message is sent
- **THEN** it SHALL include: processing_time_ms (number), completed_at (ISO timestamp)

#### Scenario: RESPONSE includes schema
- **WHEN** a RESPONSE message is sent with structured data
- **THEN** it SHALL include a "schema" field referencing the response schema

### Requirement: Payload type validation
All payload types SHALL be validated against their schemas.

#### Scenario: Unknown payload type handled
- **WHEN** a message with an unknown payload type is received
- **THEN** the system SHALL log a warning
- **AND** attempt to process it as a generic message

#### Scenario: Payload type in envelope
- **WHEN** a message is sent
- **THEN** the envelope "type" field SHALL indicate the payload type
- **AND** match one of: "request", "response", "status", "error", "close", "capability_request", "capability_response"
