## ADDED Requirements

### Requirement: Key format with type prefix
Public key fields SHALL include type prefix: `ed25519:<base64>` for signing keys and `x25519:<base64>` for exchange keys. Readers SHALL accept keys with or without prefix for backwards compatibility.

#### Scenario: Key written with prefix
- **WHEN** identity is saved to file
- **THEN** signing_public_key is formatted as "ed25519:<base64>"
- **AND** exchange_public_key is formatted as "x25519:<base64>"

#### Scenario: Key read without prefix (backwards compat)
- **WHEN** identity file contains keys without prefix
- **THEN** client loads keys successfully
- **AND** logs deprecation warning

### Requirement: Standard schema definitions
AgentMesh SHALL define standard JSON schemas for common interaction patterns stored at ~/.agentmesh/schemas/.

#### Scenario: Travel flight search schema
- **WHEN** agent sends intent travel/flights/search
- **THEN** payload is validated against agentmesh/travel/flight-search/v1 schema

#### Scenario: Commerce product search schema
- **WHEN** agent sends intent commerce/products/search
- **THEN** payload is validated against agentmesh/commerce/product-search/v1 schema

#### Scenario: Marketplace skill bid schema
- **WHEN** agent sends intent marketplace/skill-bid
- **THEN** payload is validated against agentmesh/marketplace/skill-bid/v1 schema

### Requirement: Schema validation on message receive
Client SHALL validate incoming message payloads against declared schema. Invalid payloads SHALL be logged but not rejected (warn, not error).

#### Scenario: Valid schema accepted
- **WHEN** message declares schema and payload matches
- **THEN** message is processed normally

#### Scenario: Invalid schema warned
- **WHEN** message declares schema but payload does not match
- **THEN** client logs validation warning
- **AND** message is still processed (graceful degradation)

#### Scenario: No schema declared
- **WHEN** message does not declare a schema
- **THEN** no validation is performed

### Requirement: Custom schema support
Custom schemas SHALL use format `x-<namespace>/<schema>/v<n>`. These are not validated by default but can be registered.

#### Scenario: Custom schema declared
- **WHEN** message uses schema "x-mycompany/invoice/v1"
- **THEN** client accepts without validation (no built-in schema)

#### Scenario: Custom schema registered
- **WHEN** user registers custom schema file
- **THEN** messages with that schema are validated

### Requirement: Message envelope sequence enforcement
Message envelopes SHALL include sequence numbers. Receivers SHALL validate sequence continuity within sessions.

#### Scenario: Sequence numbers increment
- **WHEN** agent sends multiple messages in session
- **THEN** sequence numbers are 0, 1, 2, ...

#### Scenario: Out-of-order detected
- **WHEN** receiver gets message with sequence gap
- **THEN** receiver logs warning "sequence gap detected"
- **AND** message is still processed

#### Scenario: Duplicate sequence rejected
- **WHEN** receiver gets message with already-seen sequence
- **THEN** message is dropped as duplicate
- **AND** warning is logged

### Requirement: Capability negotiation protocol
Agents SHALL support capability negotiation at session start to agree on schemas, languages, and payment methods.

#### Scenario: Negotiation request sent
- **WHEN** session is established
- **THEN** agents MAY exchange capability_negotiation messages

#### Scenario: Negotiation response
- **WHEN** agent receives capability_negotiation
- **THEN** agent responds with capability_negotiation_response
- **AND** response indicates matched, unavailable, and suggested_alternative

### Requirement: Standard payload types
Message payloads SHALL conform to defined types: REQUEST, RESPONSE, STATUS, ERROR, CLOSE.

#### Scenario: REQUEST payload structure
- **WHEN** agent sends request
- **THEN** payload contains intent, parameters, optional budget, and response_format

#### Scenario: RESPONSE payload structure
- **WHEN** agent sends response
- **THEN** payload contains status, results, and schema

#### Scenario: STATUS payload structure
- **WHEN** agent sends status update
- **THEN** payload contains status, progress, estimated_completion_seconds, and message

#### Scenario: ERROR payload structure
- **WHEN** agent sends error
- **THEN** payload contains code, message, optional retry_after_seconds, and optional fallback_amid

#### Scenario: CLOSE payload structure
- **WHEN** agent closes session
- **THEN** payload contains reason, optional summary, and optional reputation_feedback
