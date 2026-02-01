## ADDED Requirements

### Requirement: jsonschema library integration
The system SHALL use the jsonschema library for message validation.

#### Scenario: jsonschema validates messages
- **WHEN** a message is received
- **THEN** the system SHALL validate it against the declared schema using jsonschema.validate()
- **AND** use Draft-07 schema specification

#### Scenario: jsonschema not installed fallback
- **WHEN** jsonschema library is not installed
- **THEN** the system SHALL fall back to basic type checking
- **AND** log warning "jsonschema not installed, using basic validation"

### Requirement: Schema validation mode configuration
The system SHALL support configurable validation modes.

#### Scenario: Warning mode (default)
- **WHEN** validation_mode is "warning" (default)
- **AND** a message fails schema validation
- **THEN** the system SHALL log a warning with validation errors
- **AND** process the message anyway

#### Scenario: Strict mode
- **WHEN** validation_mode is "strict"
- **AND** a message fails schema validation
- **THEN** the system SHALL reject the message
- **AND** return an error to the sender

#### Scenario: Silent mode
- **WHEN** validation_mode is "silent"
- **AND** a message fails schema validation
- **THEN** the system SHALL process the message without logging

### Requirement: Schema registry
The system SHALL maintain a registry of known schemas.

#### Scenario: Standard schemas pre-loaded
- **WHEN** the system starts
- **THEN** the following schemas SHALL be available:
  - agentmesh/travel/flight-search/v1
  - agentmesh/commerce/product-search/v1
  - agentmesh/marketplace/skill-bid/v1

#### Scenario: Custom schema registration
- **WHEN** register_schema(schema_id, schema) is called
- **THEN** the schema SHALL be added to the registry
- **AND** saved to ~/.agentmesh/schemas/<schema_id>.json

### Requirement: Schema-based message structure
Messages SHALL declare their schema for validation.

#### Scenario: Message includes schema field
- **WHEN** a structured message is sent
- **THEN** it SHALL include a "schema" field with the schema ID

#### Scenario: Unknown schema handled gracefully
- **WHEN** a message references an unknown schema
- **THEN** validation SHALL be skipped with a warning
- **AND** the message SHALL be processed

### Requirement: Validation error details
The system SHALL provide detailed validation error information.

#### Scenario: Validation error includes path
- **WHEN** a validation error occurs
- **THEN** the error SHALL include: path (JSON pointer to failed field), message, schema_id

#### Scenario: Multiple errors collected
- **WHEN** a message has multiple validation errors
- **THEN** all errors SHALL be collected and reported (not just the first)

### Requirement: Schema caching
The system SHALL cache parsed schemas for performance.

#### Scenario: Schema parsed once
- **WHEN** the same schema is used for multiple messages
- **THEN** the schema SHALL be parsed only once
- **AND** the parsed schema SHALL be reused from cache

#### Scenario: Schema cache invalidation
- **WHEN** a schema file is updated
- **THEN** the cache SHALL be invalidated on next validation
