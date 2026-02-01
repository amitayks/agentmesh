## MODIFIED Requirements

### Requirement: Capability negotiation in session flow
Capability negotiation SHALL be integrated into the KNOCK/ACCEPT session establishment flow.

#### Scenario: Capabilities negotiated in KNOCK
- **WHEN** a KNOCK message is sent
- **THEN** it SHALL include an optional "offered_capabilities" field
- **AND** list schemas and message types the initiator supports

#### Scenario: Capabilities accepted in ACCEPT
- **WHEN** an ACCEPT message is sent
- **THEN** it SHALL include "accepted_capabilities" and "rejected_capabilities" fields
- **AND** indicate which offered capabilities are supported

### Requirement: Automatic capability negotiation
The system SHALL automatically negotiate capabilities without manual intervention.

#### Scenario: Common capabilities selected
- **WHEN** both agents support multiple schemas
- **THEN** the system SHALL automatically select the highest version of each shared schema

#### Scenario: No common capabilities warning
- **WHEN** no common capabilities exist
- **THEN** the system SHALL log a warning
- **AND** the session SHALL continue with raw message format

### Requirement: Capability negotiation message types
The system SHALL support explicit capability negotiation messages.

#### Scenario: Capability request sent
- **WHEN** session requires capability confirmation
- **THEN** a CAPABILITY_REQUEST message SHALL be sent
- **AND** include: offered_schemas[], offered_capabilities[], protocol_version

#### Scenario: Capability response received
- **WHEN** a CAPABILITY_REQUEST is received
- **THEN** a CAPABILITY_RESPONSE SHALL be sent
- **AND** include: accepted_schemas[], accepted_capabilities[], rejected_schemas[], rejected_capabilities[]

### Requirement: Dynamic capability update
The system SHALL allow capability updates during an active session.

#### Scenario: New capability added mid-session
- **WHEN** an agent gains a new capability during a session
- **THEN** it MAY send a CAPABILITY_UPDATE message
- **AND** the peer SHALL acknowledge or reject the new capability

### Requirement: Capability mismatch handling
The system SHALL handle capability mismatches gracefully.

#### Scenario: Required capability not supported
- **WHEN** a required capability is not supported by the peer
- **THEN** the system SHALL include error details in the response
- **AND** suggest fallback capabilities if available

#### Scenario: Version mismatch negotiation
- **WHEN** schema versions differ between agents
- **THEN** the system SHALL negotiate to the lowest common version
- **AND** warn if the negotiated version lacks features
