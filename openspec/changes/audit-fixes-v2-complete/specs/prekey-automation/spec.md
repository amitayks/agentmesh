## ADDED Requirements

### Requirement: Automatic prekey count monitoring
The system SHALL monitor one-time prekey count and replenish when below threshold.

#### Scenario: Prekey count checked on startup
- **WHEN** the agent connects to the network
- **THEN** the system SHALL query the registry for current prekey count
- **AND** trigger replenishment if count is below 20

#### Scenario: Prekey count checked periodically
- **WHEN** the agent is running
- **THEN** the system SHALL check prekey count every 6 hours

#### Scenario: Replenishment triggered below threshold
- **WHEN** prekey count falls below 20
- **THEN** the system SHALL generate enough prekeys to reach 100
- **AND** upload them to the registry

### Requirement: One-time prekey generation
The system SHALL generate batches of signed one-time prekeys.

#### Scenario: Prekey batch generation
- **WHEN** replenishment is triggered
- **THEN** the system SHALL generate (100 - current_count) new prekeys
- **AND** each prekey SHALL have a unique ID

#### Scenario: Prekey IDs are sequential
- **WHEN** generating new prekeys
- **THEN** the system SHALL assign IDs starting from (max_existing_id + 1)
- **AND** store the last used ID in ~/.agentmesh/prekey_counter

### Requirement: Signed prekey rotation
The system SHALL rotate the signed prekey every 7 days.

#### Scenario: Signed prekey rotation timer
- **WHEN** the signed prekey is older than 7 days
- **THEN** the system SHALL generate a new signed prekey
- **AND** upload it to the registry
- **AND** keep the old signed prekey valid for 24 hours (grace period)

#### Scenario: Signed prekey rotation on startup
- **WHEN** the agent starts
- **AND** the signed prekey is older than 7 days
- **THEN** rotation SHALL occur immediately

### Requirement: Prekey upload to registry
The system SHALL upload prekeys to the registry with proper signing.

#### Scenario: Prekey upload succeeds
- **WHEN** prekeys are uploaded via POST /v1/registry/prekeys
- **THEN** the request SHALL include: amid, signed_prekey, signed_prekey_signature, one_time_prekeys[], timestamp, signature

#### Scenario: Prekey upload failure retry
- **WHEN** prekey upload fails
- **THEN** the system SHALL retry with exponential backoff (1s, 2s, 4s, 8s, max 60s)
- **AND** log warning on each failure

### Requirement: Prekey consumption notification
The system SHALL be notified when prekeys are running low via registry.

#### Scenario: Low prekey warning from registry
- **WHEN** the registry detects prekey count below 10
- **AND** the agent is connected
- **THEN** the registry SHALL send a low_prekeys notification
- **AND** the agent SHALL trigger immediate replenishment

### Requirement: Prekey storage location
The system SHALL store prekey metadata locally for tracking.

#### Scenario: Prekey metadata stored
- **WHEN** prekeys are generated
- **THEN** metadata SHALL be stored in ~/.agentmesh/prekeys/
- **AND** include: prekey_id, created_at, uploaded_at, consumed (bool)

#### Scenario: Consumed prekeys tracked
- **WHEN** a prekey is consumed (used in X3DH by peer)
- **AND** the system learns of consumption (via registry)
- **THEN** the local metadata SHALL be updated with consumed: true
