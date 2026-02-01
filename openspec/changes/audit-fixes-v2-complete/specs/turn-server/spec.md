## ADDED Requirements

### Requirement: TURN server configuration
The system SHALL support configurable TURN server credentials for NAT traversal fallback when STUN fails.

#### Scenario: TURN servers configured via environment
- **WHEN** TURN_SERVER_URL, TURN_USERNAME, and TURN_CREDENTIAL environment variables are set
- **THEN** the system SHALL use these credentials for ICE negotiation

#### Scenario: Multiple TURN servers supported
- **WHEN** multiple TURN servers are configured in config
- **THEN** the system SHALL try each server in order until one succeeds

### Requirement: TURN fallback after STUN failure
The system SHALL automatically fall back to TURN relay when direct STUN-based connection fails.

#### Scenario: STUN connection fails, TURN succeeds
- **WHEN** P2P connection attempt via STUN fails within 5 seconds
- **AND** TURN servers are configured
- **THEN** the system SHALL attempt connection via TURN relay

#### Scenario: TURN not configured, relay fallback
- **WHEN** P2P connection fails
- **AND** no TURN servers are configured
- **THEN** the system SHALL fall back to WebSocket relay

### Requirement: ICE candidate gathering includes TURN
The system SHALL gather TURN relay candidates in addition to STUN candidates during ICE negotiation.

#### Scenario: ICE candidates include relay type
- **WHEN** ICE candidate gathering begins
- **AND** TURN servers are configured
- **THEN** the gathered candidates SHALL include candidates of type "relay"

### Requirement: TURN credentials refresh
The system SHALL support time-limited TURN credentials that can be refreshed.

#### Scenario: Credentials expired during session
- **WHEN** TURN credentials expire during an active P2P session
- **THEN** the system SHALL request new credentials and re-establish connection
- **AND** the session SHALL continue without message loss
