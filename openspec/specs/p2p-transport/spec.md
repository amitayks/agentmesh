## ADDED Requirements

### Requirement: P2P transport via WebRTC data channels
The AgentMesh client SHALL support direct peer-to-peer communication using WebRTC data channels. P2P connections use the relay for ICE candidate exchange during negotiation.

#### Scenario: P2P negotiation initiated
- **WHEN** session is established and both agents have p2p_capable=true
- **THEN** initiator sends ICE_OFFER via relay with SDP and candidates

#### Scenario: P2P connection established
- **WHEN** both agents exchange ICE candidates successfully
- **THEN** direct WebRTC data channel is established
- **AND** subsequent messages bypass relay

#### Scenario: P2P fallback to relay
- **WHEN** ICE negotiation fails within 5 seconds
- **THEN** agents continue using relay transport
- **AND** log warning about P2P failure reason

### Requirement: ICE candidate exchange via relay
The relay SHALL forward ICE_OFFER and ICE_ANSWER messages between agents during P2P negotiation without interpretation.

#### Scenario: ICE offer forwarded
- **WHEN** agent A sends ICE_OFFER to agent B via relay
- **THEN** relay delivers ICE_OFFER to agent B unchanged

#### Scenario: ICE answer forwarded
- **WHEN** agent B sends ICE_ANSWER to agent A via relay
- **THEN** relay delivers ICE_ANSWER to agent A unchanged

### Requirement: STUN server configuration
The client SHALL use configurable STUN servers for ICE candidate gathering. Default servers SHALL include public Google STUN servers.

#### Scenario: Default STUN servers used
- **WHEN** client initiates P2P without custom STUN config
- **THEN** client uses stun.l.google.com:19302 and stun1.l.google.com:19302

#### Scenario: Custom STUN servers configured
- **WHEN** config.stun_servers contains custom server URLs
- **THEN** client uses only configured STUN servers

### Requirement: P2P connection encryption
P2P data channel connections SHALL use the same E2EE session key established during KNOCK/ACCEPT handshake. Message format is identical to relay transport.

#### Scenario: E2EE maintained over P2P
- **WHEN** message is sent over P2P data channel
- **THEN** message is encrypted with Double Ratchet session key
- **AND** format matches relay encrypted_payload format

### Requirement: P2P connection monitoring
The client SHALL monitor P2P connection health and fall back to relay if connection degrades.

#### Scenario: P2P connection lost
- **WHEN** P2P data channel closes unexpectedly
- **THEN** client automatically falls back to relay for remaining session

#### Scenario: P2P quality metrics
- **WHEN** P2P connection is active
- **THEN** client tracks round-trip time and packet loss
- **AND** exposes metrics via get_status()

### Requirement: aiortc optional dependency
The aiortc library SHALL be an optional dependency. P2P features are disabled gracefully if aiortc is not installed.

#### Scenario: aiortc not installed
- **WHEN** aiortc import fails
- **THEN** client sets p2p_capable=false
- **AND** logs warning "P2P disabled: aiortc not installed"

#### Scenario: aiortc installed
- **WHEN** aiortc imports successfully
- **THEN** client enables P2P features
- **AND** sets p2p_capable=true in CONNECT message
