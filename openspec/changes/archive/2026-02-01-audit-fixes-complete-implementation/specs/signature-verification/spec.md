## ADDED Requirements

### Requirement: Relay MUST verify CONNECT signature
The relay server SHALL verify the Ed25519 signature in every CONNECT message before accepting the connection. The signature MUST be over the timestamp in ISO 8601 format. The relay SHALL reject connections where:
- Signature is invalid or missing
- Timestamp is more than 5 minutes old
- Timestamp is more than 1 minute in the future
- Derived AMID from public_key does not match claimed AMID

#### Scenario: Valid signature accepted
- **WHEN** client sends CONNECT with valid signature, public_key, and fresh timestamp
- **THEN** relay accepts connection and returns CONNECTED message with session_id

#### Scenario: Invalid signature rejected
- **WHEN** client sends CONNECT with signature that does not verify against public_key
- **THEN** relay returns ERROR with code "invalid_signature" and closes connection

#### Scenario: Expired timestamp rejected
- **WHEN** client sends CONNECT with timestamp older than 5 minutes
- **THEN** relay returns ERROR with code "timestamp_expired" and closes connection

#### Scenario: AMID mismatch rejected
- **WHEN** client sends CONNECT where sha256(public_key)[:20] does not equal claimed AMID
- **THEN** relay returns ERROR with code "amid_mismatch" and closes connection

### Requirement: CONNECT message MUST include public_key
The CONNECT message format SHALL require a `public_key` field containing the base64-encoded Ed25519 signing public key. This is a BREAKING CHANGE from protocol version 0.1.

#### Scenario: Protocol version upgrade
- **WHEN** client sends CONNECT with protocol "agentmesh/0.2"
- **THEN** relay MUST require public_key field

#### Scenario: Legacy protocol rejection
- **WHEN** client sends CONNECT with protocol "agentmesh/0.1" (no public_key)
- **THEN** relay returns ERROR with code "protocol_upgrade_required" and message explaining v0.2 requirement

### Requirement: Registry MUST verify registration signature
The registry API SHALL verify signatures on all mutation endpoints (register, status update, capabilities update, reputation submit). Each request MUST include timestamp and signature fields.

#### Scenario: Valid registration accepted
- **WHEN** agent sends POST /v1/registry/register with valid signature over timestamp
- **THEN** registry creates agent record and returns success

#### Scenario: Unsigned registration rejected
- **WHEN** agent sends POST /v1/registry/register without signature
- **THEN** registry returns 401 Unauthorized with error "signature_required"

#### Scenario: AMID derivation verified
- **WHEN** agent sends registration with AMID that does not derive from signing_public_key
- **THEN** registry returns 400 Bad Request with error "amid_mismatch"

### Requirement: Client MUST verify KNOCK signature
The AgentMesh client SHALL verify the Ed25519 signature on incoming KNOCK messages before performing policy evaluation. Invalid signatures SHALL be silently dropped (no REJECT response to prevent oracle attacks).

#### Scenario: Valid KNOCK processed
- **WHEN** client receives KNOCK with valid signature from sender's public key
- **THEN** client proceeds with policy evaluation (KnockEvaluator)

#### Scenario: Invalid KNOCK dropped
- **WHEN** client receives KNOCK with invalid or missing signature
- **THEN** client silently drops message without sending REJECT

#### Scenario: Public key lookup for verification
- **WHEN** client receives KNOCK from unknown AMID
- **THEN** client fetches sender's public key from registry before verification

### Requirement: ACCEPT and REJECT messages MUST be signed
The session ACCEPT and REJECT response messages SHALL be signed by the responder. Initiators MUST verify these signatures before processing.

#### Scenario: Signed ACCEPT verified
- **WHEN** client receives ACCEPT message with valid signature
- **THEN** client establishes session with provided session_key

#### Scenario: Unsigned ACCEPT rejected
- **WHEN** client receives ACCEPT without valid signature
- **THEN** client discards message and logs security warning

### Requirement: Relay MUST implement server-side ping
The relay server SHALL send WebSocket ping frames every 25 seconds to maintain connection liveness. Clients that do not respond with pong within 10 seconds SHALL be disconnected.

#### Scenario: Keepalive maintains connection
- **WHEN** agent is connected but idle for 30 seconds
- **THEN** relay has sent at least one ping and connection remains active

#### Scenario: Unresponsive client disconnected
- **WHEN** client does not respond to ping within 10 seconds
- **THEN** relay closes connection and unregisters agent
