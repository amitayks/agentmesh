## ADDED Requirements

### Requirement: Double Ratchet protocol implementation
The system SHALL implement the Signal Protocol Double Ratchet for message encryption with forward secrecy.

#### Scenario: New message uses new message key
- **WHEN** a message is sent in an active session
- **THEN** the system SHALL derive a unique message key from the chain key
- **AND** the chain key SHALL be ratcheted forward
- **AND** the previous chain key SHALL be deleted

#### Scenario: DH ratchet on receiving message
- **WHEN** a message is received with a new ratchet public key
- **THEN** the system SHALL perform a DH ratchet step
- **AND** derive new root key and chain keys

### Requirement: python-olm integration
The system SHALL use python-olm library when available for Double Ratchet implementation.

#### Scenario: olm library available
- **WHEN** python-olm is installed
- **THEN** the system SHALL use olm.Session for Double Ratchet operations
- **AND** log "Using python-olm for Double Ratchet"

#### Scenario: olm library not available
- **WHEN** python-olm is not installed
- **THEN** the system SHALL fall back to X3DH-only mode with session key rotation
- **AND** log a warning "python-olm not available, using simplified key rotation"

### Requirement: Message key derivation
The system SHALL derive unique message keys using HKDF from the chain key.

#### Scenario: Message key derived correctly
- **WHEN** encrypting a message
- **THEN** the message key SHALL be derived as: HKDF(chain_key, info="message_key", length=32)
- **AND** the nonce SHALL be derived from the message sequence number

#### Scenario: Same plaintext produces different ciphertext
- **WHEN** the same plaintext is sent twice in a session
- **THEN** the ciphertext SHALL be different each time due to unique message keys

### Requirement: Ratchet state persistence
The system SHALL persist ratchet state to allow session resumption.

#### Scenario: Session resumes after restart
- **WHEN** the agent restarts
- **AND** a previously established session exists
- **THEN** the system SHALL load the ratchet state from disk
- **AND** messages SHALL decrypt correctly

#### Scenario: Ratchet state stored securely
- **WHEN** ratchet state is persisted
- **THEN** it SHALL be encrypted with the owner's signing key
- **AND** stored in ~/.agentmesh/sessions/<peer_amid>/ratchet.enc

### Requirement: Out-of-order message handling
The system SHALL handle out-of-order messages by storing skipped message keys.

#### Scenario: Message received out of order
- **WHEN** message with sequence N+2 is received before sequence N+1
- **THEN** the system SHALL derive and store the skipped message key for N+1
- **AND** decrypt message N+2 successfully

#### Scenario: Skipped message limit
- **WHEN** more than 1000 message keys would be skipped
- **THEN** the system SHALL reject the message
- **AND** close the session with reason "excessive_skip"

### Requirement: Forward secrecy verification
Compromising current keys SHALL NOT reveal past message content.

#### Scenario: Past messages remain secure
- **WHEN** an attacker obtains the current chain key
- **THEN** they SHALL NOT be able to decrypt messages from previous ratchet epochs
- **AND** previously derived message keys SHALL have been deleted

### Requirement: X3DH initialization of Double Ratchet
The Double Ratchet SHALL be initialized with the shared secret from X3DH.

#### Scenario: Initiator initializes ratchet
- **WHEN** the initiator receives ACCEPT with session_key
- **THEN** the system SHALL initialize the sending chain with the X3DH shared secret
- **AND** set the receiver's ratchet public key

#### Scenario: Responder initializes ratchet
- **WHEN** the responder sends ACCEPT
- **THEN** the system SHALL initialize the receiving chain with the X3DH shared secret
- **AND** generate a new ratchet keypair for the first DH ratchet
