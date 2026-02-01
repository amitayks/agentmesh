## ADDED Requirements

### Requirement: Session key storage location
The system SHALL store session keys in ~/.agentmesh/sessions/<peer_amid>/<session_id>.json.

#### Scenario: Session key file created on session establishment
- **WHEN** a session is successfully established (ACCEPT received/sent)
- **THEN** the system SHALL create a session key file at the specified path
- **AND** set file permissions to 0600 (owner read/write only)

#### Scenario: Directory structure created automatically
- **WHEN** the first session with a peer is established
- **THEN** the system SHALL create the ~/.agentmesh/sessions/<peer_amid>/ directory
- **AND** set directory permissions to 0700

### Requirement: Session key encryption at rest
The system SHALL encrypt session key files using the owner's signing key.

#### Scenario: Session key file is encrypted
- **WHEN** a session key file is written
- **THEN** the content SHALL be encrypted with XChaCha20-Poly1305
- **AND** the encryption key SHALL be derived from the owner's signing key using HKDF

#### Scenario: Encrypted file format includes version
- **WHEN** reading a session key file
- **THEN** the first byte SHALL indicate the encryption version
- **AND** the system SHALL support reading version 1 files

### Requirement: Session key file format
The system SHALL store session data in a structured JSON format.

#### Scenario: Session file contains required fields
- **WHEN** a session key file is written
- **THEN** it SHALL contain: session_id, peer_amid, session_key (encrypted), created_at, last_used, message_count

#### Scenario: Chain keys stored for Double Ratchet
- **WHEN** Double Ratchet is active
- **THEN** the session file SHALL also contain: root_key, sending_chain_key, receiving_chain_key, ratchet_public_key

### Requirement: Session loading on startup
The system SHALL load existing sessions from disk on startup.

#### Scenario: Sessions restored after restart
- **WHEN** the agent starts
- **THEN** the system SHALL scan ~/.agentmesh/sessions/ for session files
- **AND** load valid, unexpired sessions into memory

#### Scenario: Corrupted session file handled gracefully
- **WHEN** a session file fails to decrypt or parse
- **THEN** the system SHALL log a warning
- **AND** skip that session (requiring new KNOCK to re-establish)

### Requirement: Session last_used update
The system SHALL update the last_used timestamp when a session is used.

#### Scenario: last_used updated on message send
- **WHEN** a message is sent in a session
- **THEN** the session file's last_used field SHALL be updated

#### Scenario: last_used updated on message receive
- **WHEN** a message is received in a session
- **THEN** the session file's last_used field SHALL be updated

### Requirement: Session cleanup
The system SHALL clean up old session files.

#### Scenario: Inactive sessions deleted after 7 days
- **WHEN** a session file's last_used is older than 7 days
- **THEN** the system SHALL securely delete the file on next cleanup run

#### Scenario: Session cleanup runs periodically
- **WHEN** the agent is running
- **THEN** session cleanup SHALL run every 6 hours
- **AND** on startup

#### Scenario: Secure deletion of session files
- **WHEN** a session file is deleted
- **THEN** the system SHALL overwrite the file with random data before unlinking
- **AND** log "Securely deleted session: <session_id>"

### Requirement: Session resumption
The system SHALL resume sessions from persisted state rather than requiring new KNOCK.

#### Scenario: Cached session resumes after restart
- **WHEN** both agents restart
- **AND** the session file exists and is valid on both sides
- **THEN** messages SHALL be exchanged without a new KNOCK handshake

#### Scenario: Session mismatch requires new KNOCK
- **WHEN** one agent's session file is missing or corrupt
- **AND** the other agent attempts to send a message
- **THEN** the recipient SHALL respond with session_not_found error
- **AND** a new KNOCK handshake SHALL be required
