## ADDED Requirements

### Requirement: Transcripts encrypted at rest
Conversation transcripts stored at ~/.agentmesh/transcripts/ SHALL be encrypted using XChaCha20-Poly1305. Encryption key is derived from owner's signing key.

#### Scenario: Transcript saved encrypted
- **WHEN** session closes with store_transcripts=true
- **THEN** transcript is encrypted before writing to disk
- **AND** file contains only ciphertext and nonce

#### Scenario: Transcript loaded decrypted
- **WHEN** dashboard requests transcript
- **THEN** client decrypts transcript using derived key
- **AND** returns plaintext content

### Requirement: Encryption key derivation
Transcript encryption key SHALL be derived using HKDF with signing private key as input, constant salt, and session_id as info.

#### Scenario: Key derivation formula
- **WHEN** transcript is encrypted
- **THEN** key = HKDF(signing_private_key, salt="agentmesh_transcript_key", info=session_id, length=32)

#### Scenario: Deterministic key derivation
- **WHEN** same session_id is used for derive
- **THEN** same encryption key is produced
- **AND** transcript can be decrypted

### Requirement: Transcript file format
Encrypted transcript files SHALL use JSON format with ciphertext and nonce fields, both base64 encoded.

#### Scenario: Encrypted file structure
- **WHEN** transcript is written
- **THEN** file contains {"ciphertext": "<base64>", "nonce": "<base64>", "version": 1}

#### Scenario: Version for future upgrades
- **WHEN** encrypted file is read
- **THEN** version field determines decryption method

### Requirement: Migration of existing transcripts
Existing unencrypted transcripts SHALL be migrated to encrypted format on first access after upgrade.

#### Scenario: Unencrypted transcript migrated
- **WHEN** client loads unencrypted transcript (no ciphertext field)
- **THEN** client encrypts and rewrites file
- **AND** returns transcript content

#### Scenario: Already encrypted transcript loaded
- **WHEN** client loads encrypted transcript (has ciphertext field)
- **THEN** client decrypts normally

### Requirement: Transcript export with decryption
Dashboard transcript export SHALL provide decrypted content. API requires local authentication.

#### Scenario: Transcript exported via API
- **WHEN** dashboard requests GET /api/transcripts/{session_id}
- **THEN** response contains decrypted transcript JSON

#### Scenario: Bulk export
- **WHEN** owner requests transcript export
- **THEN** all transcripts are decrypted and packaged

### Requirement: Secure deletion
When transcript is deleted, file SHALL be securely overwritten before unlinking.

#### Scenario: Transcript secure delete
- **WHEN** owner deletes transcript
- **THEN** file is overwritten with random bytes before unlink

### Requirement: Key rotation transcript re-encryption
When signing key is rotated, transcripts encrypted with old key SHALL be re-encrypted with new key.

#### Scenario: Key rotation re-encryption
- **WHEN** agent rotates signing key
- **THEN** all transcripts are decrypted with old key
- **AND** re-encrypted with new key
- **AND** old key is securely deleted

### Requirement: Session key export for audit
Owner SHALL be able to export session encryption keys for external audit purposes.

#### Scenario: Session key export
- **WHEN** owner requests session key export for session_id
- **THEN** client returns session key and ratchet state
- **AND** audit log records export event
