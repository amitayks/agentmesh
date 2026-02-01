## MODIFIED Requirements

### Requirement: Dashboard transcript auto-decryption
The dashboard SHALL automatically decrypt transcripts using the owner's key.

#### Scenario: Transcript decrypted for display
- **WHEN** a transcript is requested via GET /api/transcripts/{session_id}
- **THEN** the dashboard SHALL decrypt the transcript using the owner's signing key
- **AND** return the decrypted content

#### Scenario: Encryption key available
- **WHEN** the dashboard starts
- **THEN** it SHALL load the owner's signing key for transcript decryption
- **AND** store it in memory for the session

#### Scenario: Key not available error
- **WHEN** a transcript is requested
- **AND** the owner's key is not available
- **THEN** the API SHALL return 403 with error "encryption_key_not_available"

### Requirement: Session key export in dashboard
The dashboard SHALL expose session key export for audit purposes.

#### Scenario: Session key export endpoint
- **WHEN** GET /api/session-key-export/{session_id} is called
- **THEN** the dashboard SHALL return the session-specific decryption key
- **AND** the key SHALL be base64 encoded

#### Scenario: Session key export requires authentication
- **WHEN** session key export is requested
- **THEN** the request SHALL be verified to come from localhost only

### Requirement: Transcript list with encryption status
The transcript list SHALL indicate encryption status.

#### Scenario: Transcript list shows encryption status
- **WHEN** GET /api/transcripts is called
- **THEN** each transcript entry SHALL include "encrypted" boolean field
- **AND** "decryptable" boolean indicating if current key can decrypt

### Requirement: Transcript search in encrypted content
The dashboard SHALL support searching within encrypted transcripts.

#### Scenario: Search decrypts and filters
- **WHEN** a search query is provided to GET /api/transcripts?search=query
- **THEN** the system SHALL decrypt each transcript
- **AND** return only transcripts containing the search term

#### Scenario: Search performance for many transcripts
- **WHEN** searching across many transcripts
- **THEN** the system SHALL limit search to most recent 100 transcripts
- **AND** indicate if more results may exist
