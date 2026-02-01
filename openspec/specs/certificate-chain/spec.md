## ADDED Requirements

### Requirement: Certificate chain structure
The system SHALL implement a hierarchical certificate chain: Registry Root CA → Organization Certificate → Agent Certificate → Session Key.

#### Scenario: Full chain validation for organization agent
- **WHEN** an agent with Tier 1.5 (Organization) sends a KNOCK
- **THEN** the receiver SHALL validate the complete certificate chain from Root CA to Agent Certificate
- **AND** all certificates in the chain MUST be valid and unexpired

#### Scenario: Verified agent chain validation
- **WHEN** an agent with Tier 1 (Verified) sends a KNOCK
- **THEN** the receiver SHALL validate the chain from Root CA to Agent Certificate (skipping Organization)

### Requirement: Root CA certificate management
The registry SHALL maintain a Root CA certificate for signing all downstream certificates.

#### Scenario: Root CA signs organization certificates
- **WHEN** an organization completes DNS verification
- **THEN** the registry SHALL issue an Organization Certificate signed by the Root CA
- **AND** the certificate SHALL include the organization's domain and public key

#### Scenario: Root CA certificate rotation
- **WHEN** the Root CA certificate is rotated
- **THEN** all previously issued Organization Certificates remain valid until their expiration
- **AND** new certificates SHALL be signed with the new Root CA

### Requirement: Organization certificate issuance
The registry SHALL issue Organization Certificates after successful DNS TXT record verification.

#### Scenario: Organization certificate issued after DNS verification
- **WHEN** an organization completes POST /v1/org/register
- **AND** DNS TXT verification succeeds via POST /v1/org/verify
- **THEN** the registry SHALL return an Organization Certificate in the response

#### Scenario: Organization certificate includes metadata
- **WHEN** an Organization Certificate is issued
- **THEN** it SHALL include: organization name, domain, public key, issued_at, expires_at, signature

### Requirement: Agent certificate issuance
The registry SHALL issue Agent Certificates for verified and organization-backed agents.

#### Scenario: Agent certificate for verified tier
- **WHEN** an agent completes OAuth verification
- **THEN** the registry SHALL issue an Agent Certificate signed by the Root CA
- **AND** the registration response SHALL include the certificate

#### Scenario: Agent certificate for organization tier
- **WHEN** an organization registers an agent via POST /v1/org/agents
- **THEN** the registry SHALL issue an Agent Certificate signed by the Organization Certificate

### Requirement: Certificate validation in KNOCK evaluation
The receiver SHALL validate the sender's certificate chain before accepting a KNOCK.

#### Scenario: Invalid certificate chain rejected
- **WHEN** a KNOCK is received
- **AND** the sender's certificate chain validation fails
- **THEN** the KNOCK SHALL be rejected with reason "invalid_certificate"

#### Scenario: Expired certificate rejected
- **WHEN** a KNOCK is received
- **AND** any certificate in the sender's chain is expired
- **THEN** the KNOCK SHALL be rejected with reason "certificate_expired"

#### Scenario: Certificate chain stored in registry
- **WHEN** a client looks up an agent via GET /v1/registry/lookup
- **THEN** the response SHALL include the agent's certificate and certificate chain

### Requirement: Certificate revocation check
The system SHALL check certificate revocation status during chain validation.

#### Scenario: Revoked certificate rejected
- **WHEN** a KNOCK is received
- **AND** the sender's certificate has been revoked
- **THEN** the KNOCK SHALL be rejected with reason "certificate_revoked"

#### Scenario: Revocation check uses cached CRL
- **WHEN** validating a certificate chain
- **THEN** the system SHALL check the local revocation cache first
- **AND** refresh from registry if cache is older than 1 hour
