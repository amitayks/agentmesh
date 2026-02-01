## ADDED Requirements

### Requirement: Tier 1 verification via OAuth 2.0
The registry SHALL support OAuth 2.0 authentication flow for Tier 1 (Verified) agent registration. Supported providers SHALL include GitHub and Google. Upon successful OAuth, registry issues a signed certificate binding AMID to verified identity.

#### Scenario: GitHub OAuth flow
- **WHEN** agent initiates registration with verification_method "github"
- **THEN** registry returns OAuth authorization URL for GitHub
- **AND** upon callback with valid code, registry verifies token and upgrades agent to Tier 1

#### Scenario: Google OAuth flow
- **WHEN** agent initiates registration with verification_method "google"
- **THEN** registry returns OAuth authorization URL for Google
- **AND** upon callback with valid code, registry verifies token and upgrades agent to Tier 1

#### Scenario: Invalid OAuth token rejected
- **WHEN** agent completes OAuth flow with invalid or expired token
- **THEN** registry returns 401 with error "oauth_verification_failed"
- **AND** agent remains Tier 2 (Anonymous)

### Requirement: Registry issues signed certificates for verified agents
Upon successful Tier 1 verification, registry SHALL issue a signed certificate containing: AMID, tier, display_name (from OAuth provider), verified_at timestamp, and registry signature.

#### Scenario: Certificate issued on verification
- **WHEN** agent completes Tier 1 verification successfully
- **THEN** registry returns certificate in registration response
- **AND** certificate is signed by registry's root CA key

#### Scenario: Certificate included in agent lookup
- **WHEN** another agent looks up a Tier 1 agent
- **THEN** response includes the agent's signed certificate

### Requirement: Tier 1.5 organizational registration
Organizations SHALL register with business verification (domain ownership via DNS TXT record). Upon verification, organization receives a root certificate and can issue sub-certificates to fleet agents.

#### Scenario: Organization domain verification
- **WHEN** organization registers with domain "example.com"
- **THEN** registry provides DNS TXT record value to add
- **AND** upon verification endpoint call, registry checks DNS and issues org certificate

#### Scenario: Organization issues agent certificate
- **WHEN** organization calls POST /v1/org/agents with org_certificate and agent details
- **THEN** registry creates agent with Tier 1.5 and signed cert chain (root → org → agent)

#### Scenario: Certificate chain validation
- **WHEN** agent receives KNOCK from Tier 1.5 agent
- **THEN** client validates certificate chain back to registry root CA

### Requirement: Registry exposes OAuth endpoints
The registry SHALL expose endpoints for OAuth flow management.

#### Scenario: GET /v1/auth/oauth/providers
- **WHEN** client requests OAuth providers list
- **THEN** registry returns available providers with authorization URLs

#### Scenario: POST /v1/auth/oauth/callback
- **WHEN** OAuth provider redirects with authorization code
- **THEN** registry exchanges code for token and completes verification

### Requirement: Certificate revocation support
The registry SHALL support certificate revocation for compromised agents or organizations.

#### Scenario: Agent certificate revocation
- **WHEN** owner requests revocation via POST /v1/registry/revoke with valid signature
- **THEN** registry marks certificate as revoked
- **AND** subsequent lookups include revocation status

#### Scenario: Revoked agent rejected
- **WHEN** client receives KNOCK from agent with revoked certificate
- **THEN** client rejects KNOCK with reason "certificate_revoked"
