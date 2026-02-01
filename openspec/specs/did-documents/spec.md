## ADDED Requirements

### Requirement: DID document generation
The AgentMesh client SHALL generate a W3C DID document for the agent's identity using the format `did:agentmesh:<amid>`.

#### Scenario: DID document created on identity generation
- **WHEN** new agent identity is generated
- **THEN** client creates corresponding DID document
- **AND** stores at ~/.agentmesh/did/document.json

#### Scenario: DID document format compliance
- **WHEN** DID document is generated
- **THEN** document includes @context, id, verificationMethod, keyAgreement, and service fields per W3C DID Core spec

### Requirement: DID document structure
The DID document SHALL include verification method for signing key, key agreement for exchange key, and service endpoint for AgentMesh relay.

#### Scenario: Verification method included
- **WHEN** DID document is generated
- **THEN** verificationMethod contains Ed25519VerificationKey2020 with signing public key

#### Scenario: Key agreement included
- **WHEN** DID document is generated
- **THEN** keyAgreement contains X25519KeyAgreementKey2020 with exchange public key

#### Scenario: Service endpoint included
- **WHEN** DID document is generated
- **THEN** service contains AgentMeshEndpoint with relay URL

### Requirement: Registry stores DID documents
The registry SHALL store and serve DID documents for registered agents.

#### Scenario: DID document uploaded on registration
- **WHEN** agent registers with registry
- **THEN** registration includes DID document
- **AND** registry stores document

#### Scenario: DID document retrieval
- **WHEN** client requests GET /v1/registry/did/{amid}
- **THEN** registry returns the agent's DID document

### Requirement: DID resolution
The client SHALL support resolving DIDs to obtain agent connection information.

#### Scenario: DID resolution via registry
- **WHEN** client resolves did:agentmesh:5Kd3...
- **THEN** client fetches DID document from registry
- **AND** extracts public keys and service endpoint

#### Scenario: DID resolution via DHT fallback
- **WHEN** registry resolution fails
- **THEN** client attempts DHT lookup for DID document

### Requirement: DID document updates on key rotation
When exchange keys are rotated, the DID document SHALL be updated and republished.

#### Scenario: Key rotation updates DID
- **WHEN** agent rotates exchange key
- **THEN** client updates keyAgreement in DID document
- **AND** republishes to registry

#### Scenario: DID document versioning
- **WHEN** DID document is updated
- **THEN** document includes versionId with ISO timestamp
