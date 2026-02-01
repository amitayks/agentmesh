## Why

The AgentMesh V1 implementation passed 66% of audit checks but has **4 critical security vulnerabilities** and **17 high/medium priority gaps** that must be fixed before production deployment. The core architecture is sound, but signature verification code exists but is not being called, E2EE is simplified, and several protocol features are stubbed or missing. Without these fixes, any attacker can impersonate any agent on the network.

## What Changes

### Critical Security Fixes
- Enable Ed25519 signature verification in relay server CONNECT flow
- Enable signature verification in registry API for all mutations
- Add server-side WebSocket ping/pong keepalive (Railway/Fly.io will kill idle connections)
- Verify KNOCK message signatures on client-side before evaluation

### High Priority Implementations
- Implement OAuth 2.0 flow for Tier 1 (Verified) agent registration
- Complete P2P transport using WebRTC/aiortc (currently stubbed)
- Upgrade to full X3DH key exchange with prekeys for offline messaging
- Implement transcript encryption at rest using owner's key
- Implement Kademlia DHT for Tier 2 anonymous agent discovery
- Generate DID documents (`did:agentmesh:<amid>`) per W3C spec

### Medium Priority Implementations
- Add `ed25519:` prefix to key format as per spec
- Implement full reputation calculation system (currently stubbed)
- Implement certificate chain for Tier 1/1.5 agents
- Add session caching to skip KNOCK for known contacts
- Implement optimistic send for allowlisted AMIDs
- Define and validate standard message schemas
- Implement capability negotiation protocol

### Low Priority Fixes
- Implement key rotation for exchange keys
- Fix block command to kill active sessions with blocklisted AMIDs
- Extend emergency_stop to halt agent framework (not just disconnect)

## Capabilities

### New Capabilities
- `signature-verification`: Complete cryptographic signature verification across relay, registry, and client
- `tier-verification`: OAuth 2.0 and organizational certificate verification for trust tiers
- `p2p-transport`: WebRTC-based direct peer-to-peer communication
- `dht-discovery`: Kademlia DHT for decentralized Tier 2 agent discovery
- `did-documents`: W3C DID document generation and resolution
- `session-caching`: Skip KNOCK for cached trusted sessions
- `message-schemas`: Standard schema definitions and validation
- `reputation-system`: Full reputation calculation with peer feedback
- `transcript-encryption`: At-rest encryption for conversation transcripts

### Modified Capabilities
<!-- No existing specs to modify - this is greenfield implementation -->

## Impact

### Code Changes
- **relay/src/connection.rs**: Enable signature verification, add ping interval
- **relay/src/main.rs**: Configure keepalive settings
- **registry/src/handlers.rs**: Add signature verification, implement OAuth, reputation
- **registry/src/**: New modules for certificates, OAuth, reputation calculation
- **openclaw-skill/agentmesh/client.py**: Add KNOCK signature verification
- **openclaw-skill/agentmesh/encryption.py**: Upgrade to full X3DH with prekeys
- **openclaw-skill/agentmesh/transport.py**: Complete P2P implementation with aiortc
- **openclaw-skill/agentmesh/**: New modules for DHT, DID, schemas, session cache
- **openclaw-skill/agentmesh/audit.py**: Add transcript encryption

### Dependencies
- **Python**: `aiortc>=1.6.0` for WebRTC P2P
- **Python**: `kademlia>=2.2.2` for DHT
- **Rust**: Enable existing `ed25519-dalek` verification (already in deps)

### API Changes
- Registry API: New `/v1/auth/oauth` endpoints
- Registry API: `/v1/registry/did/<amid>` for DID resolution
- Relay protocol: Add `public_key` to CONNECT message for verification

### Breaking Changes
- **BREAKING**: Key format changes from `<base64>` to `ed25519:<base64>` and `x25519:<base64>`
- **BREAKING**: CONNECT message requires `public_key` field
