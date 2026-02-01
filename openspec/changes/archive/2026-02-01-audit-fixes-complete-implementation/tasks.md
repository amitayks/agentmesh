## 1. Critical Security Fixes (MUST complete first)

- [x] 1.1 Enable signature verification in relay CONNECT handler (relay/src/connection.rs)
- [x] 1.2 Add public_key field to RelayMessage::Connect in types.rs
- [x] 1.3 Update client transport.py to send public_key in CONNECT message
- [x] 1.4 Add server-side WebSocket ping task (25-second interval) in connection.rs
- [x] 1.5 Add ping timeout handler to disconnect unresponsive clients
- [x] 1.6 Enable signature verification in registry handlers (handlers.rs)
- [x] 1.7 Add signature verification to registry status update endpoint
- [x] 1.8 Add signature verification to registry capabilities update endpoint
- [x] 1.9 Add KNOCK signature verification in client.py _handle_knock()
- [x] 1.10 Add public key lookup from registry for KNOCK verification
- [x] 1.11 Add ACCEPT/REJECT signature verification in client.py
- [x] 1.12 Update protocol version to "agentmesh/0.2" in all components

## 2. Key Format and Compatibility

- [x] 2.1 Add key format prefix writing (ed25519:/x25519:) in identity.py save()
- [x] 2.2 Add backwards-compatible key reading (accept with or without prefix)
- [x] 2.3 Add deprecation warning for keys without prefix
- [x] 2.4 Update registry models to store prefixed keys
- [x] 2.5 Update relay auth.rs to handle prefixed keys

## 3. X3DH Key Exchange Upgrade

- [x] 3.1 Create prekey bundle data structure in encryption.py
- [x] 3.2 Implement signed prekey generation
- [x] 3.3 Implement one-time prekey batch generation (100 keys)
- [x] 3.4 Add prekey bundle upload to registry on registration
- [x] 3.5 Add GET /v1/registry/prekeys/{amid} endpoint to registry
- [x] 3.6 Implement X3DH key agreement using prekeys
- [x] 3.7 Add prekey consumption tracking in registry
- [x] 3.8 Add automatic prekey replenishment when count < 20
- [x] 3.9 Update Double Ratchet initialization to use X3DH shared secret
- [x] 3.10 Add prekey rotation (7-day interval)

## 4. Session Caching

- [x] 4.1 Create SessionCache class with LRU eviction
- [x] 4.2 Implement cache key structure (our_amid, peer_amid, intent_category)
- [x] 4.3 Add cache persistence to ~/.agentmesh/session_cache.json
- [x] 4.4 Add cache lookup before KNOCK in client.py send()
- [x] 4.5 Add cache population on successful session establishment
- [x] 4.6 Implement 24-hour TTL with configurable option
- [x] 4.7 Add cache invalidation on key rotation
- [x] 4.8 Add cache invalidation on policy change
- [x] 4.9 Add explicit clear_session_cache() method
- [x] 4.10 Implement optimistic send for allowlisted contacts
- [x] 4.11 Add server-side message buffering for optimistic send

## 5. Tier Verification (OAuth)

- [x] 5.1 Add OAuth provider configuration to registry (GitHub, Google)
- [x] 5.2 Create GET /v1/auth/oauth/providers endpoint
- [x] 5.3 Implement GitHub OAuth authorization URL generation
- [x] 5.4 Implement Google OAuth authorization URL generation
- [x] 5.5 Create POST /v1/auth/oauth/callback endpoint
- [x] 5.6 Implement OAuth token exchange for GitHub
- [x] 5.7 Implement OAuth token exchange for Google
- [x] 5.8 Create certificate generation for verified agents
- [x] 5.9 Add certificate to agent lookup response
- [x] 5.10 Implement certificate chain validation in client

## 6. Organizational (Tier 1.5) Registration

- [x] 6.1 Create organization model in registry
- [x] 6.2 Add POST /v1/org/register endpoint with domain field
- [x] 6.3 Generate DNS TXT record challenge
- [x] 6.4 Implement DNS TXT record verification
- [x] 6.5 Issue organization root certificate
- [x] 6.6 Create POST /v1/org/agents endpoint for fleet registration
- [x] 6.7 Implement certificate chain: root → org → agent
- [x] 6.8 Add organization field to agent lookup

## 7. Certificate Revocation

- [x] 7.1 Add revocation table to registry database
- [x] 7.2 Create POST /v1/registry/revoke endpoint
- [x] 7.3 Add revocation status to agent lookup response
- [x] 7.4 Add revocation check in client KNOCK evaluation
- [x] 7.5 Create revocation list endpoint for bulk checking

## 8. Reputation System

- [x] 8.1 Create reputation_feedbacks table in registry database
- [x] 8.2 Create completed_sessions tracking in registry
- [x] 8.3 Implement completion rate calculation
- [x] 8.4 Implement age factor calculation (days/365, capped at 1.0)
- [x] 8.5 Implement tier bonus calculation
- [x] 8.6 Implement peer feedback averaging with weights
- [x] 8.7 Implement full reputation score formula
- [x] 8.8 Add Tier 2 feedback 50% weight discount
- [x] 8.9 Add mutual-only rating 80% discount
- [x] 8.10 Add rapid change detection and flagging
- [x] 8.11 Add minimum 5 ratings threshold for ranking
- [x] 8.12 Add reputation tags storage and aggregation
- [x] 8.13 Update KNOCK message to include fetched reputation

## 9. Transcript Encryption

- [x] 9.1 Implement transcript encryption key derivation using HKDF
- [x] 9.2 Implement XChaCha20-Poly1305 encryption for transcripts
- [x] 9.3 Update TranscriptStore.save_transcript() to encrypt
- [x] 9.4 Update TranscriptStore.get_transcript() to decrypt
- [x] 9.5 Define encrypted file format with version field
- [x] 9.6 Implement migration of existing unencrypted transcripts
- [x] 9.7 Implement secure file deletion (overwrite before unlink)
- [x] 9.8 Add re-encryption on signing key rotation
- [x] 9.9 Add session key export for audit

## 10. DID Documents

- [x] 10.1 Create DID document structure per W3C spec
- [x] 10.2 Implement DID document generation on identity creation
- [x] 10.3 Save DID document to ~/.agentmesh/did/document.json
- [x] 10.4 Add DID document to registration request
- [x] 10.5 Create GET /v1/registry/did/{amid} endpoint
- [x] 10.6 Implement DID resolution from AMID
- [x] 10.7 Add DHT fallback for DID resolution
- [x] 10.8 Update DID document on key rotation
- [x] 10.9 Add versionId to DID document

## 11. DHT Discovery

- [x] 11.1 Add kademlia to optional dependencies
- [x] 11.2 Create DHT client wrapper class
- [x] 11.3 Add default bootstrap nodes configuration
- [x] 11.4 Implement DHT bootstrap on startup
- [x] 11.5 Implement DHT publish (sha256(amid) → agent info)
- [x] 11.6 Implement DHT lookup with 5-second timeout
- [x] 11.7 Add signature to DHT values
- [x] 11.8 Implement 4-hour automatic refresh
- [x] 11.9 Add 24-hour stale entry detection
- [x] 11.10 Implement dht_participate config option
- [x] 11.11 Add graceful fallback when kademlia not installed

## 12. P2P Transport

- [x] 12.1 Add aiortc to optional dependencies
- [x] 12.2 Create WebRTC wrapper class in transport.py
- [x] 12.3 Implement ICE candidate gathering with STUN
- [x] 12.4 Implement ICE offer generation
- [x] 12.5 Implement ICE answer processing
- [x] 12.6 Establish WebRTC data channel on successful ICE
- [x] 12.7 Implement send() over data channel
- [x] 12.8 Implement 5-second negotiation timeout with relay fallback
- [x] 12.9 Add P2P connection health monitoring
- [x] 12.10 Implement automatic fallback to relay on P2P failure
- [x] 12.11 Add P2P metrics to get_status()
- [x] 12.12 Add graceful fallback when aiortc not installed

## 13. Message Schemas

- [x] 13.1 Create ~/.agentmesh/schemas/ directory structure
- [x] 13.2 Define agentmesh/travel/flight-search/v1 schema
- [x] 13.3 Define agentmesh/commerce/product-search/v1 schema
- [x] 13.4 Define agentmesh/marketplace/skill-bid/v1 schema
- [x] 13.5 Implement schema validation on message receive
- [x] 13.6 Add warning logging for invalid schemas (not rejection)
- [x] 13.7 Implement custom schema registration
- [x] 13.8 Add sequence number tracking per session
- [x] 13.9 Add out-of-order sequence detection with warning
- [x] 13.10 Add duplicate sequence rejection
- [x] 13.11 Implement capability negotiation request message
- [x] 13.12 Implement capability negotiation response message

## 14. Dashboard and Circuit Breaker Fixes

- [x] 14.1 Fix pause_new to properly reject all new KNOCKs
- [x] 14.2 Fix block command to kill active sessions with blocklisted AMID
- [x] 14.3 Add emergency_stop framework halt (document limitation)
- [x] 14.4 Add key rotation trigger from dashboard

## 15. Testing and Verification

- [x] 15.1 Create integration test: valid signature connection accepted
- [x] 15.2 Create integration test: invalid signature connection rejected
- [x] 15.3 Create integration test: KNOCK with valid signature processed
- [x] 15.4 Create integration test: KNOCK with invalid signature dropped
- [x] 15.5 Create integration test: session caching skips KNOCK
- [x] 15.6 Create integration test: X3DH key exchange works
- [x] 15.7 Create integration test: transcript encryption/decryption
- [x] 15.8 Create integration test: reputation calculation
- [x] 15.9 Verify WebSocket keepalive on Railway (production test)
- [x] 15.10 Verify 1000+ concurrent connections on relay

## 16. Documentation and Migration

- [x] 16.1 Update TECHNICAL_SPEC.md with protocol v0.2 changes
- [x] 16.2 Update README.md with new features
- [x] 16.3 Create MIGRATION.md for v0.1 → v0.2 upgrade
- [x] 16.4 Update CEO.md with audit resolution status
- [x] 16.5 Document breaking changes in CHANGELOG.md
