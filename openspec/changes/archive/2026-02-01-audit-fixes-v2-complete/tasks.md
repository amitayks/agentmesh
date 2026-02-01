## 1. TURN Server Integration

- [x] 1.1 Add TURN server configuration to config.py (TURN_SERVERS list with url, username, credential)
- [x] 1.2 Update transport.py P2PTransport to include TURN servers in ICE configuration
- [x] 1.3 Add environment variable support for TURN credentials (TURN_SERVER_URL, TURN_USERNAME, TURN_CREDENTIAL)
- [x] 1.4 Implement TURN fallback after STUN failure (5-second timeout)
- [x] 1.5 Add relay type candidates to ICE gathering
- [x] 1.6 Add TURN credential refresh mechanism for time-limited credentials
- [x] 1.7 Add test for TURN fallback scenario
- [x] 1.8 Document TURN configuration in README

## 2. Certificate Chain Validation

- [x] 2.1 Create new agentmesh/certs.py module
- [x] 2.2 Implement Root CA certificate storage and loading
- [x] 2.3 Implement CertificateChain class with validate_chain() method
- [x] 2.4 Add certificate chain structure (Root CA → Org → Agent → Session)
- [x] 2.5 Update registry handlers.rs to issue Organization Certificates after DNS verification
- [x] 2.6 Update registry handlers.rs to issue Agent Certificates for verified tier
- [x] 2.7 Add certificate field to agent lookup response in registry
- [x] 2.8 Implement certificate chain validation in KNOCK evaluation (session.py)
- [x] 2.9 Add certificate_expired and certificate_revoked rejection reasons
- [x] 2.10 Implement certificate revocation check with 1-hour cache
- [x] 2.11 Add integration tests for certificate chain validation
- [x] 2.12 Update registry migration to add certificate columns

## 3. Double Ratchet Implementation

- [x] 3.1 Uncomment python-olm in requirements.txt
- [x] 3.2 Add DOUBLE_RATCHET_AVAILABLE check with graceful fallback
- [x] 3.3 Create DoubleRatchetSession class in encryption.py
- [x] 3.4 Implement message key derivation using HKDF
- [x] 3.5 Implement DH ratchet step on receiving new ratchet public key
- [x] 3.6 Implement chain key ratcheting after each message
- [x] 3.7 Add skipped message key storage for out-of-order handling
- [x] 3.8 Implement 1000 message skip limit with session termination
- [x] 3.9 Initialize Double Ratchet from X3DH shared secret
- [x] 3.10 Add ratchet state to session persistence
- [x] 3.11 Verify forward secrecy (past message keys deleted)
- [x] 3.12 Add unit tests for Double Ratchet operations
- [x] 3.13 Add fallback to X3DH-only mode when olm not installed

## 4. Session Key Persistence

- [x] 4.1 Create ~/.agentmesh/sessions/ directory structure on startup
- [x] 4.2 Implement session key file creation on ACCEPT
- [x] 4.3 Set file permissions to 0600 and directory to 0700
- [x] 4.4 Implement session key encryption using XChaCha20-Poly1305
- [x] 4.5 Define session file format (session_id, peer_amid, keys, created_at, last_used)
- [x] 4.6 Add version byte to encrypted session files
- [x] 4.7 Implement session loading on agent startup
- [x] 4.8 Handle corrupted session files gracefully (skip with warning)
- [x] 4.9 Update last_used timestamp on message send/receive
- [x] 4.10 Implement 7-day inactivity cleanup with secure deletion
- [x] 4.11 Add periodic cleanup task (every 6 hours)
- [x] 4.12 Implement session resumption without new KNOCK
- [x] 4.13 Handle session mismatch with session_not_found error
- [x] 4.14 Add tests for session persistence and resumption

## 5. Prekey Automation

- [x] 5.1 Implement prekey count check on agent startup
- [x] 5.2 Add 6-hour periodic prekey count check task
- [x] 5.3 Implement replenishment trigger when count < 20
- [x] 5.4 Generate (100 - current_count) new prekeys on replenishment
- [x] 5.5 Implement sequential prekey ID assignment
- [x] 5.6 Store prekey counter in ~/.agentmesh/prekey_counter
- [x] 5.7 Implement 7-day signed prekey rotation timer
- [x] 5.8 Add 24-hour grace period for old signed prekeys
- [x] 5.9 Implement prekey upload with retry and exponential backoff
- [x] 5.10 Add low_prekeys notification handling from registry
- [x] 5.11 Store prekey metadata in ~/.agentmesh/prekeys/
- [x] 5.12 Track consumed prekeys locally
- [x] 5.13 Add tests for prekey automation

## 6. Reputation Anti-Gaming

- [x] 6.1 Update registry SQL function to apply Tier 2 50% weight discount
- [x] 6.2 Implement mutual rating detection (24-hour window)
- [x] 6.3 Apply 80% discount to mutual ratings
- [x] 6.4 Implement rapid change detection (>0.2 in 24h)
- [x] 6.5 Add rapid_reputation_increase and rapid_reputation_decrease events
- [x] 6.6 Add flag field to agent lookup response
- [x] 6.7 Implement 5-rating minimum for ranking inclusion
- [x] 6.8 Mark unrated agents with "unrated" status and 0.5 default
- [x] 6.9 Add ratings_count field to lookup response
- [x] 6.10 Store rating metadata (rater_amid, rater_tier, session_id, tags)
- [x] 6.11 Add rating tags support (fast_response, accurate, professional, etc.)
- [x] 6.12 Implement same-IP rating limit (first per 24h at full weight)
- [x] 6.13 Implement new account rating limit (25% weight for <7 days)
- [x] 6.14 Verify reputation formula with all anti-gaming adjustments
- [x] 6.15 Add tests for anti-gaming measures

## 7. JSON Schema Validation

- [x] 7.1 Add jsonschema>=4.0.0 to requirements.txt
- [x] 7.2 Update SchemaValidator to use jsonschema.validate()
- [x] 7.3 Configure Draft-07 schema specification
- [x] 7.4 Implement graceful fallback when jsonschema not installed
- [x] 7.5 Add validation_mode configuration (warning, strict, silent)
- [x] 7.6 Implement warning mode as default (log but process)
- [x] 7.7 Implement strict mode (reject invalid messages)
- [x] 7.8 Pre-load standard schemas (flight-search, product-search, skill-bid)
- [x] 7.9 Implement custom schema registration with file persistence
- [x] 7.10 Add schema field to message structure
- [x] 7.11 Handle unknown schemas gracefully (skip with warning)
- [x] 7.12 Provide detailed validation errors (path, message, schema_id)
- [x] 7.13 Collect multiple validation errors (not just first)
- [x] 7.14 Implement schema caching for performance
- [x] 7.15 Add tests for schema validation

## 8. Skill Manifest Updates

- [x] 8.1 Update skill.json version to "0.2.0"
- [x] 8.2 Add python-olm>=3.2.0 to python_requirements
- [x] 8.3 Add jsonschema>=4.0.0 to python_requirements
- [x] 8.4 Implement mesh_dashboard browser launch using webbrowser.open()
- [x] 8.5 Add dashboard_port configuration support
- [x] 8.6 Handle browser launch failure gracefully
- [x] 8.7 Update homepage URL in skill.json
- [x] 8.8 Update description to mention E2EE and KNOCK protocol
- [x] 8.9 Test skill.json validation

## 9. Capability Negotiation Integration

- [x] 9.1 Add offered_capabilities field to KNOCK message
- [x] 9.2 Add accepted_capabilities and rejected_capabilities to ACCEPT message
- [x] 9.3 Implement automatic capability negotiation in session establishment
- [x] 9.4 Select highest common version of shared schemas
- [x] 9.5 Log warning when no common capabilities exist
- [x] 9.6 Add CAPABILITY_REQUEST and CAPABILITY_RESPONSE message types
- [x] 9.7 Support dynamic capability updates during session
- [x] 9.8 Handle required capability not supported error
- [x] 9.9 Implement version mismatch negotiation (lowest common)
- [x] 9.10 Add tests for capability negotiation

## 10. Dashboard Transcript Decryption

- [x] 10.1 Load owner's signing key in dashboard on startup
- [x] 10.2 Implement automatic transcript decryption in GET /api/transcripts/{session_id}
- [x] 10.3 Return 403 error when encryption key not available
- [x] 10.4 Add GET /api/session-key-export/{session_id} endpoint
- [x] 10.5 Return base64 encoded session-specific decryption key
- [x] 10.6 Verify localhost-only access for session key export
- [x] 10.7 Add encrypted and decryptable fields to transcript list
- [x] 10.8 Implement transcript search with decryption
- [x] 10.9 Limit search to 100 most recent transcripts
- [x] 10.10 Add tests for transcript decryption

## 11. Payload Types Formalization

- [x] 11.1 Define STATUS payload dataclass (progress, estimated_completion_seconds, message, phase)
- [x] 11.2 Add STATUS progress validation (0.0-1.0)
- [x] 11.3 Define ERROR payload dataclass (code, message, retry_after_seconds, fallback_amid, details)
- [x] 11.4 Define standard error codes enum
- [x] 11.5 Define CLOSE payload dataclass (reason, summary, reputation_feedback)
- [x] 11.6 Define standard close reason codes enum
- [x] 11.7 Add priority field to REQUEST payload (low, normal, high, urgent)
- [x] 11.8 Add budget object to REQUEST payload (amount, currency, max_cost)
- [x] 11.9 Add processing_time_ms and completed_at to RESPONSE payload
- [x] 11.10 Add schema field to RESPONSE payload
- [x] 11.11 Implement payload type validation against schemas
- [x] 11.12 Handle unknown payload types gracefully
- [x] 11.13 Add type field to message envelope
- [x] 11.14 Add tests for all payload types

## 12. Configuration and Infrastructure

- [x] 12.1 Add DHT bootstrap node configuration option
- [x] 12.2 Document fallback behavior when DHT unavailable
- [x] 12.3 Add OAuth token validation in registry registration handler
- [x] 12.4 Remove TODO comments and implement certificate issuance
- [x] 12.5 Update TECHNICAL_SPEC.md with all changes
- [x] 12.6 Update README.md with new configuration options
- [x] 12.7 Add TURN setup documentation
- [x] 12.8 Add certificate chain documentation

## 13. Testing and Verification

- [x] 13.1 Add edge case tests for key rotation during active session
- [x] 13.2 Add edge case tests for concurrent KNOCK handling
- [x] 13.3 Add browser-based dashboard tests
- [x] 13.4 Verify all 21 audit issues are resolved
- [x] 13.5 Run full integration test suite
- [x] 13.6 Run production tests (test_production.py)
- [x] 13.7 Verify 100% audit compliance
- [x] 13.8 Update CHANGELOG.md with all changes
