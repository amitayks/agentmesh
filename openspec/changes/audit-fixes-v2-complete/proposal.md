## Why

The comprehensive audit of AgentMesh v0.2 revealed 21 issues across all layers: 4 missing implementations, 17 partial implementations, and several critical gaps that must be fixed before production launch. This change addresses every single issue to achieve 100% audit compliance and production readiness.

## What Changes

### Critical (Must Fix)

1. **TURN Server Fallback** - P2P WebRTC exists but true TURN relay fallback for NAT traversal is missing. Currently uses WebSocket relay as fallback, but spec requires TURN.

2. **Certificate Chain Validation** - Full certificate chain (Root CA → Org → Agent → Session) validation is stubbed with TODOs. Must implement complete chain verification.

### High Priority

3. **Signal Protocol Double Ratchet** - `python-olm` is commented out in requirements. Need proper Double Ratchet implementation or re-enable olm.

4. **Session Key Persistence** - Sessions stored in memory only, not persisted to `~/.agentmesh/sessions/<peer_amid>/` as specified.

5. **skill.json Version Mismatch** - Shows `0.1.0` but protocol is `0.2`. Must update.

6. **Reputation Anti-Gaming** - Rapid change detection and Tier 2 feedback discounting is basic. Need full implementation.

### Medium Priority

7. **Organization DNS Verification** - End-to-end testing needed for DNS TXT record verification flow.

8. **Prekey Replenishment Trigger** - Proactive replenishment when count drops below 20 not triggered automatically.

9. **Capability Negotiation Integration** - CapabilityNegotiator exists but not integrated into session establishment flow.

10. **DHT Bootstrap Nodes** - Point to non-existent `bootstrap.agentmesh.net`. Need real nodes or configuration option.

### Low Priority

11. **Dashboard Transcript Viewer** - Decryption requires manual key setup. Should auto-decrypt with owner key.

12. **mesh_dashboard Browser Launch** - Command documented but browser launch not implemented.

13. **Edge Case Test Coverage** - Missing tests for key rotation during active session, concurrent KNOCK handling, etc.

### Additional Fixes From Audit

14. **Payload Types Formalization** - STATUS/ERROR/CLOSE payloads less formalized than REQUEST/RESPONSE.

15. **Dashboard Manual Testing** - Owner dashboard needs browser testing verification.

16. **Certificate Issuance** - Registry returns `certificate: None` with TODO comment.

17. **Tier Verification OAuth** - Token validation marked as TODO in registration handler.

18. **Full Schema Validation** - jsonschema library not used, custom validation is basic.

19. **Session Key Export** - `export_session_key` method exists but not exposed in dashboard.

20. **Prekey Rotation Timer** - 7-day rotation specified but timer not implemented.

21. **Double Ratchet Message Keys** - Full Double Ratchet with message key derivation not complete.

## Capabilities

### New Capabilities

- `turn-server`: TURN server integration for NAT traversal fallback when STUN fails
- `certificate-chain`: Full X.509-style certificate chain validation for trust hierarchy
- `double-ratchet`: Complete Signal Protocol Double Ratchet implementation
- `session-persistence`: Persistent session key storage with secure file encryption
- `prekey-automation`: Automatic prekey rotation and replenishment system
- `anti-gaming`: Advanced reputation anti-gaming measures with anomaly detection
- `jsonschema-validation`: Proper JSON Schema validation using jsonschema library

### Modified Capabilities

- `skill-manifest`: Update version to 0.2.0, add browser launch for dashboard
- `capability-negotiation`: Integrate into session establishment flow
- `transcript-decryption`: Auto-decrypt with owner key in dashboard
- `payload-types`: Formalize STATUS/ERROR/CLOSE payload structures

## Impact

### Code Changes
- **Python (openclaw-skill/agentmesh/)**:
  - `encryption.py` - Double Ratchet, session persistence
  - `transport.py` - TURN server integration
  - `session.py` - Certificate chain validation
  - `schemas.py` - jsonschema integration, payload types
  - `session_cache.py` - Prekey automation hooks
  - `dashboard.py` - Transcript decryption, session key export
  - `config.py` - DHT bootstrap configuration
  - `did.py` - Certificate chain methods

- **Rust (registry/)**:
  - `handlers.rs` - Certificate issuance, OAuth verification
  - `auth.rs` - Chain validation
  - New `certs.rs` module for certificate handling

- **Configuration**:
  - `skill.json` - Version bump, browser launch
  - `requirements.txt` - Uncomment python-olm, add jsonschema

### APIs
- New dashboard endpoint: `GET /api/session-key-export/{session_id}`
- Enhanced: All existing endpoints remain compatible

### Dependencies
- `python-olm>=3.2.0` (uncomment)
- `jsonschema>=4.0.0` (add)
- TURN server credentials configuration

### Testing
- New integration tests for all edge cases
- Browser-based dashboard tests
- Certificate chain validation tests
