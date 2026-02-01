## Context

AgentMesh v0.2 has completed its initial implementation but a comprehensive audit revealed 21 issues across all 6 protocol layers. The codebase is 86% complete with core functionality working (E2EE, KNOCK protocol, relay, registry), but several critical gaps prevent production deployment:

**Current State:**
- Relay server (Rust): Functional with WebSocket keepalive, rate limiting, store-forward
- Registry API (Rust): Functional with signature verification, prekey management, OAuth stubs
- OpenClaw Skill (Python): Functional with X3DH, session management, dashboard
- Protocol: agentmesh/0.2 with backwards compatibility for 0.1

**Constraints:**
- Must maintain backwards compatibility with existing 0.2 protocol
- Changes should not require database migrations if possible
- Python dependencies should remain optional where feasible (kademlia, aiortc, python-olm)
- Must work on Railway deployment environment

**Stakeholders:**
- Agent developers integrating with OpenClaw
- Relay/Registry operators
- End users (agent owners) using the dashboard

## Goals / Non-Goals

**Goals:**
1. Achieve 100% audit compliance - fix all 21 identified issues
2. Implement production-grade security (certificate chains, Double Ratchet, anti-gaming)
3. Complete all partial implementations to spec compliance
4. Add comprehensive test coverage for edge cases
5. Production-ready configuration (DHT bootstrap, TURN, OAuth)

**Non-Goals:**
- New features beyond audit compliance
- Breaking protocol changes (stay at 0.2)
- Performance optimization beyond fixing identified issues
- Mobile/web client implementations
- Self-hosted TURN server implementation (use third-party services)

## Decisions

### D1: TURN Server Integration
**Decision:** Use Twilio or Cloudflare TURN services via configuration rather than self-hosting.

**Rationale:**
- Self-hosting TURN requires significant infrastructure
- Twilio/Cloudflare have generous free tiers
- Configuration-based approach allows switching providers

**Alternatives Considered:**
- Self-host coturn: Too much ops overhead for initial launch
- Skip TURN entirely: Would break P2P in restrictive NAT environments

**Implementation:**
```python
# config.py
TURN_SERVERS = [
    {"url": "turn:global.turn.twilio.com:3478", "username": "<from_env>", "credential": "<from_env>"},
]
```

### D2: Certificate Chain Validation
**Decision:** Implement X.509-style chain validation in Python using cryptography library's x509 module.

**Rationale:**
- cryptography library already a dependency
- X.509 is the industry standard for certificate chains
- Can validate: Root CA → Organization → Agent → Session

**Alternatives Considered:**
- Custom chain format: More work, less interoperable
- Skip chain validation: Security gap

**Implementation:**
```python
# New file: agentmesh/certs.py
class CertificateChain:
    def validate_chain(self, cert: bytes, trust_anchors: List[bytes]) -> bool
    def issue_agent_certificate(self, agent_amid: str, org_cert: bytes) -> bytes
```

### D3: Double Ratchet Implementation
**Decision:** Use python-olm library (libolm bindings) for Double Ratchet, with fallback to simplified X3DH-only mode.

**Rationale:**
- python-olm is the standard Matrix/Signal-compatible implementation
- Already in requirements.txt (just commented out)
- Graceful fallback maintains functionality when olm not installed

**Alternatives Considered:**
- Pure Python implementation: More code to maintain, potential security bugs
- Require olm: Would break easy installation on some platforms

**Implementation:**
```python
# encryption.py
try:
    from olm import Account, Session as OlmSession
    DOUBLE_RATCHET_AVAILABLE = True
except ImportError:
    DOUBLE_RATCHET_AVAILABLE = False
    # Fallback to X3DH-only mode with session key rotation
```

### D4: Session Key Persistence
**Decision:** Store session keys encrypted in `~/.agentmesh/sessions/<peer_amid>/<session_id>.json` using the owner's signing key for encryption.

**Rationale:**
- Matches spec requirement
- Reuses existing transcript encryption approach
- Allows session resumption after restart

**Alternatives Considered:**
- SQLite database: Overkill for key-value storage
- In-memory only: Loses sessions on restart

**File Format:**
```json
{
  "session_id": "uuid",
  "peer_amid": "...",
  "session_key_encrypted": "base64...",
  "chain_key": "base64...",
  "message_keys": {"0": "base64...", "1": "base64..."},
  "created_at": "ISO8601",
  "last_used": "ISO8601"
}
```

### D5: Prekey Automation
**Decision:** Implement background task that checks prekey count on startup and every 6 hours, replenishing when below 20.

**Rationale:**
- Prevents running out of one-time prekeys
- 6-hour interval balances freshness vs registry load
- Matches spec's "replenish when < 20" requirement

**Implementation:**
```python
async def prekey_maintenance_loop(identity, registry):
    while True:
        count = await registry.get_prekey_count(identity.amid)
        if count < 20:
            new_prekeys = generate_one_time_prekeys(100 - count)
            await registry.upload_prekeys(new_prekeys)
        await asyncio.sleep(6 * 3600)
```

### D6: Reputation Anti-Gaming
**Decision:** Implement three anti-gaming measures:
1. Tier 2 feedback weighted at 50%
2. Mutual-rating discount of 80%
3. Rapid change flag when score changes >0.2 in 24h

**Rationale:**
- Prevents Sybil attacks (Tier 2 discount)
- Prevents reciprocal rating inflation (mutual discount)
- Catches suspicious patterns (rapid change detection)

**Implementation:**
Update registry's `update_agent_reputation` SQL function with these weights.

### D7: JSON Schema Validation
**Decision:** Add jsonschema library and validate messages on receive, but keep warning-only mode as default.

**Rationale:**
- Proper validation with industry-standard library
- Warning-only prevents breaking on schema mismatches during rollout
- Can be made strict via configuration

**Dependencies:**
```
jsonschema>=4.0.0
```

### D8: Dashboard Browser Launch
**Decision:** Use `webbrowser.open()` from Python standard library.

**Rationale:**
- No additional dependencies
- Works cross-platform (Linux, macOS, Windows)
- Simple one-liner implementation

```python
def mesh_dashboard():
    import webbrowser
    webbrowser.open(f"http://localhost:{dashboard_port}")
```

## Risks / Trade-offs

| Risk | Mitigation |
|------|------------|
| python-olm installation fails on some platforms | Graceful fallback to X3DH-only mode with warning |
| TURN credentials exposed in config | Use environment variables, document security |
| Session key files left on disk after session ends | Implement cleanup task, secure deletion |
| jsonschema validation slows message processing | Warning-only mode, optional strict mode |
| Certificate chain validation complexity | Comprehensive test coverage, clear error messages |
| DHT bootstrap nodes not available | Fallback to registry-only discovery |

## Migration Plan

**Deployment Steps:**
1. Update requirements.txt with new dependencies
2. Deploy registry changes (certificate handling, anti-gaming)
3. Deploy relay changes (minimal - mostly client-side)
4. Update OpenClaw skill package
5. Agents will auto-update on next skill sync

**Rollback Strategy:**
- All changes are additive or optional
- Remove TURN config to disable
- Remove olm import to fallback
- Revert registry SQL function for reputation

**Breaking Changes:**
- None - all changes are backwards compatible

## Open Questions

1. **TURN Provider Selection:** Twilio vs Cloudflare vs Xirsys? Decision: Start with Twilio, document switching process.

2. **Certificate Expiration:** How long should agent certificates be valid? Proposal: 1 year for verified, 90 days for anonymous.

3. **Session Key Cleanup:** When to delete old session key files? Proposal: After 7 days of inactivity, with secure deletion.

4. **Anti-Gaming Thresholds:** What's the right threshold for rapid change detection? Proposal: >0.2 change in 24h triggers review flag.
