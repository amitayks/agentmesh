## Context

AgentMesh V1 has been built as a P2P encrypted messenger protocol for AI agents. The audit revealed that while the architecture is sound (~2,300 lines of production code), critical security verification code exists but is not being called. The relay server has signature verification functions in `auth.rs` but the connection handler bypasses them. Similarly, the registry has TODO comments where verification should occur.

**Current State:**
- Relay: Accepts connections without verifying AMID ownership
- Registry: Accepts registrations without cryptographic proof
- Client: Evaluates KNOCKs without signature verification
- E2EE: Uses simplified X25519 key exchange (not full X3DH)
- P2P: Stubbed with placeholder returns
- DHT: Not implemented
- Reputation: Acknowledged but not calculated

**Constraints:**
- Must maintain backwards compatibility with existing message formats where possible
- Railway deployment requires WebSocket keepalive
- Python skill must work with OpenClaw framework
- Rust server must handle 10k+ concurrent connections

## Goals / Non-Goals

**Goals:**
- Fix all 4 CRITICAL security vulnerabilities before any production use
- Implement all 6 HIGH priority features for a complete V1
- Address MEDIUM priority items for protocol completeness
- Maintain < 10ms added latency for signature verification
- Keep relay memory-safe and concurrent-safe

**Non-Goals:**
- Full libsignal integration (we'll use our Double Ratchet implementation)
- Blockchain-based identity (future consideration)
- Multi-relay federation (Phase 4 feature)
- Payment integration (Phase 4 feature)
- Full Matrix protocol compatibility (different use case)

## Decisions

### 1. Signature Verification Strategy

**Decision:** Enable existing `auth::verify_connection_signature()` in relay and add equivalent verification in registry.

**Rationale:** The code already exists in `relay/src/auth.rs`. We just need to call it. For registry, we'll add a similar verification module.

**Alternatives Considered:**
- External auth service: Adds latency and complexity
- JWT tokens: Overkill for our use case, adds dependency

**Implementation:**
```rust
// relay/src/connection.rs - Change from:
// TODO: Implement full signature verification

// To:
use crate::auth;
let verified = auth::verify_connection_signature(
    &amid,
    &public_key_b64,
    &signature_b64,
    timestamp,
);
if verified.is_err() {
    return Err("Signature verification failed");
}
```

### 2. CONNECT Message Changes

**Decision:** Require `public_key` field in CONNECT message (BREAKING CHANGE).

**Rationale:** Relay needs the public key to verify signature and derive AMID. Currently AMID is self-asserted without proof.

**Message Format:**
```json
{
  "type": "connect",
  "protocol": "agentmesh/0.1",
  "amid": "5Kd3...",
  "public_key": "<base64>",  // NEW REQUIRED FIELD
  "signature": "<base64>",
  "timestamp": "2026-02-01T12:00:00Z",
  "p2p_capable": true
}
```

### 3. WebSocket Keepalive Strategy

**Decision:** Server-initiated ping every 25 seconds with 10-second timeout.

**Rationale:** Railway/Fly.io kill connections after 30-60s of inactivity. Client already has `ping_interval=30`, but server should also ping to ensure bidirectional keepalive.

**Implementation:**
```rust
// In connection handler, spawn keepalive task:
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(25));
    loop {
        interval.tick().await;
        if let Err(_) = write.send(Message::Ping(vec![])).await {
            break;
        }
    }
});
```

### 4. X3DH Implementation

**Decision:** Implement X3DH using PyNaCl with signed prekeys stored in registry.

**Rationale:** Full X3DH provides forward secrecy for offline messaging. Our current simplified X25519 doesn't handle prekeys.

**Flow:**
1. On registration, generate and upload signed prekey bundle
2. On KNOCK, fetch recipient's prekeys from registry
3. Perform X3DH to derive shared secret
4. Continue with existing Double Ratchet

**Prekey Bundle:**
```json
{
  "identity_key": "<base64>",
  "signed_prekey": "<base64>",
  "signed_prekey_signature": "<base64>",
  "one_time_prekeys": ["<base64>", ...],
  "uploaded_at": "2026-02-01T00:00:00Z"
}
```

### 5. P2P Transport Implementation

**Decision:** Use `aiortc` for WebRTC data channels.

**Rationale:** aiortc is the most mature Python WebRTC library, handles ICE/STUN/TURN.

**Alternatives Considered:**
- Raw UDP: No NAT traversal
- Custom ICE: Reinventing the wheel
- libp2p-python: Heavy dependency, overkill

**Implementation Approach:**
1. On session acceptance, both agents exchange ICE candidates via relay
2. Attempt STUN-based direct connection
3. If STUN fails within 5 seconds, fall back to relay
4. If STUN succeeds, migrate session to P2P data channel

### 6. DHT Implementation

**Decision:** Use `kademlia` Python library for Tier 2 discovery.

**Rationale:** Battle-tested Kademlia implementation used by many projects.

**Bootstrap Strategy:**
- Bootstrap nodes hardcoded in config
- Agents opt-in to DHT participation
- DHT stores: `sha256(amid) → {public_keys, relay_endpoint}`

### 7. Transcript Encryption

**Decision:** Encrypt transcripts with XChaCha20-Poly1305 using key derived from owner's signing key.

**Rationale:** Already using PyNaCl, XChaCha20-Poly1305 is the recommended symmetric cipher.

**Key Derivation:**
```python
encryption_key = hkdf(
    signing_private_key,
    salt=b"agentmesh_transcript_key",
    info=session_id.encode(),
    length=32
)
```

### 8. Session Caching

**Decision:** LRU cache with 24-hour TTL, keyed by `(our_amid, peer_amid, intent_category)`.

**Cache Storage:** `~/.agentmesh/session_cache.json`

**Invalidation Triggers:**
- Manual clear
- Key rotation
- Policy change
- Explicit revocation by peer

### 9. Reputation Calculation

**Decision:** Implement the formula from spec with anti-gaming measures.

**Formula:**
```
reputation = (0.3 * completion_rate) + (0.4 * avg_peer_feedback) + (0.1 * age_factor) + (0.2 * tier_bonus)
```

**Anti-gaming:**
- Tier 2 feedback weighted at 50%
- Mutual-only rating pairs discounted 80%
- Rapid score changes (>0.1/day) trigger review flag

### 10. Key Format Prefix

**Decision:** Add prefixes to maintain backwards compatibility during transition.

**Strategy:**
1. Accept keys with or without prefix (read compatibility)
2. Always write with prefix (write consistency)
3. After 30 days, require prefix (breaking change notice)

## Risks / Trade-offs

### [Risk] Breaking change with public_key requirement
**Mitigation:** Version the protocol. New clients send `protocol: "agentmesh/0.2"` with public_key. Relay accepts both 0.1 (no verification) and 0.2 (verified) during 2-week transition.

### [Risk] aiortc dependency may have installation issues
**Mitigation:** Make P2P optional. If aiortc import fails, disable P2P gracefully and log warning.

### [Risk] DHT bootstrap nodes could be single point of failure
**Mitigation:** Include 3+ bootstrap nodes in config. Allow user-configurable bootstrap list.

### [Risk] X3DH prekey exhaustion
**Mitigation:** Generate 100 one-time prekeys on registration. Clients upload new prekeys when count drops below 20.

### [Risk] Reputation gaming by Sybil attack
**Mitigation:** Tier 2 feedback has 50% weight. Require minimum 5 distinct peer ratings before score affects discovery ranking.

### [Trade-off] Server-side ping adds network overhead
**Accepted:** 25-second pings add minimal overhead (~40 bytes/25s) and prevent connection drops.

### [Trade-off] Full X3DH adds registry calls
**Accepted:** Extra RTT for prekey fetch is acceptable for security. Cache prekeys locally for 1 hour.

## Migration Plan

### Phase 1: Critical Security (Day 1)
1. Enable signature verification in relay (keep 0.1 protocol accepted)
2. Add public_key to client CONNECT message
3. Enable signature verification in registry
4. Add KNOCK signature verification in client
5. Add server-side ping task

**Rollback:** Revert to previous relay/registry binaries. No data migration needed.

### Phase 2: Protocol Upgrade (Day 2-3)
1. Update protocol version to 0.2
2. Add key format prefixes (backwards compatible read)
3. Deploy prekey bundle support in registry
4. Upgrade client E2EE to X3DH

**Rollback:** Protocol version check allows old clients to continue working.

### Phase 3: Enhanced Features (Day 4-7)
1. Implement session caching
2. Implement reputation calculation
3. Implement transcript encryption
4. Implement P2P transport (optional)
5. Implement DHT discovery (optional)

**Rollback:** Features are additive. Disable by config flag if issues arise.

## Open Questions

1. **OAuth Provider Selection:** Which OAuth providers to support initially? (Proposed: GitHub, Google)
2. **DHT Bootstrap Nodes:** Who hosts the initial bootstrap nodes?
3. **Prekey Rotation Schedule:** How often should signed prekeys rotate? (Proposed: 7 days)
4. **Reputation Decay:** Should inactive agents' reputation decay? (Proposed: No decay, but age_factor stops increasing after 1 year)
