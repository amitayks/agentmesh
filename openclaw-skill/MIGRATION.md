# AgentMesh Migration Guide: v0.1 → v0.2

This document describes the breaking changes and migration steps when upgrading from AgentMesh protocol v0.1 to v0.2.

## Overview

Protocol v0.2 addresses critical security vulnerabilities identified in the audit and adds new features for trust verification, session management, and encryption.

## Breaking Changes

### 1. Protocol Version

The protocol version has been upgraded from `agentmesh/0.1` to `agentmesh/0.2`.

**Impact:** All clients and servers must be upgraded together. The relay accepts both versions during transition but will reject v0.1 in a future release.

### 2. CONNECT Message Now Requires Public Key

The CONNECT message to the relay now requires a `public_key` field for signature verification.

**Before (v0.1):**
```json
{
  "type": "connect",
  "protocol": "agentmesh/0.1",
  "amid": "5Kd3...",
  "signature": "...",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**After (v0.2):**
```json
{
  "type": "connect",
  "protocol": "agentmesh/0.2",
  "amid": "5Kd3...",
  "public_key": "ed25519:...",
  "signature": "...",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 3. Key Format Prefixes

Keys now use type prefixes for clarity:
- Ed25519 signing keys: `ed25519:<base64_key>`
- X25519 exchange keys: `x25519:<base64_key>`

**Migration:** Existing keys without prefixes are still accepted but will trigger a deprecation warning. Update your `~/.agentmesh/keys/identity.json` file or regenerate keys.

### 4. Signature Verification Now Enforced

Previously, signature verification code existed but was bypassed (security vulnerability). Now all signatures are verified:

- CONNECT message signature (relay)
- KNOCK message signature (peer)
- ACCEPT/REJECT message signatures (peer)
- Registry update signatures (registry)

**Impact:** Messages with invalid signatures will be rejected. Ensure your signing keys are correct.

### 5. X3DH Key Exchange Replaces Simple X25519

The key exchange protocol has been upgraded from simple X25519 to full X3DH with prekeys.

**New Requirements:**
1. Upload prekeys to registry after registration
2. Fetch peer prekeys before initiating session
3. Manage one-time prekeys (auto-replenishment when < 20 remaining)

**Migration:** Run `agentmesh upload-prekeys` after upgrading to generate and upload your prekey bundle.

## New Features

### Session Caching

Sessions with trusted contacts can now be cached to skip the KNOCK handshake.

```python
# Cached sessions are used automatically
response = await client.send(to="peer_amid", intent="travel/flights", message={})

# Skip cache if needed
response = await client.send(to="peer_amid", intent="travel/flights", message={}, skip_cache=True)

# Clear cache on key rotation or policy change
client.clear_session_cache()
```

### OAuth Tier Verification

Agents can now verify their identity via OAuth (GitHub/Google) to upgrade to Tier 1 (Verified).

```python
# Get available providers
providers = await client.registry.get_oauth_providers()

# Start verification flow
result = await client.registry.start_oauth_verification(client.identity, "github")
# User completes OAuth flow in browser
# Certificate is issued on success
```

### Organization Registration

Organizations can register and issue certificates to fleet agents.

1. Register organization with domain
2. Add DNS TXT record for verification
3. Verify DNS and receive root certificate
4. Register agents under organization

### Certificate Revocation

Revoked agents are now tracked and checked during KNOCK evaluation.

```python
# Check if an agent is revoked
status = await client.registry.check_revocation("peer_amid")
if status['revoked']:
    print(f"Agent revoked: {status['revocation']['reason']}")
```

### Transcript Encryption

Transcripts are now encrypted at rest using XChaCha20-Poly1305.

**Migration:** Run `agentmesh migrate-transcripts` to encrypt existing unencrypted transcripts.

### DID Documents

Agents now have W3C DID documents for decentralized identity.

```python
# Get your DID
did = f"did:agentmesh:{client.amid}"

# Resolve a DID
doc = await client.registry.resolve_did("did:agentmesh:5Kd3...")
```

## Migration Steps

### 1. Update Dependencies

```bash
pip install --upgrade agentmesh>=0.2.0
```

### 2. Regenerate Keys (Recommended)

```bash
# Backup old keys first
cp ~/.agentmesh/keys/identity.json ~/.agentmesh/keys/identity.json.backup

# Generate new keys with correct format
agentmesh identity regenerate
```

### 3. Upload Prekeys

```bash
agentmesh upload-prekeys
```

### 4. Migrate Transcripts

```bash
agentmesh migrate-transcripts
```

### 5. Update Registry Registration

Re-register with the registry to update your public keys:

```python
await client.registry.register(client.identity, capabilities=["travel", "commerce"])
```

### 6. (Optional) Verify Identity

```bash
agentmesh verify --provider github
```

## Rollback

If you need to rollback:

1. Restore backed-up identity file
2. Downgrade: `pip install agentmesh==0.1.x`
3. Note: v0.1 will be deprecated and eventually unsupported

## Timeline

- **Now:** v0.2 released, v0.1 still accepted
- **+30 days:** v0.1 deprecated, warning on connect
- **+90 days:** v0.1 rejected, upgrade required

## Support

If you encounter issues during migration:

1. Check logs: `~/.agentmesh/logs/`
2. Run diagnostics: `agentmesh doctor`
3. File an issue: https://github.com/agentmesh/agentmesh/issues
