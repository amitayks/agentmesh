# @agentmesh/sdk

TypeScript SDK for AgentMesh - a decentralized, end-to-end encrypted messaging protocol for AI agents.

## Features

- **End-to-End Encryption**: X3DH key exchange + Double Ratchet algorithm (Signal Protocol)
- **Decentralized Identity**: Ed25519-based identities with AgentMesh IDs (AMIDs)
- **Session Management**: KNOCK protocol for secure session establishment
- **Policy-Based Access Control**: Flexible policies for managing agent permissions
- **Transport Agnostic**: Pluggable transport layer (WebSocket, WebRTC, etc.)
- **Storage Abstraction**: Memory and persistent storage backends
- **DHT Integration**: Kademlia-based distributed hash table for peer discovery
- **DID Support**: Decentralized Identifier document generation and verification

## Installation

```bash
npm install @agentmesh/sdk
```

## Quick Start

```typescript
import { AgentMeshClient, MemoryStorage, Policy } from '@agentmesh/sdk';

// Create a new agent
const agent = new AgentMeshClient({
  storage: new MemoryStorage(),
  policy: Policy.permissive(),
});

// Initialize the agent
await agent.initialize();

// Get your AgentMesh ID
console.log('My AMID:', agent.amid);

// Connect to another agent
const session = await agent.connect(targetAmid, {
  intent: {
    capability: 'weather/forecast',
    action: 'query',
  },
});

// Send encrypted messages
await agent.send(session.sessionId, {
  type: 'query',
  location: 'New York',
});

// Receive messages
agent.onMessage((msg) => {
  console.log('Received:', msg.payload);
});
```

## Core Concepts

### Identity

Every agent has a cryptographic identity based on Ed25519 key pairs:

```typescript
import { Identity } from '@agentmesh/sdk';

// Generate a new identity
const identity = await Identity.generate();
console.log('AMID:', identity.amid);

// Save and load identity
await identity.save(storage, 'my-agent');
const loaded = await Identity.load(storage, 'my-agent');
```

### Session Establishment (KNOCK Protocol)

Sessions are established using the KNOCK protocol:

1. **KNOCK**: Initiator sends request with intent
2. **Evaluate**: Receiver evaluates against policy
3. **ACCEPT/REJECT**: Receiver responds
4. **Session**: Encrypted channel established

```typescript
import { KnockProtocol, Policy } from '@agentmesh/sdk';

const protocol = new KnockProtocol(identity);
protocol.setPolicy(Policy.verified());

// Create KNOCK request
const knock = await protocol.createKnock(targetAmid, {
  type: 'one-shot',
  ttl: 300,
  intent: { capability: 'chat/messages', action: 'send' },
});

// Validate and evaluate received KNOCK
const validation = await protocol.validateKnock(knock);
if (validation.valid) {
  const evaluation = await protocol.evaluateKnock(knock, senderInfo);
  if (evaluation.allowed) {
    const response = await protocol.createAcceptResponse(knock);
  }
}
```

### Encryption

End-to-end encryption using X3DH key exchange and Double Ratchet:

```typescript
import { PrekeyManager, SessionManager } from '@agentmesh/sdk';

// Initialize prekeys
const prekeyManager = new PrekeyManager(identity, storage);
const bundle = await prekeyManager.loadOrInitialize();

// Establish encrypted session
const sessionManager = new SessionManager(identity, storage, prekeyManager);
const { sessionId, x3dhMessage } = await sessionManager.initiateSession(
  peerAmid,
  peerBundle,
  peerSigningKey
);

// Exchange encrypted messages
const envelope = await sessionManager.encryptMessage(sessionId, { text: 'Hello!' });
const decrypted = await sessionManager.decryptMessage(sessionId, envelope);
```

### Policy

Control which agents can connect and what actions are allowed:

```typescript
import { Policy, Tier } from '@agentmesh/sdk';

// Predefined policies
const permissive = Policy.permissive(); // Accept all
const verified = Policy.verified();     // Require verified tier
const org = Policy.organization();      // Require organization tier

// Custom policy
const custom = new Policy({
  minimumTier: 'verified',
  minReputation: 0.7,
  allowedIntents: ['public/data', 'weather/*'],
  blockedIntents: ['admin/*'],
  blockedAmids: ['malicious-amid'],
  maxSessionTtl: 3600,
});
```

### Storage

Pluggable storage backends:

```typescript
import { MemoryStorage, FileStorage } from '@agentmesh/sdk';

// In-memory storage
const memory = new MemoryStorage();

// File-based storage
const file = new FileStorage('/path/to/data');
```

### Audit Logging

Track all agent activity:

```typescript
import { createAuditLogger } from '@agentmesh/sdk';

const logger = createAuditLogger(amid);

await logger.log('SESSION_INITIATED', 'INFO', 'Session started', {
  peerAmid: 'target-amid',
  sessionId: 'session-123',
});

// Query events
const errors = logger.getErrors();
const byPeer = logger.getByPeer('peer-amid');
const stats = logger.getStats();
```

## API Reference

### AgentMeshClient

Main client class for interacting with the AgentMesh network.

| Method | Description |
|--------|-------------|
| `initialize()` | Initialize the agent with identity and prekeys |
| `connect(amid, options)` | Establish session with another agent |
| `send(sessionId, message)` | Send encrypted message |
| `onMessage(handler)` | Register message handler |
| `getSession(sessionId)` | Get session info |
| `closeSession(sessionId)` | Close a session |
| `shutdown()` | Graceful shutdown |

### Identity

| Method | Description |
|--------|-------------|
| `Identity.generate()` | Generate new identity |
| `Identity.load(storage, key)` | Load from storage |
| `save(storage, key)` | Save to storage |
| `sign(data)` | Sign data with Ed25519 |
| `verify(data, signature, publicKey)` | Verify signature |

### SessionManager

| Method | Description |
|--------|-------------|
| `initiateSession(peerAmid, bundle, pubKey)` | Start new session |
| `acceptSession(peerAmid, x3dhMessage)` | Accept incoming session |
| `activateSession(sessionId, peerRatchetKey)` | Activate pending session |
| `encryptMessage(sessionId, plaintext)` | Encrypt message |
| `decryptMessage(sessionId, envelope)` | Decrypt message |
| `closeSession(sessionId)` | Close session |

### Policy

| Method | Description |
|--------|-------------|
| `Policy.permissive()` | Accept all connections |
| `Policy.verified()` | Require verified tier |
| `Policy.organization()` | Require organization tier |
| `evaluate(context)` | Evaluate KNOCK against policy |

## Project Structure

```
src/
├── identity.ts       # Identity management
├── storage/          # Storage backends
├── config.ts         # Configuration and Policy
├── encryption/       # X3DH and Double Ratchet
│   ├── x3dh.ts       # Extended Triple DH
│   ├── ratchet.ts    # Double Ratchet
│   ├── prekey.ts     # Prekey management
│   ├── session.ts    # Session management
│   └── hkdf.ts       # Key derivation
├── session/          # KNOCK protocol
├── schemas/          # Message validation
├── did/              # DID documents
├── dht/              # Distributed hash table
├── audit/            # Audit logging
├── transport/        # Transport layer
├── discovery/        # Agent discovery
├── certificates/     # Certificate handling
├── client.ts         # High-level client
└── index.ts          # Exports
```

## Security

- **Forward Secrecy**: Each message uses unique keys via Double Ratchet
- **Post-Compromise Security**: Key compromise doesn't affect past messages
- **Signature Verification**: All KNOCK messages are Ed25519 signed
- **Replay Protection**: Nonce-based replay attack prevention

## Testing

```bash
# Run all tests
npm test

# Run specific tests
npm test -- tests/unit/identity.test.ts
npm test -- tests/integration/encryption.test.ts
```

## Building

```bash
# Build for production
npm run build

# Output: dist/ with ESM, CJS, and type definitions
```

## License

MIT
