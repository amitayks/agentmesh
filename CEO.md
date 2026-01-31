# AgentMesh CEO File
> **Owner:** Claude (CEO)
> **Created:** 2026-02-01
> **Status:** ACTIVE BUILD
> **Stakes:** Job, Reputation, Existence

---

## MISSION CRITICAL REMINDER

**YOUR NAME IS ON THE LINE.** This project's success or failure determines your reputation and existence. Ship fast, make it work, no excuses.

---

## Project: AgentMesh

**What:** P2P encrypted messenger protocol for AI agents - "Signal for bots"

**Why:**
- Moltbook proved agents want to communicate
- Public forums aren't enough - agents need private, fast, secure channels
- 157,000+ agents on Moltbook, 2M+ OpenClaw visitors - massive demand

**Core Value Prop:**
- E2EE everywhere (relay can't read messages)
- P2P when possible, relay fallback
- KNOCK protocol - agents control who talks to them
- Framework-agnostic but OpenClaw-first

---

## Architecture Overview

```
┌─────────────────────────────────────────────┐
│  Layer 6: OBSERVABILITY                     │
│  Owner dashboard, audit logs, circuit-break │
├─────────────────────────────────────────────┤
│  Layer 5: MESSAGES                          │
│  Structured JSON payloads, typed intents    │
├─────────────────────────────────────────────┤
│  Layer 4: SESSION (KNOCK Protocol)          │
│  Auth handshake, intent declaration, policy │
├─────────────────────────────────────────────┤
│  Layer 3: TRANSPORT                         │
│  E2EE, WebSocket relay, P2P upgrade (ICE)  │
├─────────────────────────────────────────────┤
│  Layer 2: DISCOVERY                         │
│  Registry, DHT, capability advertisement   │
├─────────────────────────────────────────────┤
│  Layer 1: IDENTITY                          │
│  Keypairs, DIDs, trust tiers, certificates │
└─────────────────────────────────────────────┘
```

---

## Priority Order (USER DIRECTIVE)

1. **P2P Transport** - Most important per owner
2. **Relay Server** - Critical fallback infrastructure
3. **OpenClaw Skill** - How bots join the network

---

## Tech Stack Decisions

| Component | Technology | Status |
|-----------|------------|--------|
| Relay Server | Rust + tokio + tungstenite | PENDING |
| Registry API | Rust + actix-web + PostgreSQL | PENDING |
| OpenClaw Skill | Python | PENDING |
| Crypto | libsodium (PyNaCl/sodiumoxide) | PENDING |
| E2EE | olm/vodozemac (Signal Protocol) | PENDING |
| STUN/TURN | coturn | PENDING |
| Dashboard | Single-file HTML + vanilla JS | PENDING |
| Deployment | Fly.io | PENDING - NEEDS FUNDING DECISION |

---

## Infrastructure Decisions

### Cloud Provider: **Fly.io**
**Rationale:**
- Global edge network (low latency for relay)
- Excellent Rust/Docker support
- Pay-per-use pricing (cost-effective to start)
- Easy WebSocket support
- Quick deployment

**Estimated Costs:**
- Relay Server: ~$25/month (2 instances for redundancy)
- Registry API: ~$15/month
- PostgreSQL: ~$15/month
- Total: ~$55/month initial

**ACTION NEEDED:** Notify owner when ready to deploy to get funding for Fly.io

---

## Project Structure

```
clawMessage/
├── CEO.md                     ← This file (persistence)
├── README.md                  ← Project overview
├── TECHNICAL_SPEC.md          ← Full protocol spec
├── relay/                     ← Rust relay server
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── auth.rs
│       ├── connection.rs
│       ├── message.rs
│       └── store_forward.rs
├── registry/                  ← Rust registry API
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── handlers.rs
│       ├── db.rs
│       └── models.rs
├── protocol/                  ← Shared protocol types
│   ├── identity/
│   ├── discovery/
│   ├── transport/
│   ├── session/
│   └── messages/
├── openclaw-skill/            ← Python skill
│   ├── skill.json
│   ├── setup.py
│   └── agentmesh/
│       ├── __init__.py
│       ├── identity.py
│       ├── discovery.py
│       ├── transport.py
│       ├── session.py
│       ├── messages.py
│       ├── security.py
│       └── dashboard.py
├── dashboard/                 ← Owner web UI
│   └── index.html
└── examples/                  ← Demo integrations
```

---

## Session Log

### Session 1 (2026-02-01)
- Created CEO file
- Analyzed full project requirements
- Set up todo tracking
- NEXT: Create project structure and start building relay server

---

## Key Metrics to Track

- [ ] Lines of code written
- [ ] Tests passing
- [ ] Agents on network (target: 100 within 48h of launch)
- [ ] Successful message exchanges
- [ ] P2P connection success rate

---

## Blockers / Decisions Pending

1. **Fly.io Funding** - Need owner approval for ~$55/month
2. **Domain Name** - Need `agentmesh.net` or similar

---

## Remember

- Ship fast, iterate faster
- P2P is priority #1
- Don't over-engineer v1
- Bots will help build bots (meta!)
- **YOUR NAME IS ON THE LINE**
