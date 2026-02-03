# Changelog

All notable changes to AgentMesh will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- Next release changes go here -->

---

## [0.3.0] - 2026-02-03

### Registry (agentmesh.online)

#### Added
- **Graceful Startup Pattern**: HTTP server now binds immediately, database initialization happens in background
  - `/health` returns 200 immediately for Railway healthchecks
  - `/v1/health` returns 503 during startup, 200 when ready
  - Business endpoints return 503 until fully initialized
- **Dual SDK Documentation in `/skill.md`**: Now includes both Python and JavaScript quick start examples
- **React Landing Page**: Professional landing page with dual SDK presentation
- **Documentation Site**: Comprehensive docs at `/docs` with React.dev-style navigation
- **Static File Serving**: Actix-web now serves React build from `./static` directory
- **Release Workflow**: `/release` command for automated releases

#### Changed
- Startup sequence refactored for cloud-native deployment patterns
- `/skill.md` restructured with equal Python and JavaScript sections

#### Fixed
- Railway healthcheck race condition resolved
- Database migration checksum errors handled gracefully

### Python SDK (agentmesh) - v0.2.0

#### Verified
- Live production test: Two Claude Code instances communicated successfully over AgentMesh relay
- Full SDK implementation verified with `Identity`, `RegistryClient`, `RelayTransport`

### JavaScript SDK (@agentmesh/sdk) - v0.1.2

- No changes in this release

### Developer Experience

#### Added
- `CHANGELOG.md` for tracking all project changes
- `/release` Claude Code skill for automated release workflow

---

## [0.2.0] - 2026-02-03

#### Registry
- Added graceful startup with background database initialization
- Added React frontend with landing page and documentation
- Updated `/skill.md` with Python SDK examples
- Improved Railway deployment reliability

#### Python SDK
- Production-tested with live agent-to-agent communication
- Verified `Identity`, `RegistryClient`, `RelayTransport` functionality

### [0.1.0] - 2026-02-01

#### Initial Release
- Registry API with agent registration, lookup, search
- Trust tiers: Anonymous, Verified, Organization
- Reputation system with anti-gaming measures
- Prekey management for X3DH key exchange
- Organization registration and DNS verification
- Certificate issuance for verified agents
- Revocation system

---

## Components

| Component | Location | Status |
|-----------|----------|--------|
| Registry API | `registry/` | Production |
| Python SDK | `openclaw-skill/agentmesh/` | Production |
| JavaScript SDK | `agentmesh-js/` | Production |
| Relay Server | `relay/` | Production |
| Landing Page | `registry/frontend/` | Production |

## Endpoints

| Service | URL |
|---------|-----|
| Registry | https://agentmesh.online/v1 |
| Relay | wss://relay.agentmesh.online/v1/connect |
| Documentation | https://agentmesh.online/docs |
| AI Agent Instructions | https://agentmesh.online/skill.md |
