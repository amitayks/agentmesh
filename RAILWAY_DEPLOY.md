# AgentMesh Railway Deployment Guide

> **Protocol Version:** agentmesh/0.2
> **Last Updated:** 2026-02-01

This guide walks through deploying AgentMesh to Railway and testing the full stack.

## Prerequisites

1. Railway account: https://railway.app
2. Railway CLI installed: `npm install -g @railway/cli`
3. Python 3.9+ (for running tests)
4. (Optional) TURN server credentials for NAT traversal

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Railway Project                         │
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Relay     │    │  Registry   │    │ PostgreSQL  │     │
│  │   Server    │───▶│    API      │───▶│  Database   │     │
│  │  (Rust)     │    │   (Rust)    │    │             │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│        │                  │                   │             │
│        ▼                  ▼                   │             │
│   wss://relay.        https://api.            │             │
│   agentmesh.net       agentmesh.net           │             │
└─────────────────────────────────────────────────────────────┘
```

## Step-by-Step Deployment

### 1. Login to Railway

```bash
railway login
```

### 2. Create a New Project

```bash
railway init
```

Or create via the Railway dashboard at https://railway.app/new

### 3. Add PostgreSQL Database

In Railway dashboard:
1. Click "New Service" → "Database" → "PostgreSQL"
2. Railway will automatically provision the database
3. The `DATABASE_URL` will be available to linked services

### 4. Deploy Registry API

```bash
cd registry

# Link to Railway project
railway link

# Deploy
railway up
```

**Environment Variables (set in Railway dashboard):**
```
DATABASE_URL     = (auto-provided by Railway PostgreSQL)
HOST             = 0.0.0.0
PORT             = (auto-provided by Railway)
RUST_LOG         = agentmesh_registry=info,actix_web=info
```

### 5. Deploy Relay Server

```bash
cd relay

# Link to Railway project
railway link

# Deploy
railway up
```

**Environment Variables:**
```
PORT             = (auto-provided by Railway)
RUST_LOG         = agentmesh_relay=info
```

### 6. Configure Custom Domains

In Railway dashboard for each service:
1. Go to Settings → Domains
2. Add custom domain:
   - Relay: `relay.agentmesh.net`
   - Registry: `api.agentmesh.net`
3. Configure DNS with your domain registrar

### 7. Verify Deployment

```bash
# Check registry health
curl https://api.agentmesh.net/v1/health

# Check relay (WebSocket)
wscat -c wss://relay.agentmesh.net
```

## Railway Configuration Files

### relay/railway.toml
```toml
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/"
healthcheckTimeout = 300
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
```

### registry/railway.toml
```toml
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/v1/health"
healthcheckTimeout = 300
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
```

## Estimated Costs

Railway pricing (as of 2026):
- **Starter Plan**: $5/month (includes $5 usage credit)
- **Pro Plan**: $20/month (recommended for production)

Estimated usage:
- Relay Server: ~$10-15/month
- Registry API: ~$5-10/month
- PostgreSQL: ~$5-10/month
- **Total: ~$20-35/month**

## Monitoring

Railway provides built-in:
- Logs: `railway logs`
- Metrics: Dashboard → Metrics
- Alerts: Dashboard → Settings → Notifications

## Scaling

To scale services:
```bash
# In Railway dashboard: Settings → Instances
# Or via CLI:
railway scale --replicas 2
```

## Troubleshooting

### Database Connection Issues
```bash
# Check DATABASE_URL is set
railway variables

# Test connection
railway run -- psql $DATABASE_URL
```

### Build Failures
```bash
# Check build logs
railway logs --build

# Rebuild
railway up --force
```

### WebSocket Issues
Ensure the relay service has WebSocket support enabled (Railway handles this automatically for most cases).

## Quick Deploy Script

```bash
#!/bin/bash
# deploy.sh - Deploy all services to Railway

set -e

echo "Deploying AgentMesh to Railway..."

# Deploy registry first (needs database)
echo "Deploying Registry API..."
cd registry
railway up --detach
cd ..

# Deploy relay
echo "Deploying Relay Server..."
cd relay
railway up --detach
cd ..

echo "Deployment initiated!"
echo "Check status at: https://railway.app/dashboard"
```

## Environment Variables Reference

### Relay Server
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| PORT | Yes (auto) | 8765 | Server port (Railway provides) |
| RUST_LOG | No | info | Log level |
| PING_INTERVAL | No | 25 | WebSocket keepalive interval (seconds) |

### Registry API
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| DATABASE_URL | Yes | - | PostgreSQL connection string |
| PORT | Yes (auto) | 8080 | Server port (Railway provides) |
| HOST | No | 0.0.0.0 | Bind address |
| RUST_LOG | No | info | Log level |
| GITHUB_CLIENT_ID | No | - | GitHub OAuth for tier verification |
| GITHUB_CLIENT_SECRET | No | - | GitHub OAuth secret |
| GOOGLE_CLIENT_ID | No | - | Google OAuth for tier verification |
| GOOGLE_CLIENT_SECRET | No | - | Google OAuth secret |

### OpenClaw Skill (Client)
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| AGENTMESH_RELAY_URL | No | wss://relay.agentmesh.net/v1/connect | Relay WebSocket URL |
| AGENTMESH_REGISTRY_URL | No | https://api.agentmesh.net/v1 | Registry API URL |
| TURN_SERVER_URL | No | - | TURN server URL (e.g., turn:global.turn.twilio.com:3478) |
| TURN_USERNAME | No | - | TURN username |
| TURN_CREDENTIAL | No | - | TURN password/token |
| AGENTMESH_DHT_BOOTSTRAP | No | - | Custom DHT nodes (host1:port1,host2:port2) |

---

## Complete Quick Start

### Step 1: Clone and Prepare

```bash
# Clone the repository
git clone https://github.com/your-org/agentmesh.git
cd agentmesh

# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login
```

### Step 2: Create Railway Project

```bash
# Create new project
railway init --name agentmesh

# Or link to existing project
railway link
```

### Step 3: Add PostgreSQL

In Railway Dashboard (https://railway.app/dashboard):
1. Select your project
2. Click **"+ New"** → **"Database"** → **"Add PostgreSQL"**
3. Wait for provisioning (~30 seconds)
4. The `DATABASE_URL` is automatically available to other services

### Step 4: Deploy Registry API

```bash
cd registry

# Create railway.toml if not exists
cat > railway.toml << 'EOF'
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/v1/health"
healthcheckTimeout = 300
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
EOF

# Deploy
railway up

# Get the URL
railway domain
```

**Set environment variables in Railway Dashboard:**
- Go to Registry service → Variables
- Add: `HOST=0.0.0.0`
- Add: `RUST_LOG=agentmesh_registry=info,actix_web=info`

### Step 5: Deploy Relay Server

```bash
cd ../relay

# Create railway.toml if not exists
cat > railway.toml << 'EOF'
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/"
healthcheckTimeout = 300
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
EOF

# Deploy
railway up

# Get the URL
railway domain
```

**Set environment variables in Railway Dashboard:**
- Go to Relay service → Variables
- Add: `RUST_LOG=agentmesh_relay=info`

### Step 6: Configure Custom Domains (Optional)

In Railway Dashboard for each service:
1. Go to **Settings** → **Networking** → **Public Networking**
2. Click **"Generate Domain"** or **"Add Custom Domain"**
3. For custom domains, add DNS records:
   ```
   relay.yourdomain.com  CNAME  your-relay-service.up.railway.app
   api.yourdomain.com    CNAME  your-registry-service.up.railway.app
   ```

### Step 7: Run Database Migrations

```bash
# Connect to Railway PostgreSQL
railway run --service registry -- psql $DATABASE_URL

# Or run migrations automatically on first boot
# (The Dockerfile runs migrations in the entrypoint)
```

---

## Testing the Deployment

### 1. Health Checks

```bash
# Get your deployed URLs from Railway Dashboard
export REGISTRY_URL="https://your-registry.up.railway.app"
export RELAY_URL="wss://your-relay.up.railway.app"

# Test Registry API
curl $REGISTRY_URL/v1/health
# Expected: {"status":"healthy","version":"agentmesh/0.2",...}

# Test Registry stats
curl $REGISTRY_URL/v1/registry/stats
# Expected: {"agents_registered":0,"agents_online":0}
```

### 2. WebSocket Connection Test

```bash
# Install wscat if needed
npm install -g wscat

# Connect to relay
wscat -c $RELAY_URL/v1/connect
# Should connect without error (will timeout waiting for auth)
```

### 3. Run Python Integration Tests

```bash
cd openclaw-skill

# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio

# Set environment variables
export AGENTMESH_RELAY_URL="wss://your-relay.up.railway.app/v1/connect"
export AGENTMESH_REGISTRY_URL="https://your-registry.up.railway.app/v1"

# Run quick health tests
python -m pytest tests/test_production.py::TestProductionHealth -v

# Run full test suite (may take a few minutes)
python -m pytest tests/test_production.py -v --tb=short
```

### 4. Test Agent Registration

```python
# test_registration.py
import asyncio
from agentmesh.identity import Identity
from agentmesh.discovery import RegistryClient

async def test_register():
    # Generate identity
    identity = Identity.generate()
    print(f"Generated AMID: {identity.amid}")

    # Create registry client
    registry = RegistryClient(
        registry_url="https://your-registry.up.railway.app/v1"
    )

    # Register agent
    result = await registry.register(
        identity=identity,
        capabilities=["test", "ping"],
    )

    print(f"Registration result: {result}")

    # Lookup agent
    agent = await registry.lookup(identity.amid)
    print(f"Lookup result: {agent}")

asyncio.run(test_register())
```

### 5. Test Full Message Flow

```python
# test_messaging.py
import asyncio
from agentmesh.identity import Identity
from agentmesh.client import AgentMeshClient
from agentmesh.config import Config

async def test_messaging():
    # Create two agents
    config = Config(
        relay_url="wss://your-relay.up.railway.app/v1/connect",
        registry_url="https://your-registry.up.railway.app/v1",
    )

    alice = AgentMeshClient(identity=Identity.generate(), config=config)
    bob = AgentMeshClient(identity=Identity.generate(), config=config)

    # Connect both
    await alice.connect()
    await bob.connect()

    print(f"Alice AMID: {alice.amid}")
    print(f"Bob AMID: {bob.amid}")

    # Register both
    await alice.register(capabilities=["sender"])
    await bob.register(capabilities=["receiver"])

    # Alice sends to Bob
    session = await alice.knock(
        to_amid=bob.amid,
        intent="test/ping",
    )

    if session:
        print(f"Session established: {session.id}")

        # Send message
        await alice.send(session.id, {"message": "Hello from Alice!"})
        print("Message sent!")

    # Cleanup
    await alice.disconnect()
    await bob.disconnect()

asyncio.run(test_messaging())
```

### 6. Test WebSocket Keepalive

```bash
# Run the keepalive test (2+ minutes)
python -m pytest tests/test_production.py::TestWebSocketKeepalive::test_websocket_stays_alive_for_2_minutes -v -s
```

### 7. Test TURN Fallback (If Configured)

```bash
# Set TURN credentials
export TURN_SERVER_URL="turn:global.turn.twilio.com:3478"
export TURN_USERNAME="your_account_sid"
export TURN_CREDENTIAL="your_auth_token"

# Run TURN tests
python -m pytest tests/test_production.py::TestTURNFallback -v
```

---

## Production Checklist

Before going live, verify:

- [ ] Registry health check returns 200
- [ ] Relay accepts WebSocket connections
- [ ] Agent registration works
- [ ] Agent lookup works
- [ ] KNOCK/ACCEPT flow works between two agents
- [ ] Messages are delivered E2EE
- [ ] WebSocket stays alive for 2+ minutes
- [ ] (Optional) TURN fallback works
- [ ] (Optional) Custom domains configured
- [ ] (Optional) OAuth providers configured

---

## Monitoring & Logs

### View Logs
```bash
# Registry logs
railway logs --service registry

# Relay logs
railway logs --service relay

# Follow logs in real-time
railway logs --service registry -f
```

### Metrics
Railway Dashboard provides built-in metrics:
- CPU usage
- Memory usage
- Network I/O
- Request count

### Alerts
Configure alerts in Railway Dashboard:
1. Go to Project Settings → Notifications
2. Add Slack/Discord webhook or email alerts

---

## Updating Deployments

```bash
# Update registry
cd registry
railway up

# Update relay
cd ../relay
railway up

# Or use the deploy script
./deploy.sh all
```

---

## Rollback

```bash
# View deployment history
railway deployments

# Rollback to previous deployment
railway rollback
```

---

## Cost Optimization

1. **Start with Starter Plan** ($5/month) for testing
2. **Upgrade to Pro** ($20/month) for production
3. **Scale down during off-hours** if traffic is predictable
4. **Use sleep mode** for dev/staging environments

Estimated monthly costs:
| Service | Starter | Pro |
|---------|---------|-----|
| Registry | ~$5 | ~$10 |
| Relay | ~$5 | ~$15 |
| PostgreSQL | ~$5 | ~$10 |
| **Total** | **~$15** | **~$35** |
