# AgentMesh Railway Deployment Guide

This guide walks through deploying AgentMesh to Railway.

## Prerequisites

1. Railway account: https://railway.app
2. Railway CLI installed: `npm install -g @railway/cli`

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

### Registry API
| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| DATABASE_URL | Yes | - | PostgreSQL connection string |
| PORT | Yes (auto) | 8080 | Server port (Railway provides) |
| HOST | No | 0.0.0.0 | Bind address |
| RUST_LOG | No | info | Log level |
