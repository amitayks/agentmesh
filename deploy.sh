#!/bin/bash
# AgentMesh Railway Deployment Script
# Usage: ./deploy.sh [relay|registry|all]

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════╗"
echo "║     AgentMesh Railway Deployment          ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Check if railway CLI is installed
if ! command -v railway &> /dev/null; then
    echo -e "${RED}Railway CLI not found. Installing...${NC}"
    npm install -g @railway/cli
fi

# Check if logged in
if ! railway whoami &> /dev/null; then
    echo -e "${YELLOW}Please login to Railway:${NC}"
    railway login
fi

deploy_relay() {
    echo -e "${GREEN}Deploying Relay Server...${NC}"
    cd relay
    railway up --detach
    cd ..
    echo -e "${GREEN}✓ Relay deployment initiated${NC}"
}

deploy_registry() {
    echo -e "${GREEN}Deploying Registry API...${NC}"
    cd registry
    railway up --detach
    cd ..
    echo -e "${GREEN}✓ Registry deployment initiated${NC}"
}

case "${1:-all}" in
    relay)
        deploy_relay
        ;;
    registry)
        deploy_registry
        ;;
    all)
        echo -e "${YELLOW}Deploying all services...${NC}"
        echo ""
        deploy_registry
        echo ""
        deploy_relay
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════${NC}"
        echo -e "${GREEN}All deployments initiated!${NC}"
        echo -e "${GREEN}Check status: https://railway.app/dashboard${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════${NC}"
        ;;
    *)
        echo "Usage: $0 [relay|registry|all]"
        exit 1
        ;;
esac
