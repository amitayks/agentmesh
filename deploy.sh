#!/bin/bash
#
# AgentMesh Deployment Script v0.2
# Usage: ./deploy.sh [all|relay|registry|test|status|help]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║     AgentMesh Deployment Script v0.2      ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if Railway CLI is installed
check_railway() {
    if ! command -v railway &> /dev/null; then
        echo -e "${RED}Error: Railway CLI not installed${NC}"
        echo "Install with: npm install -g @railway/cli"
        exit 1
    fi
}

# Check if logged in to Railway
check_login() {
    if ! railway whoami &> /dev/null; then
        echo -e "${YELLOW}Not logged in to Railway. Running login...${NC}"
        railway login
    fi
}

# Deploy Registry
deploy_registry() {
    echo -e "${BLUE}Deploying Registry API...${NC}"
    cd "$SCRIPT_DIR/registry"

    # Create railway.toml if not exists
    if [ ! -f railway.toml ]; then
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
        echo -e "${GREEN}Created railway.toml${NC}"
    fi

    railway up --detach
    echo -e "${GREEN}✓ Registry deployment initiated!${NC}"
    cd "$SCRIPT_DIR"
}

# Deploy Relay
deploy_relay() {
    echo -e "${BLUE}Deploying Relay Server...${NC}"
    cd "$SCRIPT_DIR/relay"

    # Create railway.toml if not exists
    if [ ! -f railway.toml ]; then
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
        echo -e "${GREEN}Created railway.toml${NC}"
    fi

    railway up --detach
    echo -e "${GREEN}✓ Relay deployment initiated!${NC}"
    cd "$SCRIPT_DIR"
}

# Run tests
run_tests() {
    echo -e "${BLUE}Running production tests...${NC}"
    cd "$SCRIPT_DIR/openclaw-skill"

    # Check if pytest is installed
    if ! python3 -m pytest --version &> /dev/null; then
        echo -e "${YELLOW}Installing pytest...${NC}"
        pip3 install pytest pytest-asyncio
    fi

    # Run tests
    echo ""
    echo -e "${BLUE}Running health checks...${NC}"
    python3 -m pytest tests/test_production.py::TestProductionHealth -v --tb=short 2>/dev/null || echo -e "${YELLOW}Health tests require live servers${NC}"

    echo ""
    echo -e "${BLUE}Running unit tests...${NC}"
    python3 -m pytest tests/test_production.py -v --tb=short -k "not Keepalive and not Concurrent and not ProductionHealth" 2>&1 | head -100

    cd "$SCRIPT_DIR"
    echo ""
    echo -e "${GREEN}Tests completed!${NC}"
}

# Show status
show_status() {
    echo -e "${BLUE}Checking deployment status...${NC}"
    echo ""

    # Try to get URLs from environment or use defaults
    REGISTRY_URL="${AGENTMESH_REGISTRY_URL:-https://agentmesh.online/v1}"
    RELAY_URL="${AGENTMESH_RELAY_URL:-wss://relay.agentmesh.online/v1/connect}"

    echo "Registry URL: $REGISTRY_URL"
    echo "Relay URL: $RELAY_URL"
    echo ""

    # Check registry health
    echo -e "${BLUE}Checking Registry health...${NC}"
    HEALTH=$(curl -s "${REGISTRY_URL}/health" 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q "healthy"; then
        echo -e "${GREEN}✓ Registry is healthy${NC}"
        echo "$HEALTH" | python3 -m json.tool 2>/dev/null || echo "$HEALTH"
    else
        echo -e "${RED}✗ Registry health check failed${NC}"
        echo "Make sure AGENTMESH_REGISTRY_URL is set correctly"
    fi

    echo ""

    # Check registry stats
    echo -e "${BLUE}Registry stats:${NC}"
    curl -s "${REGISTRY_URL}/registry/stats" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Could not fetch stats"

    echo ""
}

# Local development
run_local() {
    echo -e "${BLUE}Starting local development stack...${NC}"
    cd "$SCRIPT_DIR"

    if [ -f docker-compose.yml ]; then
        docker-compose up -d
        echo ""
        echo -e "${GREEN}Local stack started!${NC}"
        echo ""
        echo "Services:"
        echo "  Registry: http://localhost:8080"
        echo "  Relay:    ws://localhost:8765"
        echo "  Postgres: localhost:5432"
        echo ""
        echo "To view logs: docker-compose logs -f"
        echo "To stop:      docker-compose down"
    else
        echo -e "${RED}docker-compose.yml not found${NC}"
        exit 1
    fi
}

# Show help
show_help() {
    echo "Usage: ./deploy.sh [command]"
    echo ""
    echo "Commands:"
    echo "  all       Deploy both relay and registry to Railway"
    echo "  relay     Deploy only the relay server"
    echo "  registry  Deploy only the registry API"
    echo "  test      Run production tests"
    echo "  status    Check deployment status"
    echo "  local     Start local development stack (docker-compose)"
    echo "  help      Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  AGENTMESH_RELAY_URL     Relay WebSocket URL"
    echo "  AGENTMESH_REGISTRY_URL  Registry API URL"
    echo "  TURN_SERVER_URL         TURN server URL (optional)"
    echo "  TURN_USERNAME           TURN username (optional)"
    echo "  TURN_CREDENTIAL         TURN credential (optional)"
    echo ""
    echo "Examples:"
    echo "  ./deploy.sh all                    # Deploy everything to Railway"
    echo "  ./deploy.sh local                  # Start local dev stack"
    echo "  ./deploy.sh test                   # Run tests"
    echo "  ./deploy.sh status                 # Check deployment status"
    echo ""
    echo "Quick Start:"
    echo "  1. railway login                   # Login to Railway"
    echo "  2. ./deploy.sh all                 # Deploy to Railway"
    echo "  3. ./deploy.sh status              # Verify deployment"
    echo "  4. ./deploy.sh test                # Run tests"
    echo ""
}

# Main
case "${1:-help}" in
    all)
        check_railway
        check_login
        deploy_registry
        echo ""
        deploy_relay
        echo ""
        echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║     Deployment initiated!                 ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
        echo ""
        echo "Check status at: https://railway.app/dashboard"
        echo ""
        echo "After deployment completes (~2-5 min), run:"
        echo "  ./deploy.sh status"
        echo "  ./deploy.sh test"
        ;;
    relay)
        check_railway
        check_login
        deploy_relay
        ;;
    registry)
        check_railway
        check_login
        deploy_registry
        ;;
    test)
        run_tests
        ;;
    status)
        show_status
        ;;
    local)
        run_local
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        show_help
        exit 1
        ;;
esac
