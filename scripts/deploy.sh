#!/bin/bash
# OCMT Production Deployment Script
# Usage: ./scripts/deploy.sh [mgmt|ui|agent|all]
#
# Configure servers via environment variables or .env file:
#   DEPLOY_MGMT_HOST=root@1.2.3.4
#   DEPLOY_UI_HOST=root@1.2.3.5
#   DEPLOY_AGENT_HOST=root@1.2.3.6

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Load .env if present
if [[ -f "$ROOT_DIR/.env" ]]; then
    set -a
    source "$ROOT_DIR/.env"
    set +a
fi

MGMT_HOST="${DEPLOY_MGMT_HOST:-}"
UI_HOST="${DEPLOY_UI_HOST:-}"
AGENT_HOST="${DEPLOY_AGENT_HOST:-}"

# Extract IP from host string (user@ip -> ip)
get_ip() {
    echo "$1" | sed 's/.*@//'
}

cd "$ROOT_DIR"

log() {
    echo "[$(date '+%H:%M:%S')] $1"
}

check_host() {
    local name="$1"
    local var="$2"
    local value="$3"
    if [[ -z "$value" ]]; then
        echo "Error: $var not set. Add to .env or export it."
        echo "Example: $var=root@1.2.3.4"
        exit 1
    fi
}

deploy_management() {
    check_host "Management" "DEPLOY_MGMT_HOST" "$MGMT_HOST"
    local ip=$(get_ip "$MGMT_HOST")

    log "Deploying management server to $MGMT_HOST..."

    # Sync files
    rsync -avz --delete \
        --exclude 'node_modules' \
        --exclude '.env' \
        management-server/ \
        $MGMT_HOST:/opt/management-server/

    # Install deps and restart
    ssh $MGMT_HOST "cd /opt/management-server && npm install --omit=dev && pm2 restart ocmt-mgmt"

    # Verify
    sleep 2
    if curl -sf "http://$ip:3000/health" > /dev/null; then
        log "Management server: OK"
    else
        log "Management server: FAILED health check!"
        exit 1
    fi
}

deploy_ui() {
    check_host "UI" "DEPLOY_UI_HOST" "$UI_HOST"

    log "Building user-ui..."
    cd "$ROOT_DIR/user-ui"
    npm run build
    cd "$ROOT_DIR"

    log "Deploying user-ui to $UI_HOST..."
    rsync -avz --delete \
        user-ui/dist/ \
        $UI_HOST:/var/www/ocmt/

    log "User UI: Deployed"
}

deploy_agent() {
    check_host "Agent" "DEPLOY_AGENT_HOST" "$AGENT_HOST"
    local ip=$(get_ip "$AGENT_HOST")

    log "Deploying agent server to $AGENT_HOST..."

    # Sync files
    rsync -avz --delete \
        --exclude 'node_modules' \
        --exclude '.env' \
        agent-server/ \
        $AGENT_HOST:/opt/ocmt/agent-server/

    # Install deps and restart
    ssh $AGENT_HOST "cd /opt/ocmt/agent-server && npm install --omit=dev && pm2 restart ocmt-agent"

    # Verify
    sleep 2
    if curl -sf "http://$ip:4000/health" > /dev/null; then
        log "Agent server: OK"
    else
        log "Agent server: FAILED health check!"
        exit 1
    fi
}

deploy_admin() {
    check_host "Agent" "DEPLOY_AGENT_HOST" "$AGENT_HOST"

    log "Deploying admin-ui to $AGENT_HOST..."

    # Sync files (admin-ui runs on agent server)
    rsync -avz --delete \
        --exclude 'node_modules' \
        --exclude '.env' \
        admin-ui/ \
        $AGENT_HOST:/opt/ocmt/admin-ui/

    # Install deps and restart
    ssh $AGENT_HOST "cd /opt/ocmt/admin-ui && npm install --omit=dev && pm2 restart ocmt-admin || pm2 start server.js --name ocmt-admin"

    log "Admin UI: Deployed"
}

check_status() {
    log "Checking production status..."
    echo ""

    if [[ -n "$MGMT_HOST" ]]; then
        local mgmt_ip=$(get_ip "$MGMT_HOST")
        echo "Management Server ($mgmt_ip):"
        curl -s "http://$mgmt_ip:3000/health" || echo "UNREACHABLE"
        echo ""
    fi

    if [[ -n "$AGENT_HOST" ]]; then
        local agent_ip=$(get_ip "$AGENT_HOST")
        echo "Agent Server ($agent_ip):"
        curl -s "http://$agent_ip:4000/health" || echo "UNREACHABLE"
        echo ""
    fi
}

show_diff() {
    log "Checking differences between local and production..."
    echo ""

    if [[ -n "$MGMT_HOST" ]]; then
        echo "Management Server:"
        ssh $MGMT_HOST "wc -l /opt/management-server/server.js" 2>/dev/null || echo "  Cannot connect"
        echo "  Local: $(wc -l < management-server/server.js) lines"
        echo ""
    fi

    if [[ -n "$AGENT_HOST" ]]; then
        echo "Agent Server:"
        ssh $AGENT_HOST "wc -l /opt/ocmt/agent-server/server.js" 2>/dev/null || echo "  Cannot connect"
        echo "  Local: $(wc -l < agent-server/server.js) lines"
    fi
}

case "${1:-help}" in
    mgmt|management)
        deploy_management
        ;;
    ui|user-ui)
        deploy_ui
        ;;
    agent)
        deploy_agent
        ;;
    admin|admin-ui)
        deploy_admin
        ;;
    all)
        deploy_management
        deploy_ui
        deploy_agent
        deploy_admin
        log "All deployments complete!"
        ;;
    status)
        check_status
        ;;
    diff)
        show_diff
        ;;
    help|*)
        echo "OCMT Deployment Script"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  mgmt, management  Deploy management server"
        echo "  ui, user-ui       Build and deploy user UI"
        echo "  agent             Deploy agent server"
        echo "  admin, admin-ui   Deploy admin UI"
        echo "  all               Deploy everything"
        echo "  status            Check production health"
        echo "  diff              Compare local vs production"
        echo ""
        echo "Configuration (via .env or environment):"
        echo "  DEPLOY_MGMT_HOST   e.g. root@1.2.3.4"
        echo "  DEPLOY_UI_HOST     e.g. root@1.2.3.5"
        echo "  DEPLOY_AGENT_HOST  e.g. root@1.2.3.6"
        ;;
esac
