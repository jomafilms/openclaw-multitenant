# OCMT Deployment & Sync Strategy

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         UPSTREAM                                     │
│              github.com/openclaw/openclaw                           │
│         (Agent framework, gateway, CLI, container image)            │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │ git fetch upstream
                                │ git merge upstream/main (selective)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         ORIGIN (GitHub)                              │
│              github.com/YOUR_ORG/YOUR_REPO                           │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ management-  │  │   user-ui/   │  │ agent-server │   + upstream  │
│  │   server/    │  │              │  │      /       │     openclaw  │
│  └──────────────┘  └──────────────┘  └──────────────┘     code      │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │ git push origin
                                │ GitHub Actions (CI/CD)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      PRODUCTION SERVERS                              │
│                                                                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │  Management      │  │     User UI      │  │   Agent Server   │  │
│  │  YOUR_MGMT_SERVER_IP  │  │  YOUR_UI_SERVER_IP  │  │  YOUR_AGENT_SERVER_IP  │  │
│  │  Port 3000       │  │  Nginx/Caddy     │  │  Port 4000       │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

| Component             | Source Dir           | Production                | What It Does                          |
| --------------------- | -------------------- | ------------------------- | ------------------------------------- |
| **Management Server** | `management-server/` | YOUR_MGMT_SERVER_IP:3000  | Auth, vault, integrations, MCP proxy  |
| **User UI**           | `user-ui/`           | YOUR_UI_SERVER_IP         | Web frontend (Lit components)         |
| **Agent Server**      | `agent-server/`      | YOUR_AGENT_SERVER_IP:4000 | Container orchestration + hibernation |
| **OpenClaw Image**    | upstream             | Docker Hub                | Agent container runtime               |

## Container Hibernation

The agent server implements automatic hibernation to reduce resource usage:

### States

| State       | Resource Usage            | Wake Time | When               |
| ----------- | ------------------------- | --------- | ------------------ |
| **running** | ~450MB RAM                | N/A       | Active, responding |
| **paused**  | ~50MB RAM (memory frozen) | ~100ms    | After 30min idle   |
| **stopped** | ~0 RAM (disk only)        | ~2-3s     | After 4hr paused   |

### How It Works

1. **Activity tracking**: Every chat/request updates `lastActivity` timestamp
2. **Periodic check**: Every 60s, checks for idle containers
3. **Auto-pause**: After 30min idle → `docker pause` (instant wake)
4. **Auto-stop**: After 4hr paused → `docker stop` (slower wake)
5. **Wake-on-request**: Any request auto-wakes the container

### Capacity Planning

| Droplet Size | Always-On Users | With Hibernation |
| ------------ | --------------- | ---------------- |
| 4GB RAM      | ~8 users        | ~50-100 users    |
| 8GB RAM      | ~16 users       | ~100-200 users   |
| 16GB RAM     | ~32 users       | ~200-400 users   |

_Assumes 10-20% concurrent active users at any time_

### API Endpoints

```bash
# Health check (includes hibernation stats)
curl http://YOUR_AGENT_SERVER_IP:4000/health
# → {"status":"ok","containers":10,"hibernation":{"running":2,"paused":6,"stopped":2}}

# List containers with idle time
curl -H "x-auth-token: ..." http://YOUR_AGENT_SERVER_IP:4000/api/containers
# → [{"userId":"...","hibernationState":"paused","idleMinutes":45}]

# Manual wake
curl -X POST -H "x-auth-token: ..." http://YOUR_AGENT_SERVER_IP:4000/api/containers/:userId/wake

# Manual hibernate
curl -X POST -H "x-auth-token: ..." -H "Content-Type: application/json" \
  -d '{"mode":"pause"}' http://YOUR_AGENT_SERVER_IP:4000/api/containers/:userId/hibernate
```

### Configuration

In `agent-server/server.js`:

```javascript
const PAUSE_AFTER_MS = 30 * 60 * 1000; // 30 minutes → pause
const STOP_AFTER_MS = 4 * 60 * 60 * 1000; // 4 hours → stop
const HIBERNATION_CHECK_INTERVAL = 60_000; // Check every minute
```

## Deployment Strategy

### Option A: GitHub Actions (Recommended)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy

on:
  push:
    branches: [main]
    paths:
      - "management-server/**"
      - "user-ui/**"
      - "agent-server/**"

jobs:
  deploy-management:
    if: contains(github.event.head_commit.modified, 'management-server/')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to management server
        uses: appleboy/ssh-action@v1
        with:
          host: YOUR_MGMT_SERVER_IP
          username: root
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          script: |
            cd /opt/management-server
            git pull origin main
            npm install --production
            pm2 restart ocmt-mgmt

  deploy-user-ui:
    if: contains(github.event.head_commit.modified, 'user-ui/')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - name: Build
        run: cd user-ui && npm ci && npm run build
      - name: Deploy
        uses: appleboy/scp-action@v0.1.7
        with:
          host: YOUR_UI_SERVER_IP
          username: root
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          source: "user-ui/dist/*"
          target: "/var/www/ocmt/"
          strip_components: 2

  deploy-agent:
    if: contains(github.event.head_commit.modified, 'agent-server/')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to agent server
        uses: appleboy/ssh-action@v1
        with:
          host: YOUR_AGENT_SERVER_IP
          username: root
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          script: |
            cd /opt/ocmt/agent-server
            git pull origin main
            npm install --production
            pm2 restart ocmt-agent
```

### Option B: Git-based Pull on Servers

Set up each server to pull from GitHub:

```bash
# On each production server
cd /opt/ocmt  # or /opt/management-server, etc.
git init
git remote add origin https://github.com/YOUR_ORG/YOUR_REPO.git
git fetch origin main
git checkout main

# Create deploy script
cat > /opt/deploy.sh << 'EOF'
#!/bin/bash
cd /opt/ocmt
git pull origin main
# Component-specific steps here
EOF
```

### Option C: Simple rsync Script (Current Approach, Improved)

Create `scripts/deploy.sh`:

```bash
#!/bin/bash
set -e

MGMT_HOST="root@YOUR_MGMT_SERVER_IP"
UI_HOST="root@YOUR_UI_SERVER_IP"
AGENT_HOST="root@YOUR_AGENT_SERVER_IP"

deploy_management() {
    echo "Deploying management server..."
    rsync -avz --delete \
        management-server/ \
        $MGMT_HOST:/opt/management-server/
    ssh $MGMT_HOST "cd /opt/management-server && npm install --production && pm2 restart ocmt-mgmt"
}

deploy_ui() {
    echo "Building user-ui..."
    cd user-ui && npm run build && cd ..
    echo "Deploying user-ui..."
    rsync -avz --delete \
        user-ui/dist/ \
        $UI_HOST:/var/www/ocmt/
}

deploy_agent() {
    echo "Deploying agent server..."
    rsync -avz --delete \
        agent-server/ \
        $AGENT_HOST:/opt/ocmt/agent-server/
    ssh $AGENT_HOST "cd /opt/ocmt/agent-server && npm install --production && pm2 restart ocmt-agent"
}

case "${1:-all}" in
    mgmt|management) deploy_management ;;
    ui|user-ui) deploy_ui ;;
    agent) deploy_agent ;;
    all)
        deploy_management
        deploy_ui
        deploy_agent
        ;;
    *) echo "Usage: $0 [mgmt|ui|agent|all]" ;;
esac

echo "Deploy complete!"
```

## Upstream Sync Strategy

### When to Sync

- **Security patches**: Immediately
- **Bug fixes**: As needed
- **New features**: Evaluate case-by-case
- **Breaking changes**: Plan migration

### How to Sync

```bash
# 1. Fetch upstream changes
git fetch upstream

# 2. See what's new
git log main..upstream/main --oneline

# 3. Review specific changes
git diff main..upstream/main -- src/  # Core changes
git diff main..upstream/main -- docs/ # Doc changes

# 4. Merge selectively (recommended)
git checkout -b upstream-sync
git cherry-pick <commit>  # Pick specific commits

# OR merge everything (if compatible)
git merge upstream/main

# 5. Test locally
npm test
npm run build

# 6. Push to origin
git push origin main
```

### Files to Watch

**Always sync** (security/stability):

- `src/infra/` - Core infrastructure
- `src/cli/` - CLI improvements
- `packages/` - Shared packages
- Security-related commits

**Evaluate before sync**:

- `src/channels/` - Channel implementations
- `extensions/` - Extensions (may conflict with custom work)
- `apps/` - Mobile/desktop apps

**Skip/careful**:

- `docs/` - May have ocmt-specific changes
- `.github/workflows/` - Custom CI/CD
- Config files at root

## Environment Variables

### Management Server (YOUR_MGMT_SERVER_IP)

```bash
# /opt/management-server/.env
DATABASE_URL=postgresql://...
JWT_SECRET=...
SMTP_HOST=...
SMTP_USER=...
SMTP_PASS=...
AGENT_SERVER_URL=http://YOUR_AGENT_SERVER_IP:4000
AGENT_AUTH_TOKEN=...
```

### Agent Server (YOUR_AGENT_SERVER_IP)

```bash
# /opt/ocmt/agent-server/.env
AUTH_TOKEN=...
DATA_DIR=/opt/ocmt/data
```

### User UI (YOUR_UI_SERVER_IP)

```bash
# Build-time (in user-ui/.env or CI)
VITE_API_URL=https://api.YOUR_DOMAIN
```

## Server Setup Checklist

### New Server Setup

```bash
# 1. Base setup
apt update && apt upgrade -y
apt install -y git nodejs npm nginx

# 2. Install Node 22
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs

# 3. Install PM2
npm install -g pm2

# 4. Clone repo
git clone https://github.com/YOUR_ORG/YOUR_REPO.git /opt/ocmt

# 5. Setup SSH deploy key (for GitHub Actions)
ssh-keygen -t ed25519 -f /root/.ssh/deploy_key -N ""
# Add public key to GitHub repo deploy keys
```

## Monitoring

### Health Checks

```bash
# Management server
curl http://YOUR_MGMT_SERVER_IP:3000/health

# Agent server
curl http://YOUR_AGENT_SERVER_IP:4000/health

# User UI
curl -I https://app.YOUR_DOMAIN
```

### Logs

```bash
# On each server
pm2 logs --lines 100

# Or
tail -f /root/.pm2/logs/ocmt-*.log
```

## Rollback

```bash
# Quick rollback using git
ssh root@SERVER "cd /opt/ocmt && git checkout HEAD~1 && pm2 restart all"

# Or restore from backup
ssh root@SERVER "cp -r /opt/backups/ocmt-YYYYMMDD /opt/ocmt && pm2 restart all"
```

## Version Tracking

Add to each component's package.json or create VERSION file:

```bash
# After each deploy, tag the deployment
git tag -a deploy/mgmt/$(date +%Y%m%d-%H%M) -m "Management server deploy"
git tag -a deploy/ui/$(date +%Y%m%d-%H%M) -m "User UI deploy"
git push --tags
```

## Quick Reference

```bash
# Deploy everything
./scripts/deploy.sh all

# Deploy single component
./scripts/deploy.sh mgmt
./scripts/deploy.sh ui
./scripts/deploy.sh agent

# Sync upstream
git fetch upstream
git merge upstream/main  # or cherry-pick

# Check production status
ssh root@YOUR_MGMT_SERVER_IP "pm2 status"
ssh root@YOUR_AGENT_SERVER_IP "pm2 status"
curl -s https://app.YOUR_DOMAIN | head -1
```
