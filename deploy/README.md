# OCMT MVP Deployment

Quick deployment for tonight's demo.

## Prerequisites

1. DigitalOcean droplet (Ubuntu 22.04, 4GB RAM recommended)
2. Telegram bot token from @BotFather
3. Claude Max subscription (for setup-token auth)

## Quick Deploy (15-20 minutes)

### 1. Create Droplet

In DigitalOcean:

- Image: Ubuntu 22.04
- Size: Basic, 4GB RAM / 2 vCPU ($24/mo) - or 2GB for testing
- Region: Closest to you
- SSH key: Add yours

### 2. SSH into Droplet

```bash
ssh root@YOUR_DROPLET_IP
```

### 3. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
```

### 4. Install OpenClaw directly (simpler than Docker for demo)

```bash
# Install Node.js 22
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs

# Install OpenClaw globally
npm install -g openclaw@latest

# Verify
openclaw --version
```

### 5. Configure OpenClaw

```bash
# Create config directory
mkdir -p ~/.openclaw

# Create config file
cat > ~/.openclaw/openclaw.json << 'EOF'
{
  "gateway": {
    "port": 18789,
    "bind": "lan",
    "auth": {
      "token": "YOUR_GATEWAY_TOKEN_HERE"
    }
  },
  "channels": {
    "telegram": {
      "token": "YOUR_TELEGRAM_BOT_TOKEN",
      "dmPolicy": "open"
    }
  },
  "agents": {
    "defaults": {
      "workspace": "~/.openclaw/workspace"
    }
  }
}
EOF
```

Replace:

- `YOUR_GATEWAY_TOKEN_HERE` with a random string (use `openssl rand -hex 32`)
- `YOUR_TELEGRAM_BOT_TOKEN` with your bot token from @BotFather

### 6. Set up Claude Auth

```bash
# If you have Claude CLI installed locally, get the setup token:
# claude setup-token

# Then on the server:
openclaw models auth setup-token --provider anthropic
# Paste the token when prompted
```

### 7. Start the Gateway

```bash
# Run in foreground (for testing)
openclaw gateway --bind lan --port 18789 --verbose

# Or run as a service (for demo)
openclaw gateway --bind lan --port 18789 &
```

### 8. Test It

1. **Telegram**: Message your bot - it should respond!
2. **Web UI**: Open `http://YOUR_DROPLET_IP:18789` in browser
   - Enter your gateway token to log in

## Firewall

Make sure port 18789 is open:

```bash
ufw allow 18789
ufw allow 22
ufw enable
```

## Adding Test Users (Multi-Agent)

Edit `~/.openclaw/openclaw.json` to add agents:

```json
{
  "agents": {
    "list": [
      { "id": "alice", "workspace": "~/.openclaw/workspaces/alice" },
      { "id": "bob", "workspace": "~/.openclaw/workspaces/bob" }
    ]
  },
  "bindings": [
    { "agentId": "alice", "match": { "channel": "telegram", "peer": "ALICE_TELEGRAM_ID" } },
    { "agentId": "bob", "match": { "channel": "telegram", "peer": "BOB_TELEGRAM_ID" } }
  ]
}
```

To find someone's Telegram ID:

1. Have them message the bot
2. Check the logs - you'll see their `chat.id`
3. Add it to the bindings

## Troubleshooting

**Bot not responding?**

```bash
# Check if gateway is running
ps aux | grep openclaw

# Check logs
journalctl -u openclaw -f  # if running as service

# Or check terminal output if running in foreground
```

**Can't connect to web UI?**

- Check firewall: `ufw status`
- Check gateway is listening: `netstat -tlnp | grep 18789`
- Try with IP directly: `http://DROPLET_IP:18789`

**Auth issues?**

```bash
openclaw models status
# Should show your auth profile as working
```
