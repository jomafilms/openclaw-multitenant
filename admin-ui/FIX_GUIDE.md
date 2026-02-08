# OCMT Fix Guide - Agent Write Tools Not Working

## The Problem

The agent can **read** workspace files but **cannot write** to them. This causes:

- USER.md stays blank (not updated during bootstrap)
- IDENTITY.md stays blank (agent can't save its identity)
- BOOTSTRAP.md never gets deleted (first-run ritual never completes)
- Memory files never get created

## Root Cause

OpenClaw has a **sandboxing feature** that, when enabled with default settings:

- Redirects write operations to an isolated sandbox directory (`~/.openclaw/sandboxes/`)
- The agent's actual workspace remains untouched
- This is a security feature for multi-tenant deployments

For OCMT's use case (each user owns their workspace), we need writes to persist to the actual workspace.

## The Fix

### Step 1: Update the OpenClaw config

SSH into your server and edit `/root/.openclaw/openclaw.json`:

```bash
nano /root/.openclaw/openclaw.json
```

Add or update the `sandbox` configuration to disable it:

```json
{
  "gateway": {
    "mode": "local",
    "port": 18789,
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "YOUR_TOKEN_HERE"
    }
  },
  "agents": {
    "defaults": {
      "workspace": "/root/.openclaw/workspace",
      "sandbox": {
        "mode": "off"
      }
    },
    "list": [
      // your user agents here
    ]
  },
  "channels": {
    "telegram": {
      "token": "YOUR_TELEGRAM_BOT_TOKEN",
      "dmPolicy": "pairing"
    }
  }
}
```

**Key change**: Add `"sandbox": { "mode": "off" }` under `agents.defaults`

### Step 2: Initialize the default workspace

Run the initialization script:

```bash
chmod +x /path/to/admin-ui/init-workspace.sh
./init-workspace.sh
```

This creates the template files (AGENTS.md, SOUL.md, USER.md, IDENTITY.md, BOOTSTRAP.md) in `/root/.openclaw/workspace/`.

### Step 3: Restart the gateway

```bash
# Kill existing gateway
pkill -f "openclaw gateway" || pkill -f "clawdbot" || true

# Start fresh
nohup openclaw gateway --bind lan --port 18789 --verbose > /var/log/openclaw.log 2>&1 &
```

### Step 4: Signal config reload (if not restarting)

If you can't restart, signal the gateway to reload:

```bash
pkill -USR1 -f "openclaw gateway"
```

### Step 5: For existing users - reset their workspaces

If users already signed up but have broken workspaces:

```bash
# Re-copy template files to a user's workspace
USER_ID="rob-fmro"  # replace with actual user ID
cp /root/.openclaw/workspace/*.md /root/.openclaw/workspaces/$USER_ID/
```

## Alternative: Enable sandbox with workspace write access

If you want sandboxing for security but still need workspace writes:

```json
{
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "workspaceAccess": "rw"
      }
    }
  }
}
```

This runs tool execution in Docker containers but mounts the workspace with read/write access.

## Verify the fix

1. Sign up as a new user
2. Chat with the agent
3. The agent should:
   - Ask about your name
   - Ask about what to call the AI
   - **Update USER.md** with your info (check the file!)
   - **Update IDENTITY.md** with the AI's chosen identity
   - **Delete BOOTSTRAP.md** when onboarding is complete

Check the workspace:

```bash
cat /root/.openclaw/workspaces/YOUR_USER_ID/USER.md
cat /root/.openclaw/workspaces/YOUR_USER_ID/IDENTITY.md
ls /root/.openclaw/workspaces/YOUR_USER_ID/  # BOOTSTRAP.md should be gone
```

## Quick Diagnostic

```bash
# Run the diagnostic script
chmod +x diagnose.sh
./diagnose.sh
```

This checks:

- OpenClaw installation
- Config file
- Workspace files
- Permissions
- Gateway process
- Auth profiles

## File Structure Reference

Each user workspace should contain:

```
/root/.openclaw/workspaces/{user-id}/
├── AGENTS.md       # Operating instructions (read every session)
├── SOUL.md         # Persona definition (read every session)
├── USER.md         # User info (updated during bootstrap)
├── IDENTITY.md     # AI identity (created during bootstrap)
├── BOOTSTRAP.md    # First-run ritual (DELETED after completion)
├── TOOLS.md        # Tool notes (optional)
└── memory/         # Daily memory logs
    └── YYYY-MM-DD.md
```
