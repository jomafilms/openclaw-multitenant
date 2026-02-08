# OCMT Security Skill - Deployment Guide

## Files in This Folder

| File                            | Purpose                                 |
| ------------------------------- | --------------------------------------- |
| `SKILL.md`                      | The skill itself - copy to containers   |
| `mcp-endpoint-example.js`       | MCP endpoint code for management server |
| `container-config-example.json` | Config to inject at provisioning        |

## Deployment Steps

### 1. Add Skill to Container Image

```dockerfile
# In your Dockerfile
COPY skills/ocmt-security /opt/ocmt/skills/ocmt-security
```

### 2. Add MCP Endpoint to Management Server

```javascript
// In management-server/server.js
const { mcpHandler, requireInternalAuth } = require("./mcp-endpoint-example");

app.post("/api/mcp", requireInternalAuth, mcpHandler(db));
```

### 3. Inject Config at Container Provisioning

When creating a new container, merge into `~/.openclaw/openclaw.json`:

```javascript
// In agent-server provisioning code
const config = JSON.parse(fs.readFileSync(openclawConfigPath));

config.mcpServers = {
  ocmt: {
    url: "https://YOUR_DOMAIN/api/mcp",
    headers: {
      Authorization: `Bearer ${containerToken}`,
      "X-User-Id": userId,
    },
  },
};

config.skills = config.skills || {};
config.skills.load = config.skills.load || {};
config.skills.load.extraDirs = ["/opt/ocmt/skills"];

fs.writeFileSync(openclawConfigPath, JSON.stringify(config, null, 2));
```

### 4. Test

```bash
# From inside container
mcporter list ocmt --schema
mcporter call ocmt.ocmt_vault_status
```

## Database Schema Required

Your management server DB needs:

```sql
-- Vault sessions
CREATE TABLE vault_sessions (
  user_id TEXT PRIMARY KEY,
  unlocked_at TIMESTAMP,
  expires_at TIMESTAMP
);

-- Unlock tokens
CREATE TABLE unlock_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT,
  expires_at TIMESTAMP,
  used_at TIMESTAMP
);

-- User integrations
CREATE TABLE user_integrations (
  user_id TEXT,
  provider TEXT, -- 'google', 'microsoft', etc
  status TEXT,   -- 'connected', 'expired', 'error'
  scopes TEXT[],
  last_sync_at TIMESTAMP,
  PRIMARY KEY (user_id, provider)
);
```

## Environment Variables

Container needs:

- `OCMT_CONTAINER_TOKEN` - Auth token for MCP calls
- `OCMT_USER_ID` - User ID for this container

Management server needs:

- `OCMT_BASE_URL` - Your domain (https://YOUR_DOMAIN)
