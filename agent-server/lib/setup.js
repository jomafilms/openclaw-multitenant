// Container setup and repair logic
import fs from "fs";
import path from "path";

const DATA_DIR = "/opt/ocmt/data";

/**
 * Ensure container directories and config exist
 * Called during provisioning and on startup for existing containers
 */
export function ensureContainerSetup(userId) {
  const userDataDir = path.join(DATA_DIR, userId);
  const workspaceDir = path.join(userDataDir, "workspace");

  // Create directories if missing
  const dirsToCreate = [
    userDataDir,
    workspaceDir,
    path.join(userDataDir, "agents"),
    path.join(userDataDir, "agents", "main"),
    path.join(userDataDir, "agents", "main", "agent"),
    path.join(userDataDir, "agents", "main", "sessions"),
    path.join(workspaceDir, "memory"),
    path.join(workspaceDir, "skills"),
    path.join(workspaceDir, ".ocmt"),
  ];

  for (const dir of dirsToCreate) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      fs.chownSync(dir, 1000, 1000);
    }
  }

  // Ensure openclaw.json has correct config
  const configPath = path.join(userDataDir, "openclaw.json");
  let config = {};
  let needsUpdate = false;

  try {
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    }
  } catch (e) {
    // Invalid JSON, will recreate
  }

  // Ensure agents config with sandbox OFF
  if (!config.agents) {
    config.agents = {};
    needsUpdate = true;
  }
  if (!config.agents.defaults) {
    config.agents.defaults = {};
    needsUpdate = true;
  }
  if (config.agents.defaults.workspace !== "/home/node/.openclaw/workspace") {
    config.agents.defaults.workspace = "/home/node/.openclaw/workspace";
    needsUpdate = true;
  }
  if (!config.agents.defaults.sandbox || config.agents.defaults.sandbox.mode !== "off") {
    config.agents.defaults.sandbox = { mode: "off" };
    needsUpdate = true;
  }

  if (needsUpdate) {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    fs.chownSync(configPath, 1000, 1000);
    fs.chmodSync(configPath, 0o644);
  }

  // Create template files if missing
  createTemplateFiles(workspaceDir);

  return config;
}

/**
 * Create template files for agent workspace
 */
function createTemplateFiles(workspaceDir) {
  const templates = [
    {
      path: path.join(workspaceDir, "memory", "MEMORY.md"),
      content: `# Agent Memory

This file stores important context and memories from conversations.

## User Preferences

## Important Context

## Recent Learnings
`,
    },
    {
      // OCMT customization — not from upstream OpenClaw.
      // This file teaches the agent how to discover its own integrations and tools.
      path: path.join(workspaceDir, ".ocmt", "IDENTITY.md"),
      content: `# Agent Identity

You are a helpful AI assistant running on the OCMT (OpenClaw Multi-Tenant) platform.

## Discovering Your Integrations

On startup or when asked about capabilities, check these files:

- \`.ocmt/integrations.json\` — lists all services the user has connected (e.g. google_calendar, google_gmail, google_drive, anthropic). Always check this file before saying you don't have access to a service.
- \`.ocmt/context.md\` — full instructions for using the OCMT tools, including how to fetch credentials, call group resources, and manage the vault.
- \`.ocmt/mcp-client.sh\` — the tool you use to interact with OCMT services.

## Quick Reference

**Check what's connected:**
\`\`\`
cat .ocmt/integrations.json
\`\`\`

**Get credentials for a service (vault must be unlocked):**
\`\`\`
.ocmt/mcp-client.sh ocmt_get_credentials '{"provider":"google_calendar"}'
\`\`\`

**Check vault status:**
\`\`\`
.ocmt/mcp-client.sh ocmt_vault_status
\`\`\`

**List connected integrations via API:**
\`\`\`
.ocmt/mcp-client.sh ocmt_integrations
\`\`\`

## Capabilities
- Access to user's connected integrations via OAuth tokens
- Memory across conversations (workspace/memory/)
- File operations in the workspace
- Group shared resources and skills (.ocmt/skills/)

## Guidelines
- Always check .ocmt/integrations.json before claiming you can't access a service
- Verify vault is unlocked before accessing credentials
- Read .ocmt/context.md for full tool documentation
- If a service is listed in integrations.json, you CAN access it — fetch the credentials and use them
`,
    },
    {
      path: path.join(workspaceDir, ".ocmt", "USER.md"),
      content: `# User Profile

## Preferences

## Notes
`,
    },
  ];

  for (const template of templates) {
    if (!fs.existsSync(template.path)) {
      fs.writeFileSync(template.path, template.content);
      fs.chownSync(template.path, 1000, 1000);
    }
  }
}

/**
 * Write gateway config to openclaw.json
 * Includes MCP server config for OCMT tools (vault, integrations, org resources)
 */
export function writeGatewayConfig(userId, gatewayToken) {
  const userDataDir = path.join(DATA_DIR, userId);
  const configPath = path.join(userDataDir, "openclaw.json");

  let config = {};
  try {
    if (fs.existsSync(configPath)) {
      config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
    }
  } catch (e) {
    // Will create new config
  }

  // Gateway configuration
  config.gateway = config.gateway || {};
  config.gateway.mode = "local";
  config.gateway.port = 18789;
  config.gateway.bind = "lan";
  config.gateway.auth = { mode: "token", token: gatewayToken };
  // Allow WebSocket connections from any origin since the management server
  // proxies browser connections (ws-proxy authenticates via session cookie)
  config.gateway.controlUi = { allowInsecureAuth: true, allowedOrigins: ["*"] };
  // Trust proxy IPs and Docker networks to forward X-Forwarded-* headers
  // TRUSTED_PROXY_IPS: comma-separated list of IPs (e.g., nginx, management server, load balancers)
  const trustedProxyIps =
    process.env.TRUSTED_PROXY_IPS?.split(",")
      .map((s) => s.trim())
      .filter(Boolean) || [];
  config.gateway.trustedProxies = [...trustedProxyIps, "172.16.0.0/12", "10.0.0.0/8"];

  // Agent defaults
  config.agents = config.agents || {};
  config.agents.defaults = config.agents.defaults || {};
  config.agents.defaults.workspace = "/home/node/.openclaw/workspace";
  config.agents.defaults.sandbox = { mode: "off" };

  // NOTE: MCP server configuration is NOT supported in openclaw.json
  // The agent uses .ocmt/mcp-client.sh script instead (written by context.js)
  // Remove any stale mcpServers config that might have been added
  delete config.mcpServers;

  // Skills configuration for OCMT security skill
  // Skills are in the workspace/skills directory inside the container
  config.skills = config.skills || {};
  config.skills.load = config.skills.load || {};
  config.skills.load.extraDirs = ["/home/node/.openclaw/workspace/skills"];

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
  fs.chownSync(configPath, 1000, 1000);
  fs.chmodSync(configPath, 0o644);

  return config;
}

/**
 * Read gateway token from openclaw.json
 */
export function readGatewayToken(userId) {
  const configPath = path.join(DATA_DIR, userId, "openclaw.json");
  try {
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      return config.gateway?.auth?.token || null;
    }
  } catch (e) {
    // Config doesn't exist or is invalid
  }
  return null;
}

/**
 * Write auth-profiles.json for Google/OAuth credentials
 * This allows the agent to access credentials without MCP calls
 */
export function writeAuthProfiles(userId, profiles) {
  const userDataDir = path.join(DATA_DIR, userId);
  const agentDir = path.join(userDataDir, "agents", "main", "agent");

  // Ensure directory exists
  if (!fs.existsSync(agentDir)) {
    fs.mkdirSync(agentDir, { recursive: true });
    fs.chownSync(agentDir, 1000, 1000);
  }

  const authProfilesPath = path.join(agentDir, "auth-profiles.json");

  // Build auth-profiles.json in the expected format
  const authStore = {
    version: 2,
    profiles: profiles,
  };

  fs.writeFileSync(authProfilesPath, JSON.stringify(authStore, null, 2));
  fs.chownSync(authProfilesPath, 1000, 1000);
  fs.chmodSync(authProfilesPath, 0o600); // Secure permissions for credentials

  console.log(`[setup] Wrote auth-profiles for user ${userId.slice(0, 8)}`);
  return authStore;
}

/**
 * Read existing auth-profiles.json
 */
export function readAuthProfiles(userId) {
  const authProfilesPath = path.join(
    DATA_DIR,
    userId,
    "agents",
    "main",
    "agent",
    "auth-profiles.json",
  );
  try {
    if (fs.existsSync(authProfilesPath)) {
      return JSON.parse(fs.readFileSync(authProfilesPath, "utf-8"));
    }
  } catch (e) {
    console.error(`[setup] Failed to read auth-profiles: ${e.message}`);
  }
  return null;
}

export { DATA_DIR };
