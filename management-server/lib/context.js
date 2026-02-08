// Agent context management - injects context files into user containers
import axios from "axios";
import { users, integrations, groupMemberships, shares } from "../db/index.js";
import { decryptGatewayToken, generateEphemeralToken } from "./gateway-tokens.js";
import { getVaultSession } from "./vault-sessions.js";
import { unlockVaultWithKey, updateVaultWithKey } from "./vault.js";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

const AGENT_SERVER_URL = process.env.AGENT_SERVER_URL || "http://localhost:4000";
const AGENT_SERVER_TOKEN = process.env.AGENT_SERVER_TOKEN;
// External URL for browser redirects, internal URL for container MCP calls (bypasses DNS)
const MANAGEMENT_SERVER_URL = process.env.MANAGEMENT_SERVER_URL || "https://api.openpaw.ai";
const MANAGEMENT_SERVER_INTERNAL_URL =
  process.env.MANAGEMENT_SERVER_INTERNAL_URL || MANAGEMENT_SERVER_URL;

if (!AGENT_SERVER_TOKEN) {
  throw new Error(
    "AGENT_SERVER_TOKEN environment variable is required. " +
      "Generate a secure token and set it in your environment.",
  );
}

/**
 * Update agent context files when integrations change
 */
export async function updateAgentContext(userId) {
  try {
    const user = await users.findById(userId);
    if (!user || !user.container_id) {
      console.log(`[context] No container for user ${userId.slice(0, 8)}`);
      return;
    }

    // Repair container first (ensures directories exist)
    try {
      await axios.post(
        `${AGENT_SERVER_URL}/api/containers/${userId}/repair`,
        {},
        { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 10000 },
      );
    } catch (repairErr) {
      console.warn(`[context] Repair failed: ${repairErr.message}`);
    }

    // Get user's integrations
    const userIntegrations = await integrations.listForUser(userId);
    const connected = userIntegrations.map((i) => i.provider);

    // Get user's group memberships
    const userGroups = await groupMemberships.listByUser(userId);

    const contextJson = {
      connected,
      emails: {},
      groups: userGroups.map((g) => ({
        id: g.group_id,
        name: g.group_name,
        slug: g.group_slug,
        role: g.role,
      })),
      vaultRequired: true,
      lastUpdated: new Date().toISOString(),
    };

    for (const integration of userIntegrations) {
      if (integration.provider_email) {
        contextJson.emails[integration.provider] = integration.provider_email;
      }
    }

    // Write integrations.json
    await writeWorkspaceFile(
      userId,
      ".ocmt/integrations.json",
      JSON.stringify(contextJson, null, 2),
    );

    // Write context.md
    const contextMd = generateContextMd(connected, contextJson.emails, userGroups);
    await writeWorkspaceFile(userId, ".ocmt/context.md", contextMd);

    // Write config with ephemeral token
    // Decrypt the stored gateway token to generate ephemeral token
    let ephemeralToken;
    try {
      const rawToken = decryptGatewayToken(user.gateway_token);
      // Generate ephemeral token valid for 1 hour (container will refresh as needed)
      ephemeralToken = generateEphemeralToken(userId, rawToken, 3600);
    } catch (err) {
      // Fallback for legacy unencrypted tokens during migration
      console.warn(`[context] Using legacy token format for user ${userId.slice(0, 8)}`);
      ephemeralToken = generateEphemeralToken(userId, user.gateway_token, 3600);
    }

    const configContent = `# OCMT MCP Configuration
OCMT_MCP_URL="${MANAGEMENT_SERVER_INTERNAL_URL}/api/mcp"
OCMT_USER_ID="${userId}"
OCMT_GATEWAY_TOKEN="${ephemeralToken}"
# Note: Token is ephemeral and time-limited. Valid for 1 hour.
# Container will auto-refresh via refresh-token endpoint.
`;
    await writeWorkspaceFile(userId, ".ocmt/config", configContent);

    // Write MCP client script
    await writeWorkspaceFile(userId, ".ocmt/mcp-client.sh", MCP_CLIENT_SCRIPT);

    // Sync group skill docs from connected resources
    await syncGroupSkillDocs(userId);

    console.log(`[context] Updated agent context for user ${userId.slice(0, 8)}`);
  } catch (error) {
    console.error(`[context] Failed to update: ${error.message}`);
  }
}

async function writeWorkspaceFile(userId, filePath, content) {
  await axios.post(
    `${AGENT_SERVER_URL}/api/containers/${userId}/workspace/write`,
    { filePath, content },
    { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
  );
}

/**
 * Sync group skill docs from connected resources to agent workspace
 * Skill docs are markdown files that teach the agent how to use group APIs
 */
async function syncGroupSkillDocs(userId) {
  try {
    // Get all resources the user has connected access to
    const connectedResources = await shares.listConnectedForUser(userId);

    let skillCount = 0;
    for (const resource of connectedResources) {
      const metadata = resource.resource_metadata;
      if (!metadata?.skillDoc) {
        continue;
      }

      // Generate a safe filename from group slug and resource name
      const groupSlug = resource.group_slug || "default";
      const resourceSlug = resource.resource_name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-|-$/g, "");
      const filename = `${groupSlug}-${resourceSlug}.md`;

      // Add header with resource context
      const skillDocWithContext = `<!--
  Group Skill: ${resource.resource_name}
  Group: ${resource.group_name}
  Resource ID: ${resource.resource_id}
  Resource Type: ${resource.resource_type}

  To call this API, use ocmt_call_resource with resourceId: "${resource.resource_id}"
-->

${metadata.skillDoc}`;

      await writeWorkspaceFile(userId, `.ocmt/skills/${filename}`, skillDocWithContext);
      skillCount++;
    }

    if (skillCount > 0) {
      console.log(
        `[context] Synced ${skillCount} group skill doc(s) for user ${userId.slice(0, 8)}`,
      );
    }
  } catch (error) {
    console.error(`[context] Failed to sync group skill docs: ${error.message}`);
  }
}

function generateContextMd(connected, emails, groups = []) {
  return `# OCMT Platform Context

## Groups
${groups.length === 0 ? "- Not a member of any groups" : groups.map((g) => `- **${g.name}** (${g.slug}) - role: ${g.role}`).join("\n")}

## Connected Integrations
${connected.length === 0 ? "- None connected yet" : connected.map((c) => `- ${c}${emails[c] ? ` (${emails[c]})` : ""} - requires vault unlock to access tokens`).join("\n")}

## How to Use Integrations

Run \`.ocmt/mcp-client.sh <tool> [args_json]\`

### Available Tools

**Vault & Credentials:**
- ocmt_vault_status — check if vault is unlocked
- ocmt_unlock_link — get magic link for user to unlock vault
- ocmt_integrations — list all connected services
- ocmt_get_credentials — get OAuth tokens (vault must be unlocked)
- ocmt_extend_session — extend vault session during active conversation

**Groups & Resources:**
- ocmt_list_my_groups — list groups the user is a member of
- ocmt_group_resources — list group shared resources (available + connected)
- ocmt_call_resource — call a group resource API endpoint (permission checked)

**Resource Admin (requires group admin role):**
- ocmt_create_resource — add a new API resource to a group
- ocmt_grant_resource_access — grant a user access with granular permissions
- ocmt_delete_resource — remove a resource from a group

### Granular Permissions

Resource access uses granular permissions:
- **read** — View resource data (GET requests)
- **list** — List items in resource
- **write** — Create/update data (POST, PUT, PATCH requests)
- **delete** — Delete data (DELETE requests)
- **admin** — Manage the resource itself
- **share** — Can share resource with others

When calling a resource, the required permission is checked based on HTTP method:
- GET → requires \`read\` permission
- POST/PUT/PATCH → requires \`write\` permission
- DELETE → requires \`delete\` permission

### Examples

**Check vault status:**
\`\`\`
.ocmt/mcp-client.sh ocmt_vault_status
\`\`\`

**List user's groups:**
\`\`\`
.ocmt/mcp-client.sh ocmt_list_my_groups
\`\`\`

**Get Google Calendar tokens:**
\`\`\`
.ocmt/mcp-client.sh ocmt_get_credentials '{"provider":"google_calendar"}'
\`\`\`

**Call an org resource API:**
\`\`\`
.ocmt/mcp-client.sh ocmt_call_resource '{"resourceId":"uuid","method":"GET","path":"/endpoint"}'
\`\`\`

**List available group resources:**
\`\`\`
.ocmt/mcp-client.sh ocmt_group_resources '{"status":"all"}'
\`\`\`

**Create a new API resource (admin only):**
\`\`\`
.ocmt/mcp-client.sh ocmt_create_resource '{"groupId":"uuid","name":"Weather API","endpoint":"https://api.weather.com","authConfig":{"type":"api_key","key":"xxx","header":"X-API-Key"}}'
\`\`\`

**Grant yourself access with full permissions:**
\`\`\`
.ocmt/mcp-client.sh ocmt_grant_resource_access '{"resourceId":"uuid","userId":"me","permissions":{"read":true,"write":true,"delete":true}}'
\`\`\`

**Grant read-only access to another user:**
\`\`\`
.ocmt/mcp-client.sh ocmt_grant_resource_access '{"resourceId":"uuid","userId":"user-uuid","permissions":{"read":true}}'
\`\`\`

If vault is locked, the response will tell you. Use ocmt_unlock_link to get a link to send the user.

## Group Skills

Group skill docs are automatically synced to \`.ocmt/skills/\`. These markdown files teach you how to use group-shared APIs.

Each skill doc includes:
- API documentation and examples
- The resource ID to use with \`ocmt_call_resource\`
- Available endpoints and parameters

To use a group API:
1. Read the skill doc in \`.ocmt/skills/<org>-<resource>.md\`
2. Call the API using \`ocmt_call_resource\` with the resource ID from the skill doc header
`;
}

const MCP_CLIENT_SCRIPT = `#!/bin/bash
# OCMT MCP Client - calls management server tools via JSON-RPC

# Load config
SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config"

TOOL="$1"
ARGS="\${2:-{}}"

# JSON-RPC format
# X-Forwarded-Proto header allows internal HTTP calls to bypass HTTPS redirect
curl -s -X POST "$OCMT_MCP_URL" \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer $OCMT_GATEWAY_TOKEN" \\
  -H "X-User-Id: $OCMT_USER_ID" \\
  -H "X-Forwarded-Proto: https" \\
  -d "{\\"method\\": \\"tools/call\\", \\"params\\": {\\"name\\": \\"$TOOL\\", \\"arguments\\": $ARGS}, \\"id\\": \\"1\\"}"
`;

/**
 * Sync OAuth credentials to container's auth-profiles.json
 * Called when vault is unlocked or after OAuth callback
 */
export async function syncCredentialsToContainer(userId, vaultSessionToken) {
  try {
    const user = await users.findById(userId);
    if (!user || !user.container_id) {
      console.log(
        `[context] No container for user ${userId.slice(0, 8)}, skipping credential sync`,
      );
      return { synced: false, reason: "no_container" };
    }

    // Get vault session to access encrypted credentials
    const vaultSession = vaultSessionToken ? await getVaultSession(vaultSessionToken) : null;
    if (!vaultSession || vaultSession.userId !== userId || vaultSession.expiresAt <= Date.now()) {
      console.log(`[context] Vault session expired for user ${userId.slice(0, 8)}`);
      return { synced: false, reason: "vault_locked" };
    }

    if (!user.vault) {
      return { synced: false, reason: "no_vault" };
    }

    // Unlock vault to get credentials
    const vaultData = unlockVaultWithKey(user.vault, vaultSession.vaultKey);
    if (!vaultData.integrations || Object.keys(vaultData.integrations).length === 0) {
      console.log(`[context] No integrations for user ${userId.slice(0, 8)}`);
      return { synced: false, reason: "no_integrations" };
    }

    // Convert vault integrations to auth-profiles format
    const profiles = {};
    for (const [provider, integration] of Object.entries(vaultData.integrations)) {
      if (!integration.accessToken) {
        continue;
      }

      // Convert to auth-profiles format
      const profileId = `${provider}:default`;

      if (integration.refreshToken) {
        // OAuth credential with refresh token
        profiles[profileId] = {
          type: "oauth",
          provider,
          access: integration.accessToken,
          refresh: integration.refreshToken,
          expires: integration.expiresAt ? new Date(integration.expiresAt).getTime() : undefined,
          email: integration.email,
        };
      } else {
        // Token-only credential (no refresh)
        profiles[profileId] = {
          type: "token",
          provider,
          token: integration.accessToken,
          expires: integration.expiresAt ? new Date(integration.expiresAt).getTime() : undefined,
          email: integration.email,
        };
      }
    }

    if (Object.keys(profiles).length === 0) {
      return { synced: false, reason: "no_valid_credentials" };
    }

    // Send to agent-server
    await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/auth-profiles`,
      { profiles },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );

    console.log(
      `[context] Synced ${Object.keys(profiles).length} credential(s) to container for user ${userId.slice(0, 8)}`,
    );
    return { synced: true, count: Object.keys(profiles).length };
  } catch (error) {
    console.error(`[context] Failed to sync credentials: ${error.message}`);
    return { synced: false, reason: "error", error: error.message };
  }
}

/**
 * Refresh a Google OAuth token if expired
 */
async function refreshGoogleToken(integration) {
  if (!integration.refreshToken) {
    return null;
  }

  // Check if token is expired or expires within 5 minutes
  const expiresAt = new Date(integration.expiresAt);
  const bufferMs = 5 * 60 * 1000; // 5 minute buffer
  if (expiresAt > new Date(Date.now() + bufferMs)) {
    return null; // Token still valid
  }

  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    console.warn("[context] Cannot refresh token: Google OAuth not configured");
    return null;
  }

  try {
    const response = await axios.post("https://oauth2.googleapis.com/token", {
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: integration.refreshToken,
      grant_type: "refresh_token",
    });

    const { access_token, expires_in } = response.data;
    return {
      ...integration,
      accessToken: access_token,
      expiresAt: new Date(Date.now() + expires_in * 1000).toISOString(),
    };
  } catch (err) {
    console.error(`[context] Token refresh failed: ${err.message}`);
    return null;
  }
}

/**
 * Sync credentials using vault data directly (for OAuth callback where we already have vault access)
 * Also refreshes expired tokens before syncing
 */
export async function syncCredentialsFromVaultData(userId, vaultData, options = {}) {
  const { vaultKey, updateVaultOnRefresh = false } = options;

  try {
    const user = await users.findById(userId);
    if (!user || !user.container_id) {
      console.log(
        `[context] No container for user ${userId.slice(0, 8)}, skipping credential sync`,
      );
      return { synced: false, reason: "no_container" };
    }

    if (!vaultData.integrations || Object.keys(vaultData.integrations).length === 0) {
      console.log(`[context] No integrations for user ${userId.slice(0, 8)}`);
      return { synced: false, reason: "no_integrations" };
    }

    // Refresh expired tokens before syncing
    let vaultUpdated = false;
    for (const [provider, integration] of Object.entries(vaultData.integrations)) {
      if (provider.startsWith("google")) {
        const refreshed = await refreshGoogleToken(integration);
        if (refreshed) {
          vaultData.integrations[provider] = refreshed;
          vaultUpdated = true;
          console.log(`[context] Refreshed expired token for ${provider}`);
        }
      }
    }

    // Update vault with refreshed tokens if we have the key
    if (vaultUpdated && updateVaultOnRefresh && vaultKey && user.vault) {
      try {
        const updatedVault = updateVaultWithKey(user.vault, vaultKey, vaultData);
        await users.updateVault(userId, updatedVault);
        console.log(`[context] Updated vault with refreshed tokens for user ${userId.slice(0, 8)}`);
      } catch (err) {
        console.error(`[context] Failed to update vault: ${err.message}`);
      }
    }

    // Convert vault integrations to auth-profiles format
    const profiles = {};
    for (const [provider, integration] of Object.entries(vaultData.integrations)) {
      if (!integration.accessToken) {
        continue;
      }

      const profileId = `${provider}:default`;

      if (integration.refreshToken) {
        profiles[profileId] = {
          type: "oauth",
          provider,
          access: integration.accessToken,
          refresh: integration.refreshToken,
          expires: integration.expiresAt ? new Date(integration.expiresAt).getTime() : undefined,
          email: integration.email,
        };
      } else {
        profiles[profileId] = {
          type: "token",
          provider,
          token: integration.accessToken,
          expires: integration.expiresAt ? new Date(integration.expiresAt).getTime() : undefined,
          email: integration.email,
        };
      }
    }

    if (Object.keys(profiles).length === 0) {
      return { synced: false, reason: "no_valid_credentials" };
    }

    await axios.post(
      `${AGENT_SERVER_URL}/api/containers/${userId}/auth-profiles`,
      { profiles },
      { headers: { "x-auth-token": AGENT_SERVER_TOKEN }, timeout: 15000 },
    );

    console.log(
      `[context] Synced ${Object.keys(profiles).length} credential(s) to container for user ${userId.slice(0, 8)}`,
    );
    return { synced: true, count: Object.keys(profiles).length, refreshed: vaultUpdated };
  } catch (error) {
    console.error(`[context] Failed to sync credentials: ${error.message}`);
    return { synced: false, reason: "error", error: error.message };
  }
}

export { AGENT_SERVER_URL, AGENT_SERVER_TOKEN };
