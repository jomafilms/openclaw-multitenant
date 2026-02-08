> **PARTIALLY OUTDATED**: The security model described here (credentials on management server) has been superseded.
> The current system uses container-side secret store where credentials never leave the container.
> See [architecture/container-secret-store.md](./architecture/container-secret-store.md) for current security model.
> Integration types and concepts below remain valid for reference.

---

# OCMT Integrations Specification

> Complete specification for the integrations system in OCMT

---

## Overview

The integrations system allows users to connect external services to their OpenClaw agent. There are two distinct integration types:

1. **Custom API Integrations** - User provides any API key for any service
2. **Guided Integrations** - Pre-built OAuth flows and setup wizards for common services

**Current security model**: Credentials are stored in the container-side secret store and never leave the container in plaintext. See [architecture/container-secret-store.md](./architecture/container-secret-store.md).

---

## 1. Integration Types

### 1.1 Custom API Integrations

Custom API integrations allow users to add credentials for ANY API they want to use. This is the most flexible option and works with any REST API.

**Use Cases:**

- Workflowy API
- Notion API
- Airtable API
- Linear API
- Any internal/private API
- Any service with API key authentication

**Form Fields:**

| Field       | Type      | Required | Description                                                    |
| ----------- | --------- | -------- | -------------------------------------------------------------- |
| Name        | text      | Yes      | User-friendly name (e.g., "My Notion Workspace")               |
| API Key     | password  | Yes      | The API key or token                                           |
| Base URL    | url       | No       | API endpoint (e.g., `https://api.notion.com/v1`)               |
| Permissions | select    | Yes      | `read` or `read-write`                                         |
| Headers     | key-value | No       | Custom headers to include (e.g., `Notion-Version: 2022-06-28`) |

**How It Works:**

1. User fills out the custom API form
2. Management server encrypts and stores credentials
3. On container start, credentials are injected as environment variables
4. OpenClaw reads env vars and can make API calls directly or via MCP

### 1.2 Guided Integrations

Guided integrations provide pre-built flows for common services. These handle OAuth, token refresh, and service-specific configuration automatically.

**MVP Guided Integrations:**

| Service  | Auth Type | Capabilities                     |
| -------- | --------- | -------------------------------- |
| Google   | OAuth 2.0 | Gmail, Calendar, Drive, Contacts |
| Telegram | Bot Token | Send/receive messages            |

**Future Guided Integrations:**

| Service           | Auth Type         | Capabilities          |
| ----------------- | ----------------- | --------------------- |
| Signal            | Registration      | Send/receive messages |
| Discord           | Bot Token + OAuth | Channels, DMs, roles  |
| Slack             | OAuth 2.0         | Channels, DMs, apps   |
| Email (SMTP/IMAP) | Credentials       | Send/receive email    |
| Calendar (CalDAV) | Credentials       | Event management      |
| GitHub            | OAuth 2.0         | Repos, issues, PRs    |
| Linear            | OAuth 2.0         | Issues, projects      |
| Notion            | OAuth 2.0         | Pages, databases      |

Each guided integration is essentially a "skill" - a pre-built workflow that we develop and maintain over time.

---

## 2. Database Schema

```sql
-- User integrations (both custom and guided)
CREATE TABLE user_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Integration type: 'custom' or specific provider name
    -- Examples: 'custom', 'google', 'telegram', 'discord', 'slack'
    integration_type TEXT NOT NULL,

    -- User-friendly display name
    name TEXT NOT NULL,

    -- Encrypted credentials (API keys, OAuth tokens, etc.)
    -- Encryption key stored separately in secrets vault
    credentials_encrypted BYTEA NOT NULL,

    -- Provider-specific configuration (JSON)
    -- For custom: { "base_url": "...", "headers": {...} }
    -- For Google: { "scopes": [...], "project_id": "..." }
    -- For Telegram: { "bot_username": "...", "webhook_url": "..." }
    config JSONB DEFAULT '{}',

    -- Permissions granted by user
    -- ['read'] or ['read', 'write']
    permissions TEXT[] NOT NULL DEFAULT ARRAY['read'],

    -- OAuth-specific fields
    oauth_refresh_token_encrypted BYTEA,
    oauth_token_expires_at TIMESTAMP,

    -- Status tracking
    status TEXT NOT NULL DEFAULT 'active',  -- 'active', 'expired', 'revoked', 'error'
    last_used_at TIMESTAMP,
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for quick lookup by user
CREATE INDEX idx_user_integrations_user_id ON user_integrations(user_id);
CREATE INDEX idx_user_integrations_type ON user_integrations(integration_type);

-- Ensure unique integration names per user
CREATE UNIQUE INDEX idx_user_integrations_unique_name
    ON user_integrations(user_id, name);

-- Audit log for integration access
CREATE TABLE integration_audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMP NOT NULL DEFAULT NOW(),
    user_id UUID NOT NULL,
    integration_id UUID REFERENCES user_integrations(id),
    action TEXT NOT NULL,  -- 'created', 'updated', 'deleted', 'used', 'refreshed', 'error'
    details JSONB,
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX idx_integration_audit_user ON integration_audit_log(user_id);
CREATE INDEX idx_integration_audit_ts ON integration_audit_log(ts);
```

---

## 3. API Endpoints

### 3.1 List Integrations

```
GET /api/integrations
```

**Response:**

```json
{
  "integrations": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "integration_type": "google",
      "name": "Personal Google",
      "permissions": ["read", "write"],
      "status": "active",
      "config": {
        "scopes": ["gmail.readonly", "calendar.events"],
        "email": "user@gmail.com"
      },
      "created_at": "2024-02-01T10:00:00Z",
      "last_used_at": "2024-02-03T14:30:00Z"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "integration_type": "custom",
      "name": "Notion API",
      "permissions": ["read", "write"],
      "status": "active",
      "config": {
        "base_url": "https://api.notion.com/v1"
      },
      "created_at": "2024-02-02T15:00:00Z",
      "last_used_at": null
    }
  ]
}
```

### 3.2 Add Custom API Integration

```
POST /api/integrations/custom
```

**Request:**

```json
{
  "name": "My Notion Workspace",
  "api_key": "secret_abc123...",
  "base_url": "https://api.notion.com/v1",
  "permissions": ["read", "write"],
  "headers": {
    "Notion-Version": "2022-06-28"
  }
}
```

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440001",
  "integration_type": "custom",
  "name": "My Notion Workspace",
  "permissions": ["read", "write"],
  "status": "active",
  "created_at": "2024-02-03T10:00:00Z"
}
```

### 3.3 Google OAuth Flow

**Start OAuth:**

```
POST /api/integrations/google
```

**Request:**

```json
{
  "name": "Personal Google",
  "scopes": ["gmail.readonly", "calendar.events"],
  "permissions": ["read", "write"]
}
```

**Response:**

```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=...&scope=...&state=...",
  "state": "random-state-token"
}
```

**OAuth Callback:**

```
GET /api/integrations/google/callback?code=...&state=...
```

**Response:** Redirects to `/settings/integrations?success=google`

### 3.4 Telegram Bot Setup

```
POST /api/integrations/telegram
```

**Request:**

```json
{
  "name": "My Telegram Bot",
  "bot_token": "123456:ABC-DEF...",
  "permissions": ["read", "write"]
}
```

**Response:**

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440002",
  "integration_type": "telegram",
  "name": "My Telegram Bot",
  "status": "active",
  "config": {
    "bot_username": "@MyOpenClawBot",
    "webhook_configured": true
  }
}
```

### 3.5 Delete Integration

```
DELETE /api/integrations/:id
```

**Response:**

```json
{
  "success": true,
  "message": "Integration removed"
}
```

### 3.6 Test Integration

```
POST /api/integrations/:id/test
```

**Response:**

```json
{
  "success": true,
  "message": "Connection successful",
  "details": {
    "latency_ms": 142,
    "api_version": "2022-06-28"
  }
}
```

---

## 4. Container Injection Flow

This section describes how credentials flow from the management server into the user's container.

### 4.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CREDENTIAL INJECTION FLOW                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. USER ADDS INTEGRATION                                                │
│     ┌──────────┐         ┌─────────────────┐                            │
│     │  Web UI  │ ──POST──│ Management      │                            │
│     │          │         │ Server          │                            │
│     └──────────┘         └────────┬────────┘                            │
│                                   │                                      │
│  2. ENCRYPT & STORE               │                                      │
│                                   ▼                                      │
│                          ┌─────────────────┐                            │
│                          │ PostgreSQL      │                            │
│                          │ (encrypted at   │                            │
│                          │  rest)          │                            │
│                          └─────────────────┘                            │
│                                                                          │
│  3. CONTAINER START (or integration added to running container)         │
│                                                                          │
│     ┌─────────────────┐         ┌─────────────────┐                     │
│     │ Management      │ ──API───│ Agent Server    │                     │
│     │ Server          │         │                 │                     │
│     │                 │         │ "Inject creds   │                     │
│     │ "Here are the   │         │  for user X"    │                     │
│     │  decrypted      │         │                 │                     │
│     │  credentials"   │         └────────┬────────┘                     │
│     └─────────────────┘                  │                              │
│                                          │                              │
│  4. INJECT INTO CONTAINER                │                              │
│                                          ▼                              │
│                          ┌─────────────────────────────┐                │
│                          │ User's Container             │                │
│                          │                              │                │
│                          │ ENV VARS:                    │                │
│                          │ OCMT_INTEGRATION_GOOGLE_ACCESS_TOKEN=...  │
│                          │ OCMT_INTEGRATION_NOTION_API_KEY=...       │
│                          │ OCMT_INTEGRATION_TELEGRAM_BOT_TOKEN=...   │
│                          │                              │                │
│                          │ CONFIG FILE:                 │                │
│                          │ /tmp/ocmt/integrations.json               │
│                          │                              │                │
│                          └──────────────┬───────────────┘               │
│                                         │                               │
│  5. OPENCLAW USES CREDENTIALS           │                               │
│                                         ▼                               │
│                          ┌─────────────────────────────┐                │
│                          │ OpenClaw reads env vars     │                │
│                          │ and config file             │                │
│                          │                              │                │
│                          │ • Direct API calls          │                │
│                          │ • MCP server connections    │                │
│                          │ • Tool integrations         │                │
│                          └─────────────────────────────┘                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Environment Variable Naming Convention

All integration credentials are injected as environment variables with a consistent naming scheme:

```
OCMT_INTEGRATION_{TYPE}_{KEY}
```

**Examples:**

```bash
# Google OAuth
OCMT_INTEGRATION_GOOGLE_ACCESS_TOKEN="ya29.a0..."
OCMT_INTEGRATION_GOOGLE_REFRESH_TOKEN="1//0..."
OCMT_INTEGRATION_GOOGLE_EMAIL="user@gmail.com"

# Telegram
OCMT_INTEGRATION_TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."

# Custom API (with sanitized name)
OCMT_INTEGRATION_CUSTOM_NOTION_API_KEY="secret_abc..."
OCMT_INTEGRATION_CUSTOM_NOTION_BASE_URL="https://api.notion.com/v1"

# Multiple custom integrations distinguished by ID
OCMT_INTEGRATION_CUSTOM_550e8400_API_KEY="secret_abc..."
OCMT_INTEGRATION_CUSTOM_550e8400_BASE_URL="https://api.notion.com/v1"
```

### 4.3 Integration Config File

In addition to environment variables, a JSON config file is written to the container:

```json
// /tmp/ocmt/integrations.json
{
  "integrations": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "type": "google",
      "name": "Personal Google",
      "permissions": ["read", "write"],
      "config": {
        "email": "user@gmail.com",
        "scopes": ["gmail.readonly", "calendar.events"]
      },
      "env_prefix": "OCMT_INTEGRATION_GOOGLE"
    },
    {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "type": "custom",
      "name": "Notion API",
      "permissions": ["read", "write"],
      "config": {
        "base_url": "https://api.notion.com/v1",
        "headers": {
          "Notion-Version": "2022-06-28"
        }
      },
      "env_prefix": "OCMT_INTEGRATION_CUSTOM_550E8400"
    }
  ]
}
```

### 4.4 Agent Server API for Injection

The management server calls the agent server to inject credentials:

```
POST /internal/containers/{container_id}/integrations
Authorization: Bearer {internal-api-key}
```

**Request:**

```json
{
  "integrations": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "type": "google",
      "name": "Personal Google",
      "credentials": {
        "access_token": "ya29.a0...",
        "refresh_token": "1//0...",
        "email": "user@gmail.com"
      },
      "config": {
        "scopes": ["gmail.readonly", "calendar.events"]
      },
      "permissions": ["read", "write"]
    }
  ]
}
```

**Response:**

```json
{
  "success": true,
  "injected_count": 1
}
```

### 4.5 Hot Reload Support

When a user adds or removes an integration while their container is running:

1. Management server calls agent server inject endpoint
2. Agent server writes new env vars and config file
3. Agent server sends SIGUSR1 to OpenClaw process
4. OpenClaw reloads integration config without restart

---

## 5. Security Model

### 5.1 Encryption at Rest

All credentials are encrypted before storage using AES-256-GCM:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ENCRYPTION MODEL                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ENCRYPTION KEY HIERARCHY                                                │
│                                                                          │
│  ┌─────────────────┐                                                    │
│  │ Master Key      │ ← Stored in HSM or secrets manager (not in DB)    │
│  │ (KEK)           │                                                    │
│  └────────┬────────┘                                                    │
│           │                                                              │
│           │ Encrypts                                                     │
│           ▼                                                              │
│  ┌─────────────────┐                                                    │
│  │ Per-User Key    │ ← Generated when user signs up                     │
│  │ (DEK)           │ ← Stored encrypted in users table                  │
│  └────────┬────────┘                                                    │
│           │                                                              │
│           │ Encrypts                                                     │
│           ▼                                                              │
│  ┌─────────────────┐                                                    │
│  │ User's          │ ← Stored in user_integrations table               │
│  │ Credentials     │                                                    │
│  └─────────────────┘                                                    │
│                                                                          │
│  ENCRYPTION FORMAT                                                       │
│                                                                          │
│  credentials_encrypted = nonce (12 bytes) || ciphertext || tag (16 bytes)│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Decryption Rules

Credentials are ONLY decrypted in these scenarios:

1. **Container Start** - Management server decrypts and sends to agent server
2. **Integration Hot Reload** - Same as above
3. **OAuth Token Refresh** - Management server decrypts refresh token, gets new access token, re-encrypts

Credentials are NEVER:

- Logged
- Sent to frontend
- Stored on agent server disk
- Accessible from other users' containers

### 5.3 Container Isolation

Each user's credentials are isolated to their container:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CONTAINER ISOLATION                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Host Machine (Agent Server)                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                                                                      ││
│  │  Container Network: user-alice-net (isolated)                       ││
│  │  ┌─────────────────────────────────────────────────────┐            ││
│  │  │ Alice's Container                                    │            ││
│  │  │                                                      │            ││
│  │  │ ENV: OCMT_INTEGRATION_GOOGLE_ACCESS_TOKEN=...    │            ││
│  │  │ ENV: OCMT_INTEGRATION_NOTION_API_KEY=...         │            ││
│  │  │                                                      │            ││
│  │  │ • Cannot see other containers                       │            ││
│  │  │ • Cannot access host filesystem                     │            ││
│  │  │ • Cannot access Docker socket                       │            ││
│  │  │ • Resource limits enforced                          │            ││
│  │  └─────────────────────────────────────────────────────┘            ││
│  │                                                                      ││
│  │  Container Network: user-bob-net (isolated)                         ││
│  │  ┌─────────────────────────────────────────────────────┐            ││
│  │  │ Bob's Container                                      │            ││
│  │  │                                                      │            ││
│  │  │ ENV: OCMT_INTEGRATION_SLACK_BOT_TOKEN=...        │            ││
│  │  │                                                      │            ││
│  │  │ • Has DIFFERENT credentials                         │            ││
│  │  │ • Cannot see Alice's credentials                    │            ││
│  │  └─────────────────────────────────────────────────────┘            ││
│  │                                                                      ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.4 User Revocation

When a user revokes an integration:

1. **Immediate**: Delete from database, remove from container
2. **OAuth**: Call provider's token revocation endpoint
3. **Audit**: Log the revocation event
4. **Clean**: Remove all env vars and config entries

```
DELETE /api/integrations/:id
        │
        ▼
┌─────────────────┐
│ 1. Mark revoked │
│    in database  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ 2. Call OAuth   │────▶│ Google/etc      │
│    revocation   │     │ revoke endpoint │
└────────┬────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│ 3. Remove from  │────▶│ Agent Server    │
│    container    │     │ hot unload      │
└────────┬────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│ 4. Audit log    │
└─────────────────┘
```

---

## 6. UI Mockups

### 6.1 Integration List View

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Settings                                                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Integrations                                            [+ Add New]     │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  CONNECTED                                                               │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ [G]  Google - Personal                                    [Active]  ││
│  │      Gmail, Calendar, Drive                                         ││
│  │      Connected Feb 1, 2024 • Last used 2 hours ago                  ││
│  │                                                                     ││
│  │      [Test Connection]  [Manage Scopes]  [Disconnect]               ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ [T]  Telegram - My Bot                                    [Active]  ││
│  │      @MyOpenClawBot                                                 ││
│  │      Connected Feb 2, 2024 • Last used 5 minutes ago                ││
│  │                                                                     ││
│  │      [Test Connection]  [Disconnect]                                ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ [*]  Notion API                                           [Active]  ││
│  │      Custom API • Read & Write                                      ││
│  │      Connected Feb 3, 2024 • Never used                             ││
│  │                                                                     ││
│  │      [Test Connection]  [Edit]  [Disconnect]                        ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  AVAILABLE                                                               │
│                                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ [G] Google   │  │ [T] Telegram │  │ [D] Discord  │  │ [S] Slack    │ │
│  │              │  │              │  │              │  │              │ │
│  │ [Connect]    │  │ [Connect]    │  │ Coming Soon  │  │ Coming Soon  │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │ [*] Custom API                                                       ││
│  │     Connect any service with an API key                              ││
│  │                                                                      ││
│  │     [Add Custom API]                                                 ││
│  └──────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.2 Add Custom API Form

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Integrations                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Add Custom API Integration                                              │
│                                                                          │
│  Connect any service that uses API key authentication.                   │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  Name *                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ My Notion Workspace                                                 ││
│  └─────────────────────────────────────────────────────────────────────┘│
│  A friendly name to identify this integration                            │
│                                                                          │
│  API Key *                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ ••••••••••••••••••••••••                                    [Show] ││
│  └─────────────────────────────────────────────────────────────────────┘│
│  Your API key or token. This will be encrypted.                          │
│                                                                          │
│  Base URL                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ https://api.notion.com/v1                                           ││
│  └─────────────────────────────────────────────────────────────────────┘│
│  The base URL for API requests (optional)                                │
│                                                                          │
│  Permissions *                                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ (o) Read only - Agent can read data but not modify                  ││
│  │ ( ) Read & Write - Agent can read and modify data                   ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  Custom Headers (optional)                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ Header Name              │ Value                                    ││
│  │ ────────────────────────────────────────────────────────────────── ││
│  │ Notion-Version           │ 2022-06-28                               ││
│  │ [+ Add Header]                                                      ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│                                              [Cancel]  [Test & Save]    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Google OAuth Flow

**Step 1: Select Scopes**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Integrations                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [G] Connect Google Account                                              │
│                                                                          │
│  Select what your agent can access:                                      │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  [ ] Gmail                                                               │
│      ├─ [x] Read emails                                                 │
│      └─ [ ] Send emails                                                 │
│                                                                          │
│  [ ] Calendar                                                            │
│      ├─ [x] View events                                                 │
│      └─ [x] Create and modify events                                    │
│                                                                          │
│  [ ] Drive                                                               │
│      ├─ [ ] View files                                                  │
│      └─ [ ] Edit files                                                  │
│                                                                          │
│  [ ] Contacts                                                            │
│      └─ [ ] View contacts                                               │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  Name this connection:                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ Personal Google                                                     ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│                                   [Cancel]  [Continue to Google ->]     │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Step 2: Google Consent Screen (external)**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│                         [Google Logo]                                    │
│                                                                          │
│  Sign in with Google                                                     │
│                                                                          │
│  Choose an account to continue to OCMT                                │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ [Avatar]  user@gmail.com                                            ││
│  │           John Doe                                                  ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ [Avatar]  Use another account                                       ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Step 3: Success**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Integrations                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                                                                          │
│                            ┌───────────┐                                │
│                            │     ✓     │                                │
│                            └───────────┘                                │
│                                                                          │
│                     Google Connected Successfully!                       │
│                                                                          │
│                     Your agent can now access:                           │
│                     • Gmail (read)                                       │
│                     • Calendar (read & write)                            │
│                                                                          │
│                     Account: user@gmail.com                              │
│                                                                          │
│                                                                          │
│                              [Done]                                      │
│                                                                          │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.4 Telegram Bot Setup Wizard

**Step 1: Create Bot**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Integrations                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [T] Connect Telegram Bot                                                │
│                                                                          │
│  Step 1 of 3: Create Your Bot                                            │
│  ══════════════════════════════════════════════════════════════════════ │
│                                                                          │
│  1. Open Telegram and search for @BotFather                              │
│                                                                          │
│  2. Send the command: /newbot                                            │
│                                                                          │
│  3. Follow the prompts to:                                               │
│     • Choose a display name (e.g., "My OpenClaw Bot")                   │
│     • Choose a username ending in "bot" (e.g., "my_openclaw_bot")       │
│                                                                          │
│  4. BotFather will give you an API token that looks like:                │
│     123456789:ABCdefGHIjklMNOpqrSTUvwxYZ                                 │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                                                                     ││
│  │  [Open Telegram BotFather]                                          ││
│  │                                                                     ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│                                              [Cancel]  [I have my token]│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Step 2: Enter Token**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Integrations                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [T] Connect Telegram Bot                                                │
│                                                                          │
│  Step 2 of 3: Enter Your Bot Token                                       │
│  ══════════════════════════════════════════════════════════════════════ │
│                                                                          │
│  Paste the token you received from @BotFather:                           │
│                                                                          │
│  Bot Token *                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ                                ││
│  └─────────────────────────────────────────────────────────────────────┘│
│  This will be encrypted and stored securely.                             │
│                                                                          │
│  Name this connection:                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ My Telegram Bot                                                     ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│                                                                          │
│                                                                          │
│                                                 [Back]  [Verify & Connect]│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Step 3: Success**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  ← Integrations                                                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [T] Connect Telegram Bot                                                │
│                                                                          │
│  Step 3 of 3: Connected!                                                 │
│  ══════════════════════════════════════════════════════════════════════ │
│                                                                          │
│                            ┌───────────┐                                │
│                            │     ✓     │                                │
│                            └───────────┘                                │
│                                                                          │
│                    Telegram Bot Connected!                               │
│                                                                          │
│                    Bot: @my_openclaw_bot                                 │
│                    Status: Active                                        │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  Next Steps:                                                             │
│                                                                          │
│  1. Open Telegram and start a chat with @my_openclaw_bot                │
│  2. Send /start to begin                                                 │
│  3. Your messages will be handled by your OpenClaw agent                 │
│                                                                          │
│                                                                          │
│                              [Done]                                      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.5 Edit Integration Modal

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Edit Integration                                                   [X] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [*] Notion API                                                          │
│                                                                          │
│  Name                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ My Notion Workspace                                                 ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  API Key                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ ••••••••••••••••••••••                       [Change]               ││
│  └─────────────────────────────────────────────────────────────────────┘│
│  Current key ends in: ...xyz789                                          │
│                                                                          │
│  Base URL                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ https://api.notion.com/v1                                           ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  Permissions                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │ ( ) Read only                                                       ││
│  │ (o) Read & Write                                                    ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  Last used: Feb 3, 2024 at 2:30 PM                                       │
│  Created: Feb 1, 2024                                                    │
│                                                                          │
│                    [Delete Integration]        [Cancel]  [Save Changes] │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 6.6 Test Connection Result

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Connection Test                                                    [X] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [*] Notion API                                                          │
│                                                                          │
│                            ┌───────────┐                                │
│                            │     ✓     │                                │
│                            └───────────┘                                │
│                                                                          │
│                      Connection Successful!                              │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  Details:                                                                │
│  • Response time: 142ms                                                  │
│  • API version: 2022-06-28                                               │
│  • Workspace: "John's Workspace"                                        │
│  • Permissions verified: Read, Write                                     │
│                                                                          │
│                                                                          │
│                                                            [Close]      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Error State:**

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Connection Test                                                    [X] │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [*] Notion API                                                          │
│                                                                          │
│                            ┌───────────┐                                │
│                            │     ✗     │                                │
│                            └───────────┘                                │
│                                                                          │
│                       Connection Failed                                  │
│                                                                          │
│  ─────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  Error: 401 Unauthorized                                                 │
│                                                                          │
│  The API key appears to be invalid or expired.                           │
│                                                                          │
│  Suggestions:                                                            │
│  • Verify your API key is correct                                        │
│  • Check if the key has been revoked                                     │
│  • Generate a new API key from Notion settings                           │
│                                                                          │
│                                              [Edit Integration]  [Close]│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. OpenClaw Integration

### 7.1 How OpenClaw Uses Integrations

OpenClaw reads integration credentials from environment variables and the config file:

```typescript
// Example: Reading integrations in OpenClaw
import { readFileSync } from "fs";

interface Integration {
  id: string;
  type: string;
  name: string;
  permissions: string[];
  config: Record<string, unknown>;
  env_prefix: string;
}

function loadIntegrations(): Integration[] {
  const configPath = "/tmp/ocmt/integrations.json";
  const config = JSON.parse(readFileSync(configPath, "utf-8"));
  return config.integrations;
}

function getCredential(integration: Integration, key: string): string | undefined {
  const envKey = `${integration.env_prefix}_${key.toUpperCase()}`;
  return process.env[envKey];
}

// Usage
const integrations = loadIntegrations();
const notion = integrations.find((i) => i.name === "Notion API");
if (notion) {
  const apiKey = getCredential(notion, "api_key");
  const baseUrl = notion.config.base_url;
  // Make API calls...
}
```

### 7.2 MCP Server Integration

For guided integrations, OpenClaw can automatically configure MCP servers:

```json
// Auto-generated MCP config for Google integration
{
  "mcpServers": {
    "google-gmail": {
      "command": "npx",
      "args": ["@anthropic/mcp-google-gmail"],
      "env": {
        "GOOGLE_ACCESS_TOKEN": "${OCMT_INTEGRATION_GOOGLE_ACCESS_TOKEN}",
        "GOOGLE_REFRESH_TOKEN": "${OCMT_INTEGRATION_GOOGLE_REFRESH_TOKEN}"
      }
    },
    "google-calendar": {
      "command": "npx",
      "args": ["@anthropic/mcp-google-calendar"],
      "env": {
        "GOOGLE_ACCESS_TOKEN": "${OCMT_INTEGRATION_GOOGLE_ACCESS_TOKEN}",
        "GOOGLE_REFRESH_TOKEN": "${OCMT_INTEGRATION_GOOGLE_REFRESH_TOKEN}"
      }
    }
  }
}
```

### 7.3 Direct API Access

For custom integrations, OpenClaw can make direct HTTP calls:

```typescript
// OpenClaw tool for custom API calls
async function callCustomApi(
  integrationName: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  const integration = findIntegration(integrationName);
  if (!integration) {
    throw new Error(`Integration "${integrationName}" not found`);
  }

  // Check permissions
  if (method !== "GET" && !integration.permissions.includes("write")) {
    throw new Error(`Integration "${integrationName}" does not have write permission`);
  }

  const apiKey = getCredential(integration, "api_key");
  const baseUrl = integration.config.base_url || "";
  const headers = integration.config.headers || {};

  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  return response.json();
}
```

---

## 8. Implementation Checklist

### Phase 1: Core Infrastructure

- [ ] Database migrations for `user_integrations` and `integration_audit_log`
- [ ] Encryption service for credential storage
- [ ] Integration CRUD API endpoints
- [ ] Agent server injection API

### Phase 2: Custom API Integration

- [ ] Add custom API form component
- [ ] Custom API validation and testing
- [ ] Environment variable injection
- [ ] Integration list UI

### Phase 3: Google OAuth

- [ ] Google OAuth configuration
- [ ] Scope selection UI
- [ ] OAuth callback handling
- [ ] Token refresh mechanism
- [ ] MCP server auto-configuration

### Phase 4: Telegram Integration

- [ ] Telegram bot setup wizard
- [ ] Token validation
- [ ] Webhook configuration
- [ ] Bot info retrieval

### Phase 5: Polish

- [ ] Connection testing for all integration types
- [ ] Edit integration modal
- [ ] Audit logging
- [ ] Hot reload support
- [ ] Error handling and user feedback

---

## 9. Future Considerations

### 9.1 Guided Integration Template

When adding new guided integrations, follow this pattern:

```typescript
interface GuidedIntegration {
  // Unique identifier
  type: string;

  // Display information
  name: string;
  icon: string;
  description: string;

  // Authentication configuration
  auth: {
    type: "oauth2" | "api_key" | "credentials" | "custom";
    // OAuth-specific
    authUrl?: string;
    tokenUrl?: string;
    scopes?: string[];
    // API key specific
    keyLocation?: "header" | "query" | "body";
    keyName?: string;
  };

  // Validation
  validateCredentials: (creds: unknown) => Promise<boolean>;

  // MCP server configuration (optional)
  mcpConfig?: {
    command: string;
    args: string[];
    envMapping: Record<string, string>;
  };
}
```

### 9.2 Rate Limiting

Consider adding rate limiting for integration API calls to prevent abuse:

```sql
CREATE TABLE integration_rate_limits (
    integration_id UUID REFERENCES user_integrations(id),
    window_start TIMESTAMP NOT NULL,
    request_count INTEGER DEFAULT 0,
    PRIMARY KEY (integration_id, window_start)
);
```

### 9.3 Usage Analytics

Track integration usage for billing and analytics:

```sql
CREATE TABLE integration_usage (
    id BIGSERIAL PRIMARY KEY,
    integration_id UUID REFERENCES user_integrations(id),
    ts TIMESTAMP DEFAULT NOW(),
    operation TEXT,  -- 'read', 'write', 'oauth_refresh'
    tokens_used INTEGER,
    latency_ms INTEGER
);
```

---

## Related Documents

- [ARCHITECTURE.md](../ARCHITECTURE.md) - Overall system architecture
- [MVP_IMPLEMENTATION_PLAN.md](../MVP_IMPLEMENTATION_PLAN.md) - MVP implementation timeline
