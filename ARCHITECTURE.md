# OCMT Architecture

> Web UI + Multi-tenant Security for OpenClaw

---

## What OCMT Is (and Isn't)

**OpenClaw already does:**

- AI agent runtime
- MCP server connections
- Google/Gmail/Calendar integration
- Tool execution + sandboxing
- Memory + workspace management
- Telegram/Discord/Slack channels

**OCMT adds:**

- Web UI (no CLI needed)
- Multi-tenant infrastructure (isolated containers per user)
- Sharing layer (group resources, peer-to-peer access)
- User-friendly onboarding

```
┌─────────────────────────────────────────────────────────────────┐
│                           OCMT                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐                                               │
│   │   Web UI    │ ◄── Users chat here (no CLI needed)           │
│   └──────┬──────┘                                               │
│          │                                                       │
│          ▼                                                       │
│   ┌─────────────┐      ┌─────────────┐                          │
│   │ Management  │ ──── │   Agent     │                          │
│   │ Server      │      │   Server    │                          │
│   │             │      │             │                          │
│   │ • Users     │      │ • Containers│                          │
│   │ • Groups    │      │ • Isolation │                          │
│   │ • Secrets   │      │             │                          │
│   └─────────────┘      └──────┬──────┘                          │
│                               │                                  │
│                               ▼                                  │
│                    ┌──────────────────┐                         │
│                    │    OpenClaw      │ ◄── Does all the work   │
│                    │    (per user)    │                         │
│                    │                  │                         │
│                    │ • MCP servers    │                         │
│                    │ • Integrations   │                         │
│                    │ • Tools          │                         │
│                    │ • Memory         │                         │
│                    └──────────────────┘                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Rules

### Rule 1: No Secrets on Agent Server

```
Management Server (trusted)     Agent Server (untrusted)
├── API keys                    ├── NO keys on disk
├── User database               ├── Keys in container memory only
├── Secrets vault               ├── Per-user isolation
└── Billing                     └── Containers can't see each other
```

### Rule 2: Container Isolation

Each user gets their own OpenClaw in a container:

- Isolated network (can't talk to other containers)
- Isolated filesystem (can't see other users' data)
- Resource limits (can't DoS the host)
- No Docker socket (can't escape to host)

### Rule 3: Container Escape = One User Only

If an agent breaks out of its container:

- It gets ONE user's token (in memory)
- It CANNOT access other users
- It CANNOT access the secrets vault
- It CANNOT access the management database

---

## The Sharing Layer

This is what OCMT builds on top of OpenClaw's existing capabilities.

### Group Sharing: "This group exposes resources to members"

```
┌─────────────────────────────────────────────────────────────────┐
│                 GROUP SHARING (Simple Model)                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  White Rabbit Clubhouse (Group)                                    │
│  ├── Has: MCP server with events API                            │
│  ├── Grants access to: 8 of 10 users                            │
│  └── 6 users opt-in to use it                                   │
│                                                                  │
│  How it works:                                                   │
│                                                                  │
│  1. Group admin registers MCP server endpoint                     │
│     POST /api/groups/white-rabbit/resources                       │
│     { "name": "Events API", "endpoint": "https://..." }         │
│                                                                  │
│  2. Group admin grants access to users                            │
│     POST /api/groups/white-rabbit/grants                          │
│     { "user_id": "alice", "permissions": ["read", "write"] }    │
│                                                                  │
│  3. User opts-in (adds to their OpenClaw config)                │
│     User clicks "Connect to White Rabbit Events"                │
│     → OCMT injects MCP config into their container           │
│                                                                  │
│  4. User's agent can now use the group's MCP server               │
│     "Sign me up for the March event"                            │
│     → Agent calls events.signup() via MCP                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Peer Sharing: "I grant you access to query my agent"

```
┌─────────────────────────────────────────────────────────────────┐
│                 PEER SHARING (Simple Model)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Alice wants Bob's agent to check her calendar                   │
│                                                                  │
│  1. Alice grants Bob access                                      │
│     UI: "Share my calendar availability with Bob"               │
│     POST /api/peer-grants                                       │
│     { "grantee": "bob", "capability": "calendar:freebusy" }     │
│                                                                  │
│  2. Bob's agent discovers the grant                             │
│     When Bob asks "Check Alice's availability"                  │
│     → OCMT checks: Does Bob have a grant from Alice? ✓       │
│                                                                  │
│  3. Bob's agent queries Alice's agent                           │
│     Inter-container call (via OCMT gateway)                  │
│     → Alice's OpenClaw returns free/busy data                   │
│                                                                  │
│  4. Alice can revoke anytime                                     │
│     DELETE /api/peer-grants/{id}                                │
│     → Immediate: Bob loses access                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## What Users Do vs What OCMT Does

| Task                   | Who Does It | How                                |
| ---------------------- | ----------- | ---------------------------------- |
| Connect Google account | User        | OpenClaw's `openclaw integrations` |
| Add MCP server         | User        | OpenClaw's MCP config              |
| Configure tools        | User        | OpenClaw's tool policy             |
| Set up memory          | User        | OpenClaw's workspace files         |
| **Sign up**            | **OCMT**    | Web UI + container provisioning    |
| **Chat via web**       | **OCMT**    | WebSocket → container              |
| **Grant group access** | **OCMT**    | Permission database                |
| **Share with peer**    | **OCMT**    | Peer grant system                  |
| **View audit trail**   | **OCMT**    | Audit log UI                       |

---

## Infrastructure

### Management Server (mgmt.YOUR_DOMAIN)

- User accounts + authentication
- Group membership + permissions
- Peer grants database
- Secrets vault (API keys)
- Audit log

### Relay Server (relay.YOUR_DOMAIN)

- Encrypted message relay for container-to-container communication
- Zero-knowledge: CANNOT read message content
- WebSocket connections for real-time delivery
- Rate limiting (100 messages/hour per container)
- Wake-on-request for hibernated containers
- Logs: who -> whom, timestamp, size (NOT content)

### Agent Server (agents.YOUR_DOMAIN)

- Docker containers (one per user)
- Nginx proxy (routes to containers)
- Network isolation
- NO secrets on disk

### Per-User Container

- OpenClaw runtime
- User's workspace
- User's MCP configs
- Token in memory (injected at start)

---

## Data Model (Simplified)

```sql
-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE,
    name TEXT,
    container_id TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Groups
CREATE TABLE groups (
    id UUID PRIMARY KEY,
    name TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Group membership
CREATE TABLE group_memberships (
    user_id UUID REFERENCES users(id),
    group_id UUID REFERENCES groups(id),
    role TEXT DEFAULT 'member', -- 'member', 'admin'
    PRIMARY KEY (user_id, group_id)
);

-- Group resources (MCP servers the group exposes)
CREATE TABLE group_resources (
    id UUID PRIMARY KEY,
    group_id UUID REFERENCES groups(id),
    name TEXT,
    resource_type TEXT, -- 'mcp_server', 'api', etc.
    config JSONB,       -- endpoint, auth, etc.
    created_at TIMESTAMP DEFAULT NOW()
);

-- Group grants (who can access group resources)
CREATE TABLE group_grants (
    id UUID PRIMARY KEY,
    group_id UUID REFERENCES groups(id),
    user_id UUID REFERENCES users(id),
    resource_id UUID REFERENCES group_resources(id),
    permissions TEXT[], -- ['read'], ['read', 'write']
    created_at TIMESTAMP DEFAULT NOW()
);

-- Peer grants (user-to-user sharing)
CREATE TABLE peer_grants (
    id UUID PRIMARY KEY,
    grantor_id UUID REFERENCES users(id),
    grantee_id UUID REFERENCES users(id),
    capability TEXT,    -- 'calendar:freebusy', 'agent:query'
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Audit log
CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMP DEFAULT NOW(),
    user_id UUID,
    action TEXT,
    target_user_id UUID,
    target_group_id UUID,
    details JSONB
);

-- Relay messages (encrypted container-to-container)
CREATE TABLE relay_messages (
    id UUID PRIMARY KEY,
    from_container_id UUID NOT NULL,
    to_container_id UUID NOT NULL,
    payload_encrypted TEXT NOT NULL, -- Zero-knowledge: relay cannot decrypt
    payload_size INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW(),
    delivered_at TIMESTAMP
);

-- Relay rate limits (sliding window)
CREATE TABLE relay_rate_limits (
    container_id UUID PRIMARY KEY,
    window_start TIMESTAMP NOT NULL,
    message_count INTEGER DEFAULT 0
);
```

---

## What OpenClaw Already Handles

Don't rebuild these - they exist:

| Feature            | OpenClaw Location              | Docs                    |
| ------------------ | ------------------------------ | ----------------------- |
| Google OAuth       | `openclaw integrations google` | docs/integrations/      |
| MCP servers        | `openclaw mcp`                 | docs/mcp/               |
| Tool sandboxing    | `agents.sandbox` config        | docs/gateway/security/  |
| Memory/workspace   | `~/.openclaw/workspace/`       | docs/workspace/         |
| Telegram           | `channels.telegram` config     | docs/channels/telegram/ |
| Session management | `~/.openclaw/agents/`          | docs/sessions/          |

---

## Security Summary

```
What OCMT Secures:
├── Container isolation (users can't see each other)
├── Secret injection (keys never on agent server disk)
├── Group grants (who can access group resources)
├── Peer grants (who can query whose agent)
└── Audit trail (what happened)

What OpenClaw Secures:
├── Tool sandboxing (what tools agent can use)
├── MCP authentication (how agent talks to APIs)
├── Session isolation (conversation history)
└── Workspace access (file permissions)
```
