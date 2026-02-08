# OCMT Documentation Index

> Entry point for architecture, planning, and implementation documents

---

## What is OCMT?

OCMT extends OpenClaw with:

- **Web UI** - Chat with your AI agent via browser (no CLI needed)
- **Multi-tenant infrastructure** - Isolated containers per user
- **Distributed trust** - Container-side secret store with zero-knowledge encryption
- **Capability-based sharing** - Ed25519 signed tokens for peer-to-peer access
- **User-friendly onboarding** - Non-technical users can get started easily

---

## Current Architecture

### Core Documents

| Document                                                                           | Description                                                   |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [ARCHITECTURE.md](/ARCHITECTURE.md)                                                | Core system architecture, security rules, container isolation |
| [architecture/container-secret-store.md](./architecture/container-secret-store.md) | Container-side secret store - the current vault system        |
| [mesh/trust-model.md](./mesh/trust-model.md)                                       | Relay service trust model and threat analysis                 |
| [MESH-SECURITY-ROADMAP.md](./MESH-SECURITY-ROADMAP.md)                             | Current implementation roadmap with phase status              |
| [ZERO-KNOWLEDGE-INTEGRATIONS.md](./ZERO-KNOWLEDGE-INTEGRATIONS.md)                 | MCP config injection, zero-knowledge OAuth flow               |
| [group-skills.md](./group-skills.md)                                               | Group skill docs - teaching agents to use group APIs          |

### Security & Operations

| Document                                                           | Description                              |
| ------------------------------------------------------------------ | ---------------------------------------- |
| [security/encrypted-sessions.md](./security/encrypted-sessions.md) | Zero-knowledge encrypted session storage |
| [api/vault-endpoints.md](./api/vault-endpoints.md)                 | Vault API endpoint documentation         |
| [plugin-security.md](./plugin-security.md)                         | Plugin isolation and security model      |
| [PRODUCTION-REVIEW-STATUS.md](./PRODUCTION-REVIEW-STATUS.md)       | Production security review status        |
| [ops-runbook.md](./ops-runbook.md)                                 | Operational runbook for production       |
| [deployment-checklist.md](./deployment-checklist.md)               | Deployment checklist                     |

### Research

| Document                                                                       | Description                                            |
| ------------------------------------------------------------------------------ | ------------------------------------------------------ |
| [research/MULTI_TENANT_AI_RESEARCH.md](./research/MULTI_TENANT_AI_RESEARCH.md) | Industry analysis, Web3 approaches, security deep dive |
| [CLOUD_RUN_ARCHITECTURE.md](./CLOUD_RUN_ARCHITECTURE.md)                       | Future cloud scaling architecture (draft)              |

---

## Architecture Overview

### Distributed Trust Model

```
┌──────────────────────────────────┐
│   Management Server (Trusted)     │
│   - User accounts & auth          │
│   - Group permissions database    │
│   - Recovery system coordination  │
└──────────────────────────────────┘
           ↕ (HTTPS, auth token)
┌──────────────────────────────────┐
│   Relay Service (Untrusted)       │
│   - Zero-knowledge message relay  │
│   - Revocation blocklist (Bloom)  │
│   - Wake-on-request               │
└──────────────────────────────────┘
           ↕ (Encrypted payloads)
┌──────────────────────────────────┐
│   Agent Server (Container Mgmt)   │
│   - Docker container lifecycle    │
│   - Unlock proxy (WebSocket)      │
│   - Per-user container isolation  │
└──────────────────────────────────┘
           ↕ (Direct unlock flow)
┌──────────────────────────────────┐
│   User Containers (Isolated)      │
│   - OpenClaw agent runtime        │
│   - Container-side secret store   │
│   - Ed25519 capability tokens     │
│   - Encrypted at-rest vault       │
└──────────────────────────────────┘
```

### Key Security Principles

1. **Secrets never leave containers** - Management server holds only metadata
2. **Direct unlock flow** - Browser → container directly, no password via server
3. **Container isolation** - Per-user containers with network/filesystem isolation
4. **Capability tokens** - Ed25519-signed tokens for cross-container sharing
5. **Relay service** - Zero-knowledge message relay with revocation blocklist

### Container-Side Secret Store

Each user container maintains its own encrypted vault:

| Protected Data      | Encryption         |
| ------------------- | ------------------ |
| Session transcripts | XChaCha20-Poly1305 |
| API keys            | XChaCha20-Poly1305 |
| OAuth tokens        | XChaCha20-Poly1305 |
| Capability tokens   | Ed25519 signed     |

- **Key Derivation**: Argon2id (64MB memory, GPU-resistant)
- **Recovery**: BIP39 12-word phrase, social recovery, hardware backup
- **Session**: 30-min auto-lock, biometric unlock (FaceID/TouchID)

See [architecture/container-secret-store.md](./architecture/container-secret-store.md) for full specification.

### Capability Tokens

Users share access via Ed25519-signed capability tokens:

```javascript
{
  iss: "<issuer-public-key>",      // Who created this
  sub: "<subject-public-key>",      // Who can use it
  resource: "google_calendar",      // What resource
  scope: ["read", "list"],          // What operations
  exp: 1707264000,                  // Expires at
  sig: "<ed25519-signature>"        // Cryptographic signature
}
```

See [architecture/container-secret-store.md](./architecture/container-secret-store.md#capability-tokens) for details.

---

## Implementation Status

| Component          | Status         | Description                                          |
| ------------------ | -------------- | ---------------------------------------------------- |
| Encrypted Sessions | ✅ Complete    | Zero-knowledge session transcript storage            |
| API Key Storage    | ✅ Complete    | Zero-knowledge API key vault                         |
| OAuth PKCE         | ✅ Complete    | Zero-knowledge token exchange (container ↔ provider) |
| Biometric Unlock   | ✅ Complete    | FaceID/TouchID via WebAuthn                          |
| Recovery System    | ✅ Complete    | BIP39, social recovery, hardware backup              |
| Capability Tokens  | ✅ Complete    | Ed25519 signed cross-container access                |
| Relay & Sharing    | 🔄 In Progress | Encrypted relay, wake-on-request                     |

See [MESH-SECURITY-ROADMAP.md](./MESH-SECURITY-ROADMAP.md) for detailed roadmap.

---

## Deployment

### Production Servers (DigitalOcean)

| Server                | IP                   | Purpose                   |
| --------------------- | -------------------- | ------------------------- |
| **User UI**           | YOUR_UI_SERVER_IP    | nginx serving web UI      |
| **Management Server** | YOUR_MGMT_SERVER_IP  | Auth, groups, permissions |
| **Agent Server**      | YOUR_AGENT_SERVER_IP | Container orchestration   |

### Domain

- **Production**: https://YOUR_DOMAIN
- SSL via Let's Encrypt
- nginx proxies `/api/*` to management server, `/ws/*` to agent server

---

## Archived Documentation

Historical documents from the MVP era (Feb 2-3, 2026) have been moved to:
[docs/archive/mvp-era/](./archive/mvp-era/)

These describe the original management-server vault implementation which has been superseded by the container-side secret store architecture.

---

## Getting Started

1. Read [ARCHITECTURE.md](/ARCHITECTURE.md) for system overview
2. Review [architecture/container-secret-store.md](./architecture/container-secret-store.md) for the current vault system
3. Check [MESH-SECURITY-ROADMAP.md](./MESH-SECURITY-ROADMAP.md) for implementation status
4. Reference [mesh/trust-model.md](./mesh/trust-model.md) for security analysis
