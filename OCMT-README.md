# OpenClaw-Multitenant (OCMT)

Multi-tenant deployment layer for [OpenClaw](https://github.com/openclaw/openclaw). Adds container isolation, encrypted credential storage, and team collaboration.

## Components

This fork adds these components on top of OpenClaw:

| Component             | Description                                                    | Status   |
| --------------------- | -------------------------------------------------------------- | -------- |
| **management-server** | Auth, users, groups, vault, integrations (Express, PostgreSQL) | Core     |
| **agent-server**      | Container orchestration and lifecycle (Node.js, Docker API)    | Core     |
| **user-ui**           | Web interface for users (Lit, Vite)                            | Core     |
| **admin-ui**          | Platform administration                                        | Core     |
| **group-vault**       | Threshold-unlock team secrets (N-of-M approval)                | Optional |
| **relay-server**      | Zero-knowledge encrypted container-to-container relay          | Optional |

## Features

- **Container isolation** — Each user gets their own OpenClaw instance in Docker
- **Encrypted vault** — API keys and OAuth tokens encrypted at rest (AES-256-GCM, Argon2id)
- **Groups** — Organize users, share resources, manage permissions
- **MFA** — TOTP-based multi-factor authentication
- **Approvals** — Human-in-the-loop for sensitive actions
- **Audit log** — Track activity across the platform
- **Integrations** — OAuth connections to external services

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User UI                                  │
│                    (Lit, Vite, TypeScript)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Management Server                             │
│  • Auth (magic link, MFA)                                        │
│  • Users, Groups, Permissions                                    │
│  • Encrypted Vault                                               │
│  • Integrations, Audit                                           │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Agent Server                                │
│  • Container lifecycle (start, stop, hibernate)                  │
│  • Resource limits                                               │
│  • Health monitoring                                             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
    ┌───────────┐   ┌───────────┐   ┌───────────┐
    │  User A   │   │  User B   │   │  User C   │
    │ Container │   │ Container │   │ Container │
    │ (OpenClaw)│   │ (OpenClaw)│   │ (OpenClaw)│
    └───────────┘   └───────────┘   └───────────┘
```

## Security Model

**Credential isolation**: The management server stores credentials in an encrypted vault. Credentials are decrypted only when injected into a user's container memory — never written to disk on the agent server.

**Container isolation**: Each container runs with:

- Isolated network namespace
- Isolated filesystem
- Resource limits (CPU, memory)
- No Docker socket access

**Blast radius**: A compromised container affects only that user's session.

## Development

```bash
# Management server
cd management-server
npm install
npm run db:migrate
npm run dev

# Agent server
cd agent-server
npm install
npm run dev

# User UI
cd user-ui
npm install
npm run dev
```

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md).

## Security

See [SECURITY-OCMT.md](SECURITY-OCMT.md) for security details, known issues, and optional enhancements.

## License

MIT

## Credits

Built on [OpenClaw](https://github.com/openclaw/openclaw).
