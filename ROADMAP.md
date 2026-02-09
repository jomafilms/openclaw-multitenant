# Roadmap

This document outlines the development roadmap for OCMT, a multi-tenant platform layer built on top of OpenClaw.

## Current State (v1.0)

OCMT extends OpenClaw with:

- **Zero-Knowledge Architecture** - Platform cannot read your conversations or credentials
- **Container Isolation** - One Docker container per user with network isolation
- **Credential Vault** - Encrypted secrets with team sharing (AES-256-GCM, Argon2id)
- **Groups & Sharing** - Organizations with admin/member roles and granular permissions
- **Peer Grants** - User-to-user capability sharing
- **Human-in-the-Loop** - Approval workflows for sensitive operations
- **Container Hibernation** - Auto-pause/stop idle containers to reduce resource usage

## Phase 1: Core Platform (Complete)

- [x] Per-user Docker container provisioning
- [x] PostgreSQL data model (users, groups, shares, vault)
- [x] Magic link authentication
- [x] Group membership and roles
- [x] Resource sharing with granular permissions (read/list/write/delete/admin/share)
- [x] Per-org encrypted vault
- [x] Peer-to-peer capability grants
- [x] Container hibernation (pause after 30min, stop after 4hr)
- [x] Audit logging
- [x] Integration OAuth (Google Drive, etc. - connect services to your account)
- [x] End-to-end encrypted AI conversations (platform cannot read)
- [x] All API keys and OAuth tokens stored in vault (zero-knowledge)
- [x] Zero-knowledge OAuth with PKCE (tokens never touch management server)
- [x] Self-service vault recovery:
  - [x] BIP39 mnemonic phrase (12-word recovery)
  - [x] Social recovery (Shamir's Secret Sharing, 3-of-5 contacts)
  - [x] Hardware backup key (Base32, YubiKey-compatible)

## Phase 2: Multi-Tenant SaaS (Complete)

### Tenant Scoping Layer

- [x] Add `tenant_id` to all relevant database tables
- [x] Tenant detection middleware (from JWT/API key/session)
- [x] Automatic query filtering by tenant
- [x] Cross-tenant access prevention at database layer

### API Authentication Expansion

- [x] API key authentication for service-to-service
- [x] Login OAuth ("Sign in with Google/GitHub/Microsoft")
- [x] SAML/SSO (enterprise requirement)
- [x] Service account tokens for deployed agents
- [x] JWT tokens with tenant subject

### Billing & Quotas

- [x] Stripe integration for subscriptions
- [x] Subscription tiers (free, pro, enterprise)
- [x] Per-tenant quotas (agents, users, API calls)
- [x] Usage-based billing calculation
- [x] Rate limiting per tenant

### Self-Service Onboarding

- [x] Sign up → Create org → Deploy agent → Chat flow
- [x] Invite team members
- [x] Configure first agent
- [x] Auto-provision container

## Phase 3: Production Hardening (Complete)

### Security Enhancements

- [x] Data encryption at rest (sessions encrypted with XChaCha20-Poly1305)
- [x] Encryption key rotation automation
- [ ] Plugin sandboxing (isolated execution) - planned for v2.0

### Operations

- [x] Admin dashboard for platform operators
- [x] Tenant health monitoring
- [x] Tenant branding (custom branding per tenant)
- [x] Backup/restore per tenant
- [ ] Container auto-scaling - planned
- [ ] Multi-region deployment - planned
- [ ] Cost attribution per tenant - planned
- [ ] Centralized audit log export (SIEM integration) - planned

### Compliance

- [ ] SOC 2 readiness - planned
- [ ] GDPR compliance features - planned
- [ ] Data residency controls - planned

### Privacy Hardening

- [ ] Configurable audit log retention per tenant
- [ ] Option to disable platform-side audit logging
- [ ] Encrypt approval request data with user's vault key
- [ ] Export-only logging (logs go to tenant's SIEM, not stored on platform)

## Phase 4: Enterprise Features (Future)

- [ ] Advanced RBAC (owner, admin, member, observer, custom roles)
- [ ] Federated identity management
- [ ] Custom branding per tenant
- [ ] Advanced analytics and reporting
- [ ] SLA monitoring and enforcement
- [ ] Dedicated infrastructure option

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas for contribution:

1. Tenant scoping middleware
2. API key authentication
3. Billing integration
4. Admin dashboard

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      User UI (Lit, Vite)                        │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Management Server                             │
│  - Auth (magic link, OAuth, API keys)                           │
│  - Groups, Shares, Vault                                         │
│  - MCP proxy, Integrations                                       │
│  - Billing, Quotas (planned)                                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Agent Server                                │
│  - Container orchestration                                       │
│  - Hibernation management                                        │
│  - Health monitoring                                             │
└─────────────────────────────────────────────────────────────────┘
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

See [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) for the full security assessment and hardening details.

Key security properties:

- Container escape affects only one user (isolation)
- Secrets never stored on agent container disk
- Management database never exposed to containers
- Per-org vault with capability-based access
- Comprehensive audit logging
