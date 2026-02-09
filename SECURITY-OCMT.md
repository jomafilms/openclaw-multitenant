# OCMT Security

Security information specific to the OCMT (OpenClaw Multi-Tenant) layer.

For upstream OpenClaw security, see [SECURITY.md](./SECURITY.md).

## Known Dependency Issues

### Matrix Extension (Optional)

The Matrix extension (`extensions/matrix`) depends on `@vector-im/matrix-bot-sdk`, which transitively uses the deprecated `request` package with **CVE-2023-28155** (SSRF via cross-protocol redirect).

**Risk**: Moderate - affects outbound HTTP requests made by the Matrix bot.

**Mitigation**:

- The Matrix extension is optional and not installed by default
- Only install if you need Matrix/Element integration
- Monitor upstream for a fix: https://github.com/element-hq/matrix-bot-sdk

**Status**: Waiting for upstream migration away from `request` package.

## OCMT-Specific Security Features

### Authentication

- Passwordless magic link authentication
- SHA-256 hashed session tokens (never stored in plaintext)
- Timing-safe token comparison throughout
- Rate limiting on auth endpoints (5 attempts / 15 min)

### Encryption

- AES-256-GCM for vault storage
- Argon2id for key derivation (64MB memory, 3 iterations)
- Key rotation support with versioning

### Container Isolation

- Per-user Docker containers
- Network isolation between containers
- 1.5GB memory limit per container
- Non-root execution (uid 1000)

### Admin UI

- Token authentication via Authorization header only
- Binds to localhost by default (127.0.0.1)
- Access via SSH tunnel recommended for production

### Cookie Security

- Session cookies use `httpOnly`, `secure` (in production), and `sameSite="lax"`
- **Note**: `sameSite="lax"` is intentional - `"strict"` would break magic link and OAuth login flows that redirect from external domains

### API Security

- CORS with explicit origin validation (no wildcards)
- CSRF protection with HMAC-signed double-submit tokens
- Rate limiting with Redis (distributed across instances)
- Security headers: CSP, HSTS (1 year), X-Frame-Options: DENY

## Optional Security Enhancements (Not Yet Deployed)

The following services exist in the codebase but are optional enhancements:

### Relay Server (`relay-server/`)

Zero-knowledge encrypted message relay for container-to-container communication.

**Current state**: Resource sharing works via management-server (permission grants in database). The management server can see sharing metadata.

**With relay**: Containers communicate directly with end-to-end encryption. Management server only forwards encrypted blobs - cannot read shared content.

**When to deploy**: When you need privacy-sensitive sharing where even the platform shouldn't see what's being shared.

### Group Vault (`group-vault/`)

Dedicated encrypted storage for team/organization secrets with threshold unlock.

**Current state**: Per-user vaults work. Group sharing uses permission grants.

**With group-vault**: Shared secrets require N-of-M admin approval to unlock. Time-locked access. Separate audit log to all admins.

**When to deploy**: When you have teams that need shared credentials with governance controls.

See [MESH-SECURITY-ROADMAP.md](./docs/MESH-SECURITY-ROADMAP.md) for full implementation details.

## Privacy & Logging

### What the Platform CAN See (Metadata)

- Login times and IP addresses
- Vault lock/unlock events (not contents)
- Which integrations are connected (e.g., "Google Calendar")
- Group membership changes
- Session activity
- MFA events

### What the Platform CANNOT See (Zero-Knowledge)

- Vault contents (encrypted with user's password)
- Conversation content (stays in isolated container)
- Actual credentials/API keys (encrypted in vault)
- What the agent does inside the container

### Hardening Options

For maximum privacy, operators can:

1. **Disable audit logging** per tenant (trades security visibility for privacy)
2. **Reduce log retention** (7 days vs 90 days)
3. **Export-only logging** (logs go to tenant's own system)
4. **Self-host** with no external log aggregation

### Approval Request Data

The `capability_approvals` table stores `reason` and `agentContext` for human-in-the-loop workflows. These may contain conversation context. Future enhancement: encrypt these fields with the user's vault key.

## Reporting OCMT-Specific Issues

For security issues specific to the OCMT layer (management-server, agent-server, relay-server, admin-ui, user-ui, group-vault), please report via GitHub Security Advisories.
