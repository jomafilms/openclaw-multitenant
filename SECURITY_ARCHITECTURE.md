# OCMT Security Architecture

> Security posture and implementation details for the OCMT multi-tenant platform layer.

---

## Security Posture

| Category                | Rating        | Notes                                                            |
| ----------------------- | ------------- | ---------------------------------------------------------------- |
| **Authentication**      | Strong        | Timing-safe comparison, session management, pairing system       |
| **Authorization**       | Strong        | Granular permissions (read/list/write/delete/admin/share)        |
| **Isolation**           | Excellent     | Per-user Docker containers, network isolation, no shared secrets |
| **Input Validation**    | Good          | Zod schemas, sanitization patterns                               |
| **Dependency Security** | Strong        | Dependabot, Semgrep, CodeQL, npm audit in CI                     |
| **Secrets Management**  | Good          | Per-group vault with AES-256-GCM, Argon2id key derivation        |
| **Audit Logging**       | Comprehensive | User actions, API calls, container activity logged               |
| **Container Security**  | Strong        | Non-root user, health checks, resource limits                    |

---

## Security Hardening (12 Plans Implemented)

| Plan                     | Description                                           |
| ------------------------ | ----------------------------------------------------- |
| 01 - Security Headers    | CSP, HSTS, CORS, HTTPS, request body limits           |
| 02 - Rate Limiting       | Redis-backed with Lua atomicity + exponential backoff |
| 03 - Multi-Factor Auth   | TOTP, backup codes, pending sessions                  |
| 04 - Session Security    | httpOnly, timeouts, SHA-256 hashed tokens             |
| 05 - Security Alerting   | Multi-channel (Slack/Discord/PagerDuty)               |
| 06 - Dependency Security | Audit, Dependabot, CVE response                       |
| 07 - Admin Security      | Token auth required, confirmation flow                |
| 08 - WebSocket Proxy     | Token via Sec-WebSocket-Protocol header               |
| 09 - XSS Mitigation      | HTML escaping, DOM APIs, safe templates               |
| 10 - Error Handling      | Sanitized responses, UUID validation                  |
| 11 - Encryption Rotation | Versioned format, migration support                   |
| 12 - CSRF Protection     | Double-submit, timing-safe comparison                 |
| 13 - Gateway Tokens      | Ephemeral signed tokens (1hr expiry)                  |
| 14 - Command Injection   | spawn() with argument arrays, input validation        |

---

## Secure Defaults

```yaml
gateway.bind: "loopback"           # Only localhost can connect
gateway.auth.mode: "token"         # Token required for connections
dmPolicy: "pairing"                # Unknown senders get pairing codes
container.user: "node" (uid 1000)  # Non-root in Docker
container.memory: "1.5GB"          # Resource limits enforced
```

---

## OWASP Top 10 Coverage

| Category                      | Status    | Implementation                               |
| ----------------------------- | --------- | -------------------------------------------- |
| A01 Broken Access Control     | Strong    | DM pairing, allowlists, tool policies        |
| A02 Cryptographic Failures    | Good      | node:crypto, AES-256-GCM, Argon2id           |
| A03 Injection                 | Mitigated | Prompt injection soft-gated via model choice |
| A04 Insecure Design           | Good      | Threat model documented                      |
| A05 Security Misconfiguration | Strong    | Secure defaults, audit tool                  |
| A06 Vulnerable Components     | Strong    | Dependabot, Semgrep, CodeQL                  |
| A07 Auth Failures             | Strong    | Session management, token auth               |
| A08 Data Integrity            | Good      | Audit logging, tamper detection              |
| A09 Logging Failures          | Good      | Comprehensive audit trail                    |
| A10 SSRF                      | Good      | Sandboxing available                         |

---

## Known Considerations

| Area              | Notes                                                                                          |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| Prompt injection  | Use Claude Opus 4+, enable sandbox mode for best protection                                    |
| Plugin sandboxing | Only install trusted plugins                                                                   |
| Login OAuth/SSO   | Magic link auth is secure (like Slack/Notion); OAuth login is convenience, SAML for enterprise |

---

## Container Isolation Model

```
┌─────────────────────────────────────────────────────┐
│                 Management Server                    │
│  ├── PostgreSQL (users, groups, shares, audit)      │
│  ├── Auth middleware (magic link, sessions)         │
│  └── Container orchestrator                         │
└─────────────────────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  User A     │  │  User B     │  │  User C     │
│  Container  │  │  Container  │  │  Container  │
├─────────────┤  ├─────────────┤  ├─────────────┤
│ - OpenClaw  │  │ - OpenClaw  │  │ - OpenClaw  │
│   Gateway   │  │   Gateway   │  │   Gateway   │
│ - Isolated  │  │ - Isolated  │  │ - Isolated  │
│   network   │  │   network   │  │   network   │
│ - Own vault │  │ - Own vault │  │ - Own vault │
└─────────────┘  └─────────────┘  └─────────────┘
```

**Security Properties:**

- One Docker container per user
- Isolated network bridge (containers cannot communicate)
- Per-user mount at `{DATA_DIR}/{userId}/`
- 1.5GB memory limit, CPU shares, no Docker socket
- API keys injected via env vars (never on disk)
- Container hibernation after idle (30min pause, 4hr stop)

**Zero-Knowledge Architecture:**

- Platform cannot read conversations or credentials
- End-to-end encrypted AI conversations
- All API keys/OAuth tokens in encrypted vault

---

## Encryption Schemes

| Data Type                          | Cipher                  | Notes                                     |
| ---------------------------------- | ----------------------- | ----------------------------------------- |
| **Vault (API keys, OAuth tokens)** | AES-256-GCM + Argon2id  | Industry standard, hardware acceleration  |
| **Session transcripts**            | XChaCha20-Poly1305      | High-volume, 24-byte nonces prevent reuse |
| **OAuth PKCE**                     | SHA-256 (S256 method)   | Standard PKCE code challenge              |
| **Social recovery shards**         | Shamir's Secret Sharing | Threshold recovery (e.g., 3-of-5)         |
| **Hardware backup key**            | Argon2id + AES-256-GCM  | YubiKey / hardware token support          |

---

## Zero-Knowledge OAuth (PKCE)

OAuth token exchange is fully zero-knowledge. The management server **never sees** OAuth tokens:

```
1. Container generates PKCE code_verifier + code_challenge (SHA-256)
2. Management server includes code_challenge in OAuth URL (never sees verifier)
3. User authorizes at provider (Google, etc.)
4. Management server forwards ONLY auth_code to container
5. Container exchanges code directly with provider using code_verifier
6. Tokens encrypted and stored in container vault
7. Management server only stores metadata (provider, email, timestamp)
```

Even if management server is compromised, attacker cannot obtain OAuth tokens.

---

## Key Code Locations

### Security Implementation

```
management-server/
├── middleware/
│   ├── auth.js                 # Session + API key auth (hashed tokens)
│   ├── org-auth.js             # Group membership checks
│   ├── tenant-context.js       # Tenant detection + scoping
│   ├── admin-security.js       # Admin security controls
│   └── security-headers.js     # CSP, HSTS, CORS
├── db/
│   ├── groups.js               # Group CRUD
│   ├── shares.js               # Permission grants
│   ├── group-vault.js          # Encrypted secrets
│   ├── sessions.js             # SHA-256 hashed session tokens
│   └── audit.js                # Audit logging
├── lib/
│   ├── encryption.js           # AES-256-GCM vault encryption
│   ├── gateway-tokens.js       # Ephemeral signed gateway tokens
│   ├── rate-limit.js           # Redis-backed rate limiting
│   ├── shamir.js               # Social recovery
│   └── recovery.js             # Hardware backup keys

agent-server/
├── routes/oauth-pkce.js        # Zero-knowledge OAuth

relay-server/
├── middleware/auth.js          # WebSocket auth via Sec-WebSocket-Protocol
├── lib/rate-limit.js           # Redis-backed distributed rate limiting
└── lib/redis.js                # Redis client for clustering

src/gateway/
└── secret-store-http.ts        # Vault unlock with exponential backoff

src/config/sessions/
└── encrypted-store.ts          # XChaCha20-Poly1305 session encryption

admin-ui/
└── server.js                   # Token auth, spawn() for commands, HTML escaping
```

### Security Documentation

See `docs/security/` for operator guides:

- `deployment.md` - TLS, network isolation, firewall rules
- `secrets.md` - Key management, encryption, Redis config
- `hardening.md` - Production checklist
- `monitoring.md` - Logging, alerting, incident response

---

## Security Audit

```bash
# Run built-in security audit
openclaw security audit           # Quick check
openclaw security audit --deep    # Live gateway probe
openclaw security audit --fix     # Apply safe fixes

# Check file permissions
chmod 700 ~/.openclaw
chmod 600 ~/.openclaw/openclaw.json
chmod 700 ~/.openclaw/credentials/
```

## Hardening Checklist

- [ ] Run `openclaw security audit --deep`
- [ ] Set `dmPolicy: "pairing"` for all channels
- [ ] Set `groupPolicy: "allowlist"` for groups
- [ ] Configure `sandbox.mode: "all"` unless full access needed
- [ ] Use Claude Opus 4+ for prompt injection resistance
- [ ] Enable audit logging
- [ ] Review session transcripts periodically
- [ ] Document allowed users in pairing allowlist
