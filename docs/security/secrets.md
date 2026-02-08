# Secret Management

How to securely manage secrets for OCMT deployments.

## ENCRYPTION_KEY

The `ENCRYPTION_KEY` encrypts all user secrets stored in the database, including API keys and OAuth tokens.

### Requirements

| Requirement   | Value                                |
| ------------- | ------------------------------------ |
| Length        | 64 hexadecimal characters (32 bytes) |
| Character set | 0-9, a-f (lowercase hex)             |
| Entropy       | Cryptographically random             |
| Algorithm     | AES-256-GCM                          |

### Generating a Key

```bash
# Using Node.js (recommended)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Using OpenSSL
openssl rand -hex 32

# Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### Example Output

```
a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

### Configuration

```bash
# In .env file or environment
ENCRYPTION_KEY=a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

### Backup Requirements

**Critical**: If you lose the encryption key, all encrypted data becomes unrecoverable.

- [ ] Store key in a secure secrets manager (1Password, HashiCorp Vault, AWS Secrets Manager)
- [ ] Keep an offline backup in a secure location
- [ ] Document the backup location for disaster recovery
- [ ] Never commit the key to version control

### Key Rotation

OCMT supports key rotation without downtime:

```bash
# Step 1: Store current key as versioned backup
ENCRYPTION_KEY_V0=<current-key>

# Step 2: Generate new key
ENCRYPTION_KEY=<new-key>
ENCRYPTION_KEY_VERSION=1

# Step 3: Deploy with both keys
# The system will read with old key, write with new key

# Step 4: Run migration to re-encrypt all data
# (migration script updates all encrypted values to new key)

# Step 5: Remove old key after migration completes
```

See [Security Plan 11](/security-plans/11-encryption-key-rotation) for detailed rotation procedures.

---

## ADMIN_TOKEN

The `ADMIN_TOKEN` protects the admin UI and administrative API endpoints.

### Requirements

| Requirement    | Value                    |
| -------------- | ------------------------ |
| Minimum length | 24 characters            |
| Character set  | Base64 or alphanumeric   |
| Entropy        | Cryptographically random |

### Generating a Token

```bash
# Using Node.js (recommended)
node -e "console.log(require('crypto').randomBytes(24).toString('base64'))"

# Using OpenSSL
openssl rand -base64 24
```

### Configuration

```bash
# Admin UI (admin-ui/server.js)
ADMIN_TOKEN=YourSecureRandomToken123456789

# Pass via header or query parameter
curl -H "Authorization: Bearer YourSecureRandomToken123456789" http://localhost:8080/admin
# or
curl http://localhost:8080/admin?token=YourSecureRandomToken123456789
```

### Protected Endpoints

When `ADMIN_TOKEN` is set, these endpoints require authentication:

- `GET /admin` - Admin dashboard
- `POST /api/approve-pairing` - Approve device pairing
- `GET /api/files/*` - File browser
- `POST /api/chat` - Chat interface

---

## AGENT_SERVER_TOKEN

Authenticates communication between management server and agent server.

### Generating

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Configuration

```bash
# On management server
AGENT_SERVER_TOKEN=<token>
AGENT_SERVER_URL=http://agent-server:4000

# On agent server (must match)
AUTH_TOKEN=<same-token>
```

---

## Redis Configuration

For distributed deployments, Redis stores rate limiting state and OAuth session data.

### Connection URL Format

```bash
# Without authentication
REDIS_URL=redis://redis-host:6379

# With authentication
REDIS_URL=redis://:password@redis-host:6379

# With TLS (rediss://)
REDIS_URL=rediss://:password@redis-host:6379
```

### Redis Security

```yaml
# docker-compose.yml
services:
  redis:
    image: redis:7-alpine
    command: >
      redis-server
      --appendonly yes
      --requirepass ${REDIS_PASSWORD}
      --maxmemory 256mb
      --maxmemory-policy volatile-lru
    networks:
      - internal # Not exposed to public
```

### What Redis Stores

| Data Type           | TTL             | Purpose                      |
| ------------------- | --------------- | ---------------------------- |
| Rate limit counters | 2x window       | Request rate limiting        |
| OAuth state tokens  | 10 minutes      | PKCE flow state              |
| Session metadata    | Session timeout | Distributed session tracking |
| Vault sessions      | 1 hour          | Unlocked vault state         |

**Security note**: Redis data is not encrypted at rest. Use network isolation and authentication.

### Vault Session Persistence

Vault sessions use Redis when available, with automatic fallback to in-memory storage.

**Without Redis** (default):

- Vault sessions stored in-memory
- Sessions lost on server restart
- Users must re-unlock after deployments
- Credentials remain synced to containers regardless

**With Redis** (recommended for production):

- Vault sessions persist across restarts
- Sessions automatically expire after 1 hour TTL
- Set `REDIS_URL` to enable

---

## API Key Storage

User API keys (for AI providers like OpenAI, Anthropic) are stored encrypted in the database.

### Encryption Flow

```
User Input → SHA-256 Hash (for lookup) → Stored in DB
           ↘ AES-256-GCM Encrypt → Stored in vault
```

### Security Properties

- API keys are hashed for lookup (cannot be reversed)
- Full key encrypted with ENCRYPTION_KEY
- Decryption only happens in user's container
- Management server never sees plaintext keys

---

## Session Token Security

Session tokens authenticate users after login.

### Storage

```sql
-- Sessions table
token_hash VARCHAR(64)  -- SHA-256 hash, not plaintext
```

### Security Properties

- Plaintext token only returned once at login
- Database stores SHA-256 hash
- Compromised database does not expose tokens
- Session timeout enforced server-side

### Configuration

```bash
# Session timeout (default: 7 days)
USER_SESSION_TIMEOUT_MS=604800000

# Max sessions per user (default: 5)
MAX_SESSIONS_PER_USER=5
```

---

## Gateway Token Security

Gateway tokens authenticate CLI and API connections to the gateway.

### Generation

```bash
# Tokens are generated during onboarding
openclaw onboard
# Or manually
openssl rand -hex 32
```

### Configuration

```bash
# Environment variable
OPENCLAW_GATEWAY_TOKEN=<token>

# Or in config file
# ~/.openclaw/openclaw.json
{
  "gateway": {
    "auth": {
      "token": "<token>"
    }
  }
}
```

### Security Considerations

- Tokens should be unique per deployment
- Store in environment variables, not config files when possible
- Rotate tokens if compromised
- Use `--bind loopback` for local-only access

---

## Environment Variable Best Practices

### Do

```bash
# Use environment variables for secrets
DATABASE_URL=postgresql://...
ENCRYPTION_KEY=...
ADMIN_TOKEN=...

# Set restrictive permissions
chmod 600 .env

# Use secrets manager in production
# AWS Secrets Manager, HashiCorp Vault, etc.
```

### Do Not

```bash
# Never commit secrets to version control
git add .env  # NO!

# Never log secrets
console.log(process.env.ENCRYPTION_KEY);  # NO!

# Never include in Docker images
COPY .env /app/.env  # NO!
```

### Production Secret Management

**Recommended approaches**:

1. **Cloud secrets manager** (AWS Secrets Manager, GCP Secret Manager)
2. **HashiCorp Vault** for on-premises deployments
3. **Docker secrets** for Swarm deployments
4. **Kubernetes secrets** with encryption at rest

---

## Secret Rotation Checklist

### Routine Rotation (Recommended: Quarterly)

- [ ] Rotate ADMIN_TOKEN
- [ ] Rotate AGENT_SERVER_TOKEN
- [ ] Update Redis password
- [ ] Rotate database password

### After Security Incident

- [ ] Rotate ENCRYPTION_KEY (requires migration)
- [ ] Rotate all tokens immediately
- [ ] Invalidate all user sessions
- [ ] Review audit logs
- [ ] Rotate OAuth client secrets

---

## See Also

- [Deployment Security](/security/deployment)
- [Production Hardening](/security/hardening)
- [Encrypted Sessions](/security/encrypted-sessions)
