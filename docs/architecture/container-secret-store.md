# Container-Side Secret Store

> **Status:** ✅ Implemented (February 2026)

## Overview

Each user container maintains its own encrypted secret store. Secrets never leave the container in plaintext. The management server only stores metadata (what integrations exist) and encrypted blobs it cannot decrypt.

### What's Stored

| Credential Type     | Storage        | Encryption         |
| ------------------- | -------------- | ------------------ |
| API Keys            | Container only | XChaCha20-Poly1305 |
| OAuth Tokens        | Container only | XChaCha20-Poly1305 |
| Session Transcripts | Container only | XChaCha20-Poly1305 |
| Capability Tokens   | Container only | Ed25519 signed     |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER CONTAINER                           │
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   OpenClaw   │───►│ Secret Store │───►│ External APIs    │  │
│  │    Agent     │    │   (locked)   │    │ (Google, etc.)   │  │
│  └──────────────┘    └──────┬───────┘    └──────────────────┘  │
│                             │                                   │
│                      ┌──────▼───────┐                          │
│                      │ ~/.ocmt/  │                          │
│                      │ secrets.enc  │ ← Encrypted at rest      │
│                      └──────────────┘                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Unlock via secure channel
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                         USER DEVICE                             │
│  Browser / Mobile App / CLI                                     │
│  - User enters vault password                                   │
│  - Derived key sent directly to container (not via mgmt server) │
└─────────────────────────────────────────────────────────────────┘
```

## Encryption Design

### Key Derivation

```
User Password
     │
     ▼ Argon2id (memory-hard, GPU-resistant)
     │
     ├──► Vault Key (256-bit)
     │         │
     │         ├──► Local Secrets Key (for container-local secrets)
     │         └──► Capability Signing Key (for issuing capability tokens)
     │
     └──► Auth Key (for authenticating unlock requests)
```

### Storage Format

```
~/.ocmt/secrets.enc
{
  "version": 2,
  "algorithm": "XChaCha20-Poly1305",
  "kdf": {
    "algorithm": "argon2id",
    "salt": "<base64>",
    "memory": 65536,
    "iterations": 3,
    "parallelism": 4
  },
  "nonce": "<base64>",
  "ciphertext": "<base64>",
  "tag": "<base64>"
}
```

### Decrypted Structure

```javascript
{
  // API Keys (zero-knowledge storage)
  apiKeys: {
    "openai": {
      key: "sk-...",
      addedAt: "2026-02-07T12:00:00Z"
    },
    "anthropic": {
      key: "sk-ant-...",
      addedAt: "2026-02-07T12:00:00Z"
    }
  },

  // OAuth integrations
  integrations: {
    "google_calendar": {
      accessToken: "ya29...",
      refreshToken: "1//...",
      expiresAt: "2026-02-06T12:00:00Z",
      email: "user@gmail.com",
      scopes: ["calendar.readonly"]
    },
    "google_drive": { ... }
  },

  // User's keypair for capability tokens
  identity: {
    publicKey: "<base64>",
    privateKey: "<encrypted with vault key>"
  },

  // Capability tokens others have granted to this user
  capabilities: {
    "<capability-id>": {
      issuer: "<user-b-public-key>",
      resource: "google_calendar",
      scope: ["read"],
      expires: "2024-02-07T00:00:00Z",
      token: "<signed-token>"
    }
  },

  // Capability tokens this user has issued to others
  grants: {
    "<capability-id>": {
      subject: "<user-c-public-key>",
      resource: "google_drive",
      scope: ["read", "write"],
      expires: "2024-02-10T00:00:00Z",
      revoked: false
    }
  }
}
```

## Unlock Flow

### Direct Unlock (No Management Server in Path)

```
1. User visits https://unlock.YOUR_DOMAIN?container=<id>

2. Browser establishes WebSocket directly to container
   wss://agent-server/containers/<id>/unlock

3. Container sends challenge:
   { challenge: "<random-32-bytes>", salt: "<kdf-salt>" }

4. Browser:
   - User enters password
   - Derives key locally: key = argon2id(password, salt)
   - Signs challenge: signature = sign(challenge, key)
   - Sends: { signature }

5. Container:
   - Verifies signature matches stored auth key
   - Derives vault key from password (same derivation)
   - Decrypts secrets.enc
   - Stores vault key in memory (with timeout)
   - Responds: { success: true, expiresIn: 1800 }

6. Management server is NOT involved in unlock
   - Only knows "container X was unlocked" (audit event)
   - Never sees password or derived key
```

### Session Management

```javascript
class SecretStoreSession {
  vaultKey: Buffer | null = null;
  expiresAt: number = 0;

  unlock(derivedKey: Buffer) {
    // Verify key can decrypt
    const secrets = this.decrypt(derivedKey);
    if (!secrets) throw new Error('Invalid key');

    this.vaultKey = derivedKey;
    this.expiresAt = Date.now() + SESSION_TIMEOUT;

    // Auto-lock on timeout
    setTimeout(() => this.lock(), SESSION_TIMEOUT);
  }

  lock() {
    // Securely zero the key
    if (this.vaultKey) {
      crypto.randomFillSync(this.vaultKey);
      this.vaultKey = null;
    }
    this.expiresAt = 0;
  }

  isUnlocked(): boolean {
    return this.vaultKey !== null && Date.now() < this.expiresAt;
  }
}
```

## Capability Tokens

### Token Structure

```javascript
{
  // Header
  version: 1,
  algorithm: "Ed25519",

  // Claims
  iss: "<issuer-public-key>",      // Who created this capability
  sub: "<subject-public-key>",      // Who can use it
  aud: "<issuer-container-id>",     // Where to send requests

  resource: "google_calendar",      // What resource
  scope: ["read", "list"],          // What operations

  iat: 1707177600,                  // Issued at
  exp: 1707264000,                  // Expires at

  constraints: {
    maxCalls: 100,                  // Usage limit
    rateLimit: "10/minute",         // Rate limit
    ipAllowlist: ["container-b"]    // Network restrictions
  },

  // Signature
  sig: "<base64>"                   // Ed25519 signature over claims
}
```

### Issuing a Capability

```javascript
async function issueCapability(
  subjectPublicKey: string,
  resource: string,
  scope: string[],
  expiresIn: number
): Promise<CapabilityToken> {
  if (!this.isUnlocked()) {
    throw new Error('Vault locked');
  }

  const secrets = this.getSecrets();
  const { publicKey, privateKey } = secrets.identity;

  const claims = {
    iss: publicKey,
    sub: subjectPublicKey,
    aud: this.containerId,
    resource,
    scope,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor((Date.now() + expiresIn) / 1000),
    constraints: { maxCalls: 100 }
  };

  const signature = ed25519.sign(
    JSON.stringify(claims),
    privateKey
  );

  const token = { ...claims, sig: base64(signature) };

  // Store grant record
  secrets.grants[tokenId] = {
    subject: subjectPublicKey,
    resource,
    scope,
    expires: new Date(claims.exp * 1000).toISOString(),
    revoked: false
  };

  await this.saveSecrets(secrets);

  return token;
}
```

### Executing a Capability (Receiving Side)

```javascript
async function executeCapability(
  capabilityToken: CapabilityToken,
  request: ResourceRequest
): Promise<ResourceResponse> {
  // 1. Verify token signature
  const claims = { ...capabilityToken };
  delete claims.sig;

  const valid = ed25519.verify(
    JSON.stringify(claims),
    base64Decode(capabilityToken.sig),
    capabilityToken.iss  // Issuer's public key
  );

  if (!valid) {
    throw new Error('Invalid capability signature');
  }

  // 2. Check expiry
  if (capabilityToken.exp < Date.now() / 1000) {
    throw new Error('Capability expired');
  }

  // 3. Check this is for us
  if (capabilityToken.aud !== this.containerId) {
    throw new Error('Capability not for this container');
  }

  // 4. Check scope allows this operation
  if (!capabilityToken.scope.includes(request.operation)) {
    throw new Error('Operation not in capability scope');
  }

  // 5. Check constraints (rate limit, max calls)
  await this.checkConstraints(capabilityToken, request);

  // 6. Execute the actual API call
  const secrets = this.getSecrets();
  const credential = secrets.integrations[capabilityToken.resource];

  if (!credential) {
    throw new Error('Resource not connected');
  }

  // 7. Make the real API call
  const response = await this.callExternalAPI(
    credential,
    request
  );

  // 8. Audit log
  await this.auditLog('capability.executed', {
    capability: tokenId(capabilityToken),
    resource: capabilityToken.resource,
    operation: request.operation,
    subject: capabilityToken.sub
  });

  return response;
}
```

## Container-to-Container Communication

### Message Relay Protocol

```
Container B wants to access Container A's calendar:

1. B's container encrypts request with A's public key:
   {
     capability: "<token>",
     request: { operation: "list", params: {...} }
   }

2. B sends to relay:
   POST /relay/send
   {
     to: "container-a-id",
     payload: "<encrypted-blob>"
   }

3. Relay:
   - Validates B is allowed to message A (group check)
   - Queues message for A
   - Wakes A if hibernating
   - Returns { messageId, status: "queued" }

4. A's container receives via WebSocket:
   - Decrypts with private key
   - Executes capability
   - Encrypts response with B's public key
   - Sends back via relay

5. B receives response:
   - Decrypts with private key
   - Returns to agent
```

### Relay Message Format

```javascript
// Outer envelope (relay can read)
{
  id: "<message-id>",
  from: "<container-b-id>",
  to: "<container-a-id>",
  timestamp: 1707177600,
  type: "capability_request",

  // Encrypted payload (relay cannot read)
  payload: "<encrypted-with-recipient-public-key>"
}

// Decrypted payload
{
  capability: { /* full token */ },
  request: {
    operation: "list",
    resource: "google_calendar",
    params: {
      timeMin: "2024-02-01",
      timeMax: "2024-02-28"
    }
  },
  replyTo: "<b-public-key>"  // For encrypting response
}
```

## Implementation Status

| Phase   | Description                           | Status         |
| ------- | ------------------------------------- | -------------- |
| Phase 1 | Container secret store, direct unlock | ✅ Complete    |
| Phase 2 | Identity & Ed25519 keypairs           | ✅ Complete    |
| Phase 3 | Capability tokens                     | ✅ Complete    |
| Phase 4 | Relay & cross-container messaging     | 🔄 In Progress |

### Implementation Files

| Component          | File                                     |
| ------------------ | ---------------------------------------- |
| Secret Store       | `src/container/secret-api.ts`            |
| Vault Service      | `src/services/vault-service.ts`          |
| Encrypted Sessions | `src/config/sessions/encrypted-store.ts` |
| Biometric Keys     | `src/services/biometric-keys.ts`         |
| API Key Storage    | `src/container/secret-api.ts`            |
| OAuth PKCE         | `agent-server/routes/oauth-pkce.js`      |
| Vault Routes       | `agent-server/routes/vault.js`           |

## Security Considerations

### Key Rotation

- User can rotate vault password
- Old capabilities remain valid until expiry
- Identity keypair rotation requires re-issuing all capabilities

### Revocation

- Immediate: Mark grant as revoked in issuer's store
- Relay can maintain revocation list (bloom filter)
- Capability execution checks revocation before proceeding

### Container Compromise

- Attacker gets ONE user's secrets
- Cannot forge capabilities for other users (no private key)
- Cannot decrypt other containers' messages
- Revoke all capabilities immediately on detection

### Backup & Recovery

- Encrypted backup to user's cloud storage (optional)
- Social recovery: split key among trusted contacts
- Hardware key backup (YubiKey, etc.)

## File Locations

```
~/.ocmt/
├── secrets.enc          # Encrypted secret store
├── identity.pub         # Public key (can be shared)
├── capabilities/        # Received capability tokens
│   └── <id>.token
├── grants/              # Issued grants (for revocation)
│   └── <id>.grant
└── relay/               # Pending relay messages
    └── inbox/
        └── <id>.msg
```

## API Surface

### Container HTTP API (Local Only)

```
# Vault Management
POST /vault/unlock         { derivedKey } → { success, expiresIn }
POST /vault/lock           → { success }
GET  /vault/status         → { locked, expiresIn }
POST /vault/extend         → { expiresIn }

# API Keys (zero-knowledge)
POST   /apikeys/:provider  { key } → { success }
GET    /apikeys/:provider  → { key }
DELETE /apikeys/:provider  → { success }
GET    /apikeys            → { providers: [...] }

# OAuth Integrations
POST /secrets/integrations/:provider  { accessToken, refreshToken, ... } → { success }
GET  /secrets/integrations            → { integrations: [...] }

# Capability Tokens
POST /capabilities/issue   { subject, resource, scope, expiresIn } → { token }
POST /capabilities/execute { token, request } → { response }
POST /capabilities/revoke/:id → { success }

# Biometrics
POST   /vault/biometrics/enable   { fingerprint, name } → { deviceKey }
POST   /vault/biometrics/unlock   { fingerprint, deviceKey } → { expiresIn }
GET    /vault/biometrics/devices  → { devices: [...] }
DELETE /vault/biometrics/devices/:fingerprint → { success }
```

### MCP Tools (Agent-Facing)

```
ocmt_vault_status
  → { locked, expiresIn }

ocmt_unlock_link
  → { url }  // Direct to container, not mgmt server

ocmt_get_credentials
  { provider }
  → { key } or { accessToken, ... } or { error: "vault_locked" }

ocmt_list_integrations
  → { integrations: [{ provider, type, status }] }

ocmt_issue_capability
  { userId, resource, scope, expiresIn }
  → { capabilityId, token }

ocmt_call_shared_resource
  { capabilityId, operation, params }
  → { response }

ocmt_list_capabilities
  { type: "issued" | "received" }
  → { capabilities: [...] }

ocmt_revoke_capability
  { capabilityId }
  → { success }
```

When vault is locked, credential requests return `{ error: "vault_locked", unlockUrl: "..." }` so agents can guide users to unlock.
