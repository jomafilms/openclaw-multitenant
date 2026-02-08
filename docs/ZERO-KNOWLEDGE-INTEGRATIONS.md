# Zero-Knowledge Integrations

> **Status:** ✅ Fully Zero-Knowledge (February 2026)

The platform **never sees user credentials** - not during storage, not during exchange. API keys and OAuth tokens are stored exclusively in user containers, encrypted with the user's vault key. OAuth token exchange uses PKCE and happens directly between the container and the OAuth provider.

## Architecture

```
┌─────────────────┐        ┌─────────────────┐        ┌─────────────────┐
│     Browser     │───────►│ Agent Server    │───────►│   Container     │
│                 │        │ (proxy only)    │        │                 │
│ API Key Entry   │        │ Never stores    │        │ secrets.enc     │
│ ─────────────── │        │ credentials     │        │ (encrypted)     │
│ Key sent direct │        │                 │        │                 │
│ to container    │        │                 │        │ Vault Key in    │
└─────────────────┘        └─────────────────┘        │ memory (30min)  │
                                                      └─────────────────┘
```

## Implementation Status

| Component                   | Status  | Location                             |
| --------------------------- | ------- | ------------------------------------ |
| Container API key storage   | ✅ Done | `src/container/secret-api.ts`        |
| MCP credential proxy        | ✅ Done | `management-server/lib/mcp.js`       |
| Zero-knowledge UI flow      | ✅ Done | `user-ui/src/lib/api.ts`             |
| Container vault sync/backup | ✅ Done | `management-server/routes/vault.js`  |
| API key tests               | ✅ Done | `src/container/apikey-vault.test.ts` |
| Zero-knowledge OAuth (PKCE) | ✅ Done | `agent-server/routes/oauth-pkce.js`  |

## How It Works

### Adding an API Key

1. User enters API key in browser
2. Browser sends key **directly to container** (not management server)
3. Container encrypts with vault key and stores in `secrets.enc`
4. Management server only records metadata (provider name, timestamp)

### Agent Accessing Credentials

1. Agent calls `ocmt_get_credentials` MCP tool
2. MCP proxy forwards request to user's container
3. Container decrypts and returns credential (if vault unlocked)
4. If vault locked, returns `vault_locked` error with unlock URL

### Vault Sync (Backup)

Encrypted vault blobs can be synced to management server for backup:

- Management server stores only encrypted blobs
- Cannot decrypt without user's vault key
- Enables vault restoration on new containers

## What the Platform Cannot See

| Data                   | Platform Access                       |
| ---------------------- | ------------------------------------- |
| API keys               | ❌ Never                              |
| OAuth tokens           | ❌ Never (PKCE exchange in container) |
| PKCE code_verifier     | ❌ Never (generated in container)     |
| Vault password         | ❌ Never                              |
| Derived encryption key | ❌ Never                              |
| Decrypted credentials  | ❌ Never                              |

## What the Platform Can See

| Data                  | Purpose                                |
| --------------------- | -------------------------------------- |
| Provider names        | Show "Google Calendar connected" in UI |
| Connection timestamps | Audit trail                            |
| Encrypted blobs       | Backup only, cannot decrypt            |

---

## Zero-Knowledge OAuth with PKCE

OAuth tokens use a zero-knowledge PKCE flow where tokens **never touch the management server**:

```
1. Container generates PKCE code_verifier + code_challenge
2. Management server includes code_challenge in auth URL (never sees verifier)
3. User authorizes at Google
4. Management server forwards ONLY auth_code to container
5. Container exchanges code directly with Google (using code_verifier)
6. Tokens stored in container's encrypted vault
7. Management server only stores metadata (provider name, email, timestamp)
```

### Implementation

| Component                        | File                                |
| -------------------------------- | ----------------------------------- |
| PKCE generation & token exchange | `agent-server/routes/oauth-pkce.js` |
| Auth URL & code forwarding       | `management-server/routes/oauth.js` |

### Security Properties

- **code_verifier**: Generated and stored only in container, never transmitted to management server
- **code_challenge**: SHA-256 hash of verifier, safe to include in auth URL
- **access_token / refresh_token**: Exchanged directly between container and Google, encrypted in vault
- **Management server**: Only sees auth_code (useless without code_verifier) and metadata

---

## Related Documentation

- [Encrypted Sessions](./security/encrypted-sessions.md) - Session transcript encryption
- [Container Secret Store](./architecture/container-secret-store.md) - Full vault architecture
- [Vault Endpoints](./api/vault-endpoints.md) - API reference
