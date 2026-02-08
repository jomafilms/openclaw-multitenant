# OCMT Group Vault

Dedicated container for group-level secret storage. No agent, no chat capability - just secure encrypted storage with an HTTP API.

## Overview

Each group gets its own vault container that:

- Stores group-level secrets (shared API keys, database credentials, etc.)
- Uses AES-256-GCM encryption with Argon2id key derivation
- Provides scoped capability tokens for member access
- Maintains audit logs for all access

## Architecture

```
Management Server
       |
       v
Agent Server (provisions containers)
       |
       v
Group Vault Container (per group)
  - No agent
  - No chat
  - Just storage + API
```

## API Endpoints

### Management API (requires AUTH_TOKEN)

| Method | Endpoint               | Description                    |
| ------ | ---------------------- | ------------------------------ |
| POST   | `/init`                | Initialize vault with password |
| POST   | `/import`              | Import existing vault data     |
| GET    | `/export`              | Export encrypted vault         |
| POST   | `/unlock`              | Unlock vault (starts session)  |
| POST   | `/lock`                | Lock vault                     |
| POST   | `/extend`              | Extend unlock session          |
| GET    | `/status`              | Get vault status               |
| POST   | `/tokens`              | Issue capability token         |
| DELETE | `/tokens/:id`          | Revoke token                   |
| DELETE | `/tokens/user/:userId` | Revoke all tokens for user     |
| GET    | `/audit`               | Get audit logs                 |
| GET    | `/health`              | Health check                   |

### Secrets API (requires capability token)

| Method | Endpoint        | Description              |
| ------ | --------------- | ------------------------ |
| GET    | `/secrets`      | List secrets (keys only) |
| GET    | `/secrets/:key` | Get secret value         |
| POST   | `/secrets/:key` | Store secret             |
| DELETE | `/secrets/:key` | Delete secret            |

## Capability Tokens

Tokens are scoped to:

- Specific secrets or `*` for all
- Permissions: `read`, `write`, `delete`
- Time-to-live (TTL)

Example token payload:

```json
{
  "groupId": "group-123",
  "userId": "user-456",
  "allowedSecrets": ["api-key", "db-password"],
  "permissions": ["read"],
  "expiresAt": 1699999999999
}
```

## Security Model

1. **Encryption**: Vault data encrypted at rest with AES-256-GCM
2. **Key Derivation**: Argon2id with 64MB memory, 3 iterations
3. **Sessions**: Unlocked vaults expire after 30 minutes
4. **Tokens**: Signed with HMAC-SHA256, stored for revocation
5. **Audit**: Every access logged

## Environment Variables

| Variable      | Description               | Required            |
| ------------- | ------------------------- | ------------------- |
| `PORT`        | API port (default: 18790) | No                  |
| `GROUP_ID`    | Group ID                  | Yes                 |
| `AUTH_TOKEN`  | Management API auth token | Yes                 |
| `SIGNING_KEY` | Token signing key         | No (auto-generated) |

## Container Provisioning

Group vault containers are provisioned by the agent server:

```javascript
POST /api/group-vaults/provision
{
  "groupId": "group-123",
  "groupSlug": "acme-corp",
  "authToken": "secret-token"
}
```

## Integration with Threshold Unlock

The group vault supports threshold-based unlock where multiple admins must approve before the vault is unlocked. See `management-server/routes/group-vault.js` for the threshold approval flow.
