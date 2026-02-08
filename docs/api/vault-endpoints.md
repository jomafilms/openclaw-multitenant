# Vault API Endpoints

This document describes the HTTP and WebSocket endpoints for vault operations.

## Overview

OCMT uses a multi-tier architecture for vault operations:

1. **Browser** - Where key derivation happens
2. **Management Server** - Provides connection info, never sees keys
3. **Agent Server** - Proxies requests to containers
4. **Container** - Where encryption/decryption happens

## Authentication

All endpoints require authentication:

- Management Server endpoints: Session cookie or Bearer token
- Agent Server endpoints: `x-auth-token` header
- Container endpoints: Accessed via agent server proxy

## Management Server Endpoints

### GET /api/container/unlock-info

Get connection info for direct browser-to-container communication.

**Response:**

```json
{
  "agentServerUrl": "https://agent.YOUR_DOMAIN",
  "userId": "user-123",
  "wsPath": "/api/containers/user-123/unlock",
  "httpPathPrefix": "/api/containers/user-123/vault",
  "authToken": "transport-auth-token"
}
```

## Session Vault Endpoints

These endpoints manage encrypted session storage.

### GET /vault/session/status

Get session vault status.

**Response:**

```json
{
  "success": true,
  "status": {
    "initialized": true,
    "locked": false,
    "expiresIn": 1800,
    "sessionsEncrypted": true
  }
}
```

### GET /vault/session/challenge

Get KDF parameters for client-side key derivation.

**Response:**

```json
{
  "success": true,
  "challenge": {
    "salt": "base64-encoded-salt",
    "kdf": {
      "algorithm": "argon2id",
      "memory": 65536,
      "iterations": 3,
      "parallelism": 4
    }
  }
}
```

### POST /vault/session/unlock

Unlock the session vault with a derived key.

**Request:**

```json
{
  "derivedKey": "base64-encoded-32-byte-key"
}
```

**Response:**

```json
{
  "success": true,
  "expiresIn": 1800
}
```

**Errors:**

- `400` - Missing derivedKey
- `401` - Invalid key
- `503` - Container not available

### POST /vault/session/lock

Lock the session vault immediately.

**Response:**

```json
{
  "success": true
}
```

### POST /vault/session/extend

Extend the vault session timeout.

**Response:**

```json
{
  "success": true,
  "expiresIn": 1800
}
```

**Errors:**

- `401` - Vault is locked

### POST /vault/session/migrate

Migrate plaintext sessions to encrypted format.

**Response:**

```json
{
  "success": true,
  "migrated": 5,
  "failed": []
}
```

**Errors:**

- `401` - Vault must be unlocked to migrate

## Biometric Endpoints

These endpoints manage device-based vault unlock.

### POST /vault/biometrics/enable

Register a device for biometric unlock. Requires vault to be unlocked.

**Request:**

```json
{
  "fingerprint": "device-hardware-fingerprint",
  "name": "iPhone"
}
```

**Response:**

```json
{
  "success": true,
  "deviceKey": "base64-encoded-device-key"
}
```

**Errors:**

- `401` - Vault must be unlocked to enable biometrics

### POST /vault/biometrics/unlock

Unlock vault using a device key.

**Request:**

```json
{
  "fingerprint": "device-hardware-fingerprint",
  "deviceKey": "base64-encoded-device-key"
}
```

**Response:**

```json
{
  "success": true,
  "expiresIn": 1800
}
```

**Errors:**

- `401` - Invalid device key

### GET /vault/biometrics/devices

List registered biometric devices. Requires vault to be unlocked.

**Response:**

```json
{
  "success": true,
  "devices": [
    {
      "fingerprint": "device-fingerprint-1",
      "name": "iPhone",
      "registeredAt": 1699000000000,
      "lastUsedAt": 1699100000000
    }
  ]
}
```

### DELETE /vault/biometrics/devices/:fingerprint

Remove a registered device. Requires vault to be unlocked.

**Response:**

```json
{
  "success": true
}
```

## Legacy Vault Endpoints

These endpoints manage the original vault (for integrations/capabilities).

### GET /vault/status

Get legacy vault status.

**Response:**

```json
{
  "initialized": true,
  "locked": false,
  "expiresIn": 1800,
  "publicKey": "base64-encoded-public-key"
}
```

### POST /vault/unlock/challenge

Generate an unlock challenge.

**Response:**

```json
{
  "challengeId": "challenge-uuid",
  "challenge": "base64-random-challenge",
  "salt": "base64-salt-or-null"
}
```

### POST /vault/unlock/verify

Verify challenge response and unlock.

**Request:**

```json
{
  "challengeId": "challenge-uuid",
  "response": "base64-hmac-response",
  "derivedKey": "base64-derived-key"
}
```

**Response:**

```json
{
  "success": true,
  "expiresIn": 1800
}
```

### POST /vault/lock

Lock the vault.

**Response:**

```json
{
  "success": true
}
```

### POST /vault/extend

Extend vault session.

**Response:**

```json
{
  "success": true,
  "expiresIn": 1800
}
```

## WebSocket Protocol

The WebSocket endpoint provides real-time vault operations.

### Connection

```
ws://agent-server/api/containers/{userId}/unlock
```

### Message Format

All messages are JSON with an `id` and `type` field:

```json
{
  "id": "unique-request-id",
  "type": "message-type",
  ...
}
```

### Message Types

#### status

Get vault status.

**Request:**

```json
{
  "id": "1",
  "type": "status"
}
```

**Response:**

```json
{
  "id": "1",
  "type": "response",
  "success": true,
  "data": {
    "initialized": true,
    "locked": false,
    "expiresIn": 1800
  }
}
```

#### challenge

Get unlock challenge.

**Request:**

```json
{
  "id": "2",
  "type": "challenge"
}
```

**Response:**

```json
{
  "id": "2",
  "type": "response",
  "success": true,
  "data": {
    "challengeId": "uuid",
    "challenge": "base64",
    "salt": "base64"
  }
}
```

#### unlock

Unlock with derived key.

**Request:**

```json
{
  "id": "3",
  "type": "unlock",
  "challengeId": "uuid",
  "response": "base64-hmac",
  "derivedKey": "base64-key"
}
```

**Response:**

```json
{
  "id": "3",
  "type": "response",
  "success": true,
  "data": {
    "expiresIn": 1800
  }
}
```

#### lock

Lock the vault.

**Request:**

```json
{
  "id": "4",
  "type": "lock"
}
```

#### extend

Extend session timeout.

**Request:**

```json
{
  "id": "5",
  "type": "extend"
}
```

#### session:status / session:unlock / session:lock / session:extend

Session vault operations follow the same pattern with `session:` prefix.

### Error Responses

```json
{
  "id": "request-id",
  "type": "error",
  "error": "Error message"
}
```

## Error Codes

| HTTP Code | Meaning                                     |
| --------- | ------------------------------------------- |
| 400       | Bad Request - Missing or invalid parameters |
| 401       | Unauthorized - Invalid key or vault locked  |
| 404       | Not Found - Container or resource not found |
| 503       | Service Unavailable - Container not ready   |
| 504       | Gateway Timeout - Container wake timeout    |

## Rate Limiting

Vault endpoints are rate-limited:

- Unlock attempts: 5 per minute per IP
- Status checks: 60 per minute per user
- Other operations: 30 per minute per user

Exceeding limits returns `429 Too Many Requests`.
