# Mesh Security Architecture Roadmap

> Zero-knowledge, distributed trust model for OCMT

## Overview

This roadmap covers the complete implementation of a mesh security architecture where:

- Secrets live ONLY in user containers (not management server)
- Management server holds metadata only
- Sharing uses cryptographic capability tokens
- Relay enables container-to-container communication without seeing content

## Task Dependencies

```
#16 Container Secret Store ──┬──► #17 Direct Unlock
                             ├──► #18 Ed25519 Signing ──┐
                             │                          │
                             └──────────────────────────┴──► #19 Tests
                                                              │
                                                              ▼
                                                        #20 Relay ──┬──► #21 Revocation
                                                              │     ├──► #25 Cached Sharing
                                                              │     ├──► #26 Wake-on-Request
                                                              │     └──► #33 Sharing UI
                                                              │
                                                              └──► #27 Group Vault ──► #28 Threshold Unlock

#16 + #17 + #19 ──► #30 Migration ──► #31 Delete Legacy

Independent:
- #22 Human-in-the-loop approval
- #23 Capability ceilings
- #24 Anomaly detection
- #29 Recovery options
- #32 Group invite acceptance
```

## Phase 1: Foundation

### #16 Integrate container-side secret store into OpenClaw runtime

Wire up SecretStore class into OpenClaw gateway. Secrets never leave container in plaintext.

### #17 Implement direct browser-to-container unlock flow

Browser connects directly to container WebSocket. Password never sent to management server.

### #18 Replace placeholder signing with Ed25519 (libsodium)

Real cryptographic signatures for capability tokens.

## Phase 2: Testing

### #19 Write comprehensive tests for secret store and capability tokens

- Key derivation tests
- Encrypt/decrypt roundtrip
- Capability token generation/verification
- Scope enforcement
- Expiry enforcement
- Revocation checks

## Phase 3: Relay & Sharing

### #20 Build encrypted message relay service

Zero-knowledge relay: forwards encrypted blobs, can't read content. Rate limiting, audit logging.

### #21 Implement instant capability revocation via relay blocklist

Bloom filter at relay for instant revoke. Solves the "token valid for 2 more hours after revoke" problem.

### #25 Implement CACHED sharing tier for offline access

A pushes encrypted snapshots. B reads without A online. Solves container availability trilemma.

### #26 Implement wake-on-request for hibernated containers

B requests → A hibernated → relay queues → wakes A → processes → returns.

### #33 Build sharing UI that hides capability complexity

User sees "Share my calendar with Bob", not "Issue Ed25519-signed capability token".

## Phase 4: Agent Safety

### #22 Add human-in-the-loop approval for sensitive agent operations

Agent wants to issue capability → push notification → user approves → then it happens.

### #23 Implement capability ceilings for agents

Agent can: read, list. Agent cannot: delete, admin, share-further. Limits prompt injection damage.

### #24 Add behavioral anomaly detection for agents

Track patterns. 10 calls/day → suddenly 10,000 → auto-lock, alert user. Weekly digest.

## Phase 5: Group Features

### #27 Build dedicated Group Vault container

No agent, just storage. Threshold unlock. Time-locked. Audit log to all admins.

### #28 Implement threshold unlock for group vault (2 of N admins)

2 of 3 admins approve → vault unlocked for 8 hours.

### #32 Design and implement group invite acceptance flow

Invite creates pending state. Invitee must accept. Hide user existence.

## Phase 6: Recovery & Migration

### #29 Add multiple recovery options (social, hardware, institutional)

User chooses: BIP39 phrase, social recovery (3 of 5 friends), hardware backup, institutional escrow.

### #30 Migrate existing users from management server vault to container vault

One-time migration for 2 test users. Decrypt on mgmt server, re-encrypt in container.

### #31 Delete legacy vault code after migration

**STATUS: DEFERRED** - Analysis complete (Feb 2026).

The management server vault code (`vault.js`, `vault-sessions.js`) is **NOT legacy** and
**cannot be removed**. It remains actively required for:

1. **User Authentication** - Vault unlock via password (routes/vault.js, routes/unlock.js)
2. **OAuth Token Storage** - Tokens stored encrypted in vault after OAuth callbacks (routes/oauth.js)
3. **Recovery Operations** - Social/hardware recovery needs vault crypto (routes/recovery.js, lib/recovery.js)
4. **Migration System** - The migration code reads FROM the vault (lib/migration.js)
5. **Credential Sync** - Syncs vault data to containers (lib/context.js)
6. **MCP Operations** - Vault access for MCP tools (lib/mcp.js)
7. **Biometrics** - Password age checks for biometric unlock (routes/biometrics.js)
8. **Anomaly Detection** - Session management for security (lib/anomaly-detection.js)

**Current Architecture:**

- Management server vault: User-facing operations, OAuth, recovery, password management
- Container secret store: Agent operations, capability tokens, local credential cache

**To achieve zero-knowledge (secrets ONLY in containers):**

1. Implement direct browser-to-container OAuth (bypass management server for tokens)
2. Move recovery to container-based key escrow
3. Replace management vault with container-first unlock (browser → container directly)
4. Only then can management vault code be deprecated

Until those prerequisites are complete, this task remains deferred.

## Other Tasks

### #13 Add embeddings API key support for memory_search

### #14 Revisit Google Drive OAuth scope - give users options

### #15 Add granular resource permissions and access controls

## Success Criteria

When complete:

- [ ] Hack management server → get metadata only, no credentials
- [ ] Hack one container → get ONE user's secrets only
- [ ] Agent prompt injection → limited by capability ceilings + human approval
- [ ] User loses password → recoverable via chosen method
- [ ] Non-tech users can share resources without understanding crypto
- [ ] All sensitive operations have audit trail
