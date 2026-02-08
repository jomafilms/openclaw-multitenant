# Mesh Security: Relay Trust Model

This document analyzes the security implications of relay-enforced capability revocation.

## Overview

OCMT's mesh architecture enables users to share access to resources (like OAuth tokens) via **capability tokens**. These tokens are cryptographically signed and have an expiry time.

The problem: If user A revokes user B's capability at 10:05, but the token expires at 12:00, user B still has access for nearly 2 hours.

The solution: A relay service maintains a **revocation blocklist** that provides instant enforcement.

## Architecture

```
┌─────────────────┐    1. Revoke    ┌─────────────────┐
│                 │ ──────────────> │                 │
│  Container A    │                 │  Relay Service  │
│  (Issuer)       │                 │  (Blocklist)    │
│                 │ <────────────── │                 │
└─────────────────┘    ACK          └─────────────────┘
                                            │
                                            │ 2. Check
                                            ▼
                       ┌─────────────────────────────────┐
                       │                                 │
                       │  All subsequent requests with   │
                       │  that capability are REJECTED   │
                       │                                 │
                       └─────────────────────────────────┘
```

## Trust Analysis

### What the Relay Gains

| Power             | Description                                 |
| ----------------- | ------------------------------------------- |
| Enforcement       | Can block capability usage network-wide     |
| Visibility        | Learns which capabilities are being checked |
| Denial of Service | Could falsely claim revocation              |

### What the Relay Cannot Do

| Limitation            | Why                                                 |
| --------------------- | --------------------------------------------------- |
| Forge revocations     | Revocations must be signed by the capability issuer |
| Read capability data  | Capabilities are encrypted end-to-end               |
| Impersonate users     | No access to private keys                           |
| Modify in-flight data | Only sees capability IDs, not payloads              |

### Mitigations

1. **Signed Revocations**: Every revocation request must include:
   - The capability ID
   - The issuer's public key
   - A timestamp
   - A signature from the issuer's Ed25519 private key

   The relay verifies this signature before accepting the revocation.

2. **Timestamp Validation**: Revocation requests are rejected if the timestamp is more than 5 minutes old or in the future. This prevents replay attacks.

3. **Graceful Degradation**: If the relay is unreachable, capabilities still work based on their expiry time. Revocation is best-effort.

4. **Audit Logging**: All revocation operations are logged with full details, enabling detection of anomalies.

5. **Relay Choice**: Users can self-host relays or choose trusted relay operators.

## Implementation Details

### Bloom Filter

The relay uses a Bloom filter for fast O(1) revocation checks:

- **False positives**: Possible (a non-revoked capability might be flagged for a database check)
- **False negatives**: Impossible (a revoked capability will always be caught)
- **Default settings**: 100k items at 0.1% false positive rate

When the Bloom filter says "might be revoked", the relay checks the authoritative database.

### Revocation Flow

1. **Container A** calls `revokeCapability(id)` on the secret store
2. **Secret Store** marks the capability as revoked locally
3. **Secret Store** calls `notifyRevocation(id)` on the relay client
4. **Relay Client** signs the revocation and sends to relay
5. **Relay Service** verifies signature and adds to blocklist
6. **Relay Service** updates Bloom filter

### Message Forwarding Check

Before forwarding any message that uses a capability, the relay:

1. Extracts the capability ID from the message
2. Checks Bloom filter (O(1))
3. If Bloom filter says "might contain", checks database
4. If revoked, rejects with error immediately

## Threat Scenarios

### Malicious Relay Operator

**Scenario**: Relay operator falsely reports capabilities as revoked.

**Impact**: Denial of service for legitimate capability usage.

**Detection**: Users notice capabilities failing before expiry. Audit logs show no matching revocation request from issuer.

**Mitigation**:

- Switch to a different relay
- Self-host relay
- Fall back to expiry-only model

### Compromised Relay

**Scenario**: Attacker gains control of relay infrastructure.

**Impact**:

- Can block legitimate capabilities
- Can learn which capabilities are being used (metadata)
- Cannot forge capabilities or access data

**Mitigation**:

- Rotate to new relay
- Capabilities without relay check still work until expiry
- No data breach (relay never sees plaintext)

### Replay Attack

**Scenario**: Attacker captures and replays a revocation request.

**Impact**: Could revoke a capability that was later re-issued.

**Mitigation**: Timestamp validation (5-minute window) + capability IDs are unique random values.

## Comparison with Alternatives

| Approach             | Instant Revoke | Privacy | Complexity |
| -------------------- | -------------- | ------- | ---------- |
| Short expiry (5 min) | Sort of        | High    | Low        |
| Relay blocklist      | Yes            | Medium  | Medium     |
| Blockchain           | Yes            | Low     | High       |
| Direct issuer check  | Yes            | High    | High       |

The relay blocklist approach balances instant revocation with reasonable privacy and complexity.

## Configuration

### Container Side

```typescript
import { getSecretStore } from "./container/secret-store.js";

const store = getSecretStore({
  baseDir: "~/.ocmt",
  relayUrl: "https://relay.example.com",
});

// Revoke with relay notification
const result = await store.revokeCapability("cap-id", {
  reason: "User requested",
});

if (!result.relayNotified) {
  console.warn("Relay notification failed:", result.relayError);
}
```

### Relay Side

```typescript
import { createRevocationService, createRevocationMiddleware } from "./relay/index.js";

const service = createRevocationService();
const middleware = createRevocationMiddleware(service);

// In message forwarding handler
function forwardMessage(capabilityId: string, message: unknown) {
  const check = middleware.shouldBlock(capabilityId);
  if (check.blocked) {
    throw new Error(`Capability revoked: ${check.reason}`);
  }
  // Proceed with forwarding...
}
```

## Future Considerations

1. **Distributed Relays**: Multiple relays with revocation propagation
2. **Revocation Certificates**: Offline-verifiable signed revocation proofs
3. **Privacy-Preserving Checks**: Zero-knowledge proofs for revocation status
4. **Threshold Revocation**: Require multiple parties to agree on revocation
