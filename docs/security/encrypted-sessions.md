# Encrypted Sessions

OCMT implements end-to-end encrypted session storage, ensuring that conversation data is protected at rest. This document describes the security model, cryptographic choices, and threat analysis.

## Overview

OCMT's encrypted session storage uses a **zero-knowledge model** similar to 1Password and Signal. The key insight is:

- **The platform never sees your password or derived keys**
- All cryptographic operations happen in your browser or device
- Only encrypted data is stored on the server

```
Browser                Container              Management Server
   |                      |                         |
   | (1) Password ------->|                         |
   |   [Argon2id KDF]     |                         |
   | (2) Derived Key ---->|                         |
   |   [XChaCha20-Poly1305]                        |
   |                      |                         |
   |                 Encrypted Sessions             |
   |                      |                         |
```

## Encryption Details

### Algorithm: XChaCha20-Poly1305

We use XChaCha20-Poly1305 (from `@noble/ciphers`) for symmetric encryption:

- **24-byte nonce**: Eliminates nonce reuse risk (vs AES-GCM's 12-byte nonce)
- **256-bit key**: Provides ~128-bit security post-quantum
- **Poly1305 MAC**: Provides authentication and integrity

### Key Derivation: Argon2id

User passwords are converted to encryption keys using Argon2id:

| Parameter   | Value          | Rationale                |
| ----------- | -------------- | ------------------------ |
| Memory      | 64 MB          | Resistant to GPU attacks |
| Iterations  | 3              | Balance security/latency |
| Parallelism | 4              | Utilize modern CPUs      |
| Salt        | 128-bit random | Unique per user          |
| Output      | 256-bit        | Match cipher key size    |

These parameters are tuned for ~1 second derivation on modern devices while remaining resistant to offline attacks.

## Trust Boundaries

```
+----------------------+     +----------------------+
|      Browser         |     |     Container        |
|  - Password entry    |     |  - Encrypted storage |
|  - Key derivation    |     |  - Session files     |
|  - Biometric auth    |     |  - Vault service     |
+----------------------+     +----------------------+
          |                           |
          | (encrypted)               | (encrypted)
          v                           v
+--------------------------------------------------+
|              Management Server                    |
|  - NEVER sees: passwords, derived keys, sessions |
|  - Only sees: encrypted blobs, metadata          |
+--------------------------------------------------+
```

### What the Platform Can See

- Encrypted session files (unreadable without key)
- Session metadata (timestamps, message counts)
- User authentication tokens
- Device fingerprints for biometric unlock

### What the Platform Cannot See

- Raw passwords
- Derived encryption keys
- Decrypted session content
- Biometric device keys

## Threat Model

### Attacker with Database Access

An attacker who gains read access to the database sees:

- Encrypted session files (`.jsonl.enc`)
- User salts (needed for KDF)
- Encrypted biometric device keys

**Cannot do:** Decrypt sessions without the user's password

### Attacker with Container Access

An attacker who gains access to a running container sees:

- Encrypted session files
- Derived key (while vault is unlocked)

**Mitigation:** 30-minute auto-lock clears key from memory

### Attacker with Browser Access

An attacker with access to the user's browser sees:

- Derived key (during unlock session)
- Biometric device key (in IndexedDB)

**Mitigation:**

- WebAuthn requires physical biometric verification
- Session timeout clears keys
- Keys are overwritten with random bytes before release

### Attacker at the Network Layer

An attacker who can intercept network traffic sees:

- TLS-encrypted communications
- Cannot see derived keys or session content

## Session Timeout

Sessions auto-lock after 30 minutes of inactivity:

1. Timer starts when vault is unlocked
2. Each operation extends the timer
3. On timeout:
   - Derived key is overwritten with random bytes
   - Key reference is nullified
   - Any ongoing operations fail gracefully

Users can:

- Manually lock at any time
- Extend the session before timeout
- Unlock again with password or biometric

## Biometric Security

Biometric unlock allows users to skip password entry on registered devices:

### Registration Flow

1. User unlocks vault with password
2. WebAuthn creates a device-bound credential
3. Container generates a random device key
4. Device key is stored in browser (IndexedDB)
5. Device key is encrypted with vault key and stored

### Unlock Flow

1. WebAuthn verifies biometric (FaceID/TouchID)
2. Device key is retrieved from IndexedDB
3. Device key is sent to container
4. Container decrypts vault key from device key
5. Vault is unlocked

### Security Properties

- Device key is useless without the physical device (WebAuthn)
- Device key is tied to a specific browser/domain
- Compromised device key cannot be used from another device
- Password change invalidates all device registrations

## Comparison to Similar Systems

| Feature          | OCMT               | 1Password          | Signal       |
| ---------------- | ------------------ | ------------------ | ------------ |
| Zero-knowledge   | Yes                | Yes                | Yes          |
| Key derivation   | Argon2id           | PBKDF2/Argon2      | Curve25519   |
| Symmetric cipher | XChaCha20-Poly1305 | AES-GCM            | AES-CTR-HMAC |
| Biometric unlock | WebAuthn           | Platform SDK       | Platform SDK |
| Auto-lock        | 30 min             | Configurable       | Configurable |
| Key rotation     | On password change | On password change | Ratcheted    |

## Implementation Notes

### Secure Key Erasure

Keys are cleared from memory by:

1. Overwriting with `crypto.randomFillSync()`
2. Nullifying the reference
3. Relying on garbage collection

JavaScript cannot guarantee memory clearing, but these steps make key recovery difficult.

### Atomic File Writes

Encrypted session files are written atomically:

1. Write to temporary file
2. Rename to target path
3. Clean up temporary file

This prevents corruption from crashes during writes.

### Session File Format

Encrypted sessions use `.jsonl.enc` extension:

- Header: nonce (24 bytes)
- Body: encrypted JSONL (XChaCha20-Poly1305)

Each message append re-encrypts the entire file to prevent leak of message order/timing.

## Recommendations

1. **Use a strong password**: 16+ characters, random
2. **Enable biometric unlock**: More secure than weak passwords
3. **Lock when not in use**: Don't leave vault unlocked
4. **Review registered devices**: Remove unknown devices
5. **Update regularly**: Security improvements are released

## References

- [XChaCha20-Poly1305](https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [Argon2](https://github.com/P-H-C/phc-winner-argon2)
- [WebAuthn](https://webauthn.guide/)
- [1Password Security Model](https://1password.com/security/)
