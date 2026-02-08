# Security Plan 03: Multi-Factor Authentication (MFA)

## Overview

Add TOTP-based MFA (Google Authenticator compatible) and optional WebAuthn/Passkeys support to OCMT. The implementation integrates with the existing magic link flow by adding a verification step after successful magic link authentication.

## Current State

- Magic-link only authentication in `routes/auth.js`
- Session management in `middleware/auth.js`
- Existing `deviceKeys` table with WebAuthn fields
- Encryption utilities (AES-256-GCM) in `db/index.js`
- Comprehensive audit logging

---

## Implementation Plan

### Phase 1: Database Schema

Add migration `db/migrations/20260207_add_mfa_tables.sql`:

```sql
-- MFA configuration per user
CREATE TABLE user_mfa (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  totp_secret_encrypted TEXT,
  totp_enabled BOOLEAN DEFAULT FALSE,
  totp_verified_at TIMESTAMPTZ,
  mfa_enforced BOOLEAN DEFAULT FALSE,
  preferred_method VARCHAR(20) DEFAULT 'totp',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id)
);

-- Backup codes for recovery
CREATE TABLE mfa_backup_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- MFA verification attempts
CREATE TABLE mfa_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  attempt_type VARCHAR(20) NOT NULL,
  success BOOLEAN NOT NULL,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Pending MFA sessions (between magic link and MFA)
CREATE TABLE pending_mfa_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Add to users table
ALTER TABLE users
ADD COLUMN mfa_required BOOLEAN DEFAULT FALSE,
ADD COLUMN mfa_last_verified_at TIMESTAMPTZ;

-- Indexes
CREATE INDEX idx_user_mfa_user ON user_mfa(user_id);
CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);
CREATE INDEX idx_pending_mfa_token ON pending_mfa_sessions(session_token);
```

---

### Phase 2: TOTP Module

Create `management-server/lib/totp.js`:

```javascript
import { TOTP, Secret } from "otpauth";
import crypto from "crypto";
import QRCode from "qrcode";
import { encrypt, decrypt } from "../db/index.js";

const TOTP_CONFIG = {
  issuer: "OCMT",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};

export function generateTotpSecret() {
  const secret = new Secret({ size: 20 });
  const encryptedSecret = encrypt(secret.base32);
  return { secret: secret.base32, encryptedSecret };
}

export function generateTotpUri(email, secret) {
  const totp = new TOTP({
    ...TOTP_CONFIG,
    label: email,
    secret: Secret.fromBase32(secret),
  });
  return totp.toString();
}

export async function generateTotpQRCode(email, secret) {
  const uri = generateTotpUri(email, secret);
  return QRCode.toDataURL(uri, {
    errorCorrectionLevel: "M",
    width: 256,
    margin: 2,
  });
}

export function verifyTotpCode(encryptedSecret, code) {
  const secret = decrypt(encryptedSecret);
  const totp = new TOTP({
    ...TOTP_CONFIG,
    secret: Secret.fromBase32(secret),
  });
  const delta = totp.validate({ token: code, window: 1 });
  return delta !== null;
}
```

---

### Phase 3: Backup Codes Module

Create `management-server/lib/backup-codes.js`:

```javascript
import crypto from "crypto";
import argon2 from "argon2";

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LENGTH = 8;

export async function generateBackupCodes() {
  const codes = [];
  const hashedCodes = [];
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    let code = "";
    const randomBytes = crypto.randomBytes(BACKUP_CODE_LENGTH);
    for (let j = 0; j < BACKUP_CODE_LENGTH; j++) {
      code += chars[randomBytes[j] % chars.length];
    }

    const formattedCode = `${code.slice(0, 4)}-${code.slice(4)}`;
    codes.push(formattedCode);

    const hash = await argon2.hash(code, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16,
      timeCost: 3,
    });
    hashedCodes.push(hash);
  }

  return { codes, hashedCodes };
}

export async function verifyBackupCode(code, hash) {
  const normalizedCode = code.replace(/-/g, "").toUpperCase();
  return argon2.verify(hash, normalizedCode);
}
```

---

### Phase 4: MFA API Routes

Create `management-server/routes/mfa.js`:

```javascript
import { Router } from "express";
import crypto from "crypto";
import { users, audit, sessions } from "../db/index.js";
import { userMfa, mfaBackupCodes, mfaAttempts, pendingMfaSessions } from "../db/mfa.js";
import { requireUser } from "../middleware/auth.js";
import { createRateLimiter } from "../lib/rate-limit.js";
import { generateTotpSecret, generateTotpQRCode, verifyTotpCode } from "../lib/totp.js";
import { generateBackupCodes, verifyBackupCode } from "../lib/backup-codes.js";

const router = Router();

const mfaVerifyLimiter = createRateLimiter({
  name: "mfa-verify",
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
});

// Get MFA status
router.get("/status", requireUser, async (req, res) => {
  const mfaConfig = await userMfa.findByUserId(req.user.id);
  const backupCodesRemaining = await mfaBackupCodes.countUnused(req.user.id);

  res.json({
    totpEnabled: mfaConfig?.totp_enabled || false,
    mfaEnforced: mfaConfig?.mfa_enforced || false,
    backupCodesRemaining,
  });
});

// Begin TOTP setup
router.post("/totp/setup", requireUser, async (req, res) => {
  const existingMfa = await userMfa.findByUserId(req.user.id);
  if (existingMfa?.totp_enabled) {
    return res.status(400).json({ error: "TOTP already enabled" });
  }

  const { secret, encryptedSecret } = generateTotpSecret();
  const qrCode = await generateTotpQRCode(req.user.email, secret);

  await userMfa.upsert(req.user.id, {
    totpSecretEncrypted: encryptedSecret,
    totpEnabled: false,
  });

  res.json({ secret, qrCode });
});

// Verify and enable TOTP
router.post("/totp/verify", requireUser, mfaVerifyLimiter, async (req, res) => {
  const { code } = req.body;
  const mfaConfig = await userMfa.findByUserId(req.user.id);

  if (!mfaConfig?.totp_secret_encrypted) {
    return res.status(400).json({ error: "TOTP setup not started" });
  }

  const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);

  await mfaAttempts.log({
    userId: req.user.id,
    attemptType: "totp_setup",
    success: isValid,
    ipAddress: req.ip,
  });

  if (!isValid) {
    return res.status(401).json({ error: "Invalid code" });
  }

  await userMfa.upsert(req.user.id, {
    totpEnabled: true,
    totpVerifiedAt: new Date(),
  });

  const { codes, hashedCodes } = await generateBackupCodes();
  await mfaBackupCodes.replaceAll(req.user.id, hashedCodes);

  await audit.log(req.user.id, "mfa.totp_enabled", null, req.ip);

  res.json({ success: true, backupCodes: codes });
});

// Disable TOTP
router.post("/totp/disable", requireUser, mfaVerifyLimiter, async (req, res) => {
  const { code } = req.body;
  const mfaConfig = await userMfa.findByUserId(req.user.id);

  if (!mfaConfig?.totp_enabled) {
    return res.status(400).json({ error: "TOTP not enabled" });
  }

  const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);
  if (!isValid) {
    return res.status(401).json({ error: "Invalid code" });
  }

  await userMfa.upsert(req.user.id, {
    totpSecretEncrypted: null,
    totpEnabled: false,
  });
  await mfaBackupCodes.deleteAll(req.user.id);
  await audit.log(req.user.id, "mfa.totp_disabled", null, req.ip);

  res.json({ success: true });
});

// Verify TOTP during login
router.post("/verify/totp", mfaVerifyLimiter, async (req, res) => {
  const { pendingToken, code } = req.body;

  const pending = await pendingMfaSessions.findByToken(pendingToken);
  if (!pending || pending.expires_at < new Date()) {
    return res.status(401).json({ error: "Session expired" });
  }

  const mfaConfig = await userMfa.findByUserId(pending.user_id);
  const isValid = verifyTotpCode(mfaConfig.totp_secret_encrypted, code);

  await mfaAttempts.log({
    userId: pending.user_id,
    attemptType: "totp",
    success: isValid,
    ipAddress: req.ip,
  });

  if (!isValid) {
    return res.status(401).json({ error: "Invalid code" });
  }

  // Complete login
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await sessions.create(pending.user_id, sessionToken, sessionExpiresAt);
  await pendingMfaSessions.delete(pending.id);
  await users.updateMfaLastVerified(pending.user_id);

  const user = await users.findById(pending.user_id);

  res.json({
    success: true,
    sessionToken,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// Verify backup code during login
router.post("/verify/backup-code", mfaVerifyLimiter, async (req, res) => {
  const { pendingToken, code } = req.body;

  const pending = await pendingMfaSessions.findByToken(pendingToken);
  if (!pending || pending.expires_at < new Date()) {
    return res.status(401).json({ error: "Session expired" });
  }

  const backupCodes = await mfaBackupCodes.getUnused(pending.user_id);
  let matchedCode = null;

  for (const bc of backupCodes) {
    if (await verifyBackupCode(code, bc.code_hash)) {
      matchedCode = bc;
      break;
    }
  }

  if (!matchedCode) {
    return res.status(401).json({ error: "Invalid backup code" });
  }

  await mfaBackupCodes.markUsed(matchedCode.id);

  // Complete login (same as TOTP)
  const sessionToken = crypto.randomBytes(32).toString("hex");
  const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await sessions.create(pending.user_id, sessionToken, sessionExpiresAt);
  await pendingMfaSessions.delete(pending.id);

  const remainingCodes = backupCodes.length - 1;

  res.json({
    success: true,
    sessionToken,
    backupCodesRemaining: remainingCodes,
    warning: remainingCodes < 3 ? "Low on backup codes" : null,
  });
});

export default router;
```

---

### Phase 5: Modified Magic Link Flow

Update `routes/auth.js` `/verify` endpoint:

```javascript
router.get("/verify", strictAuthLimiter, async (req, res) => {
  const { token } = req.query;

  const result = await verifyMagicLink(token, req.ip);
  if (!result.success) {
    return res.status(400).json({ error: result.error });
  }

  // Check if MFA is required
  const mfaConfig = await userMfa.findByUserId(result.user.id);
  const mfaRequired = mfaConfig?.totp_enabled || result.user.mfa_required;

  if (mfaRequired) {
    // Create pending MFA session
    const pendingToken = crypto.randomBytes(32).toString("hex");
    await pendingMfaSessions.create({
      userId: result.user.id,
      sessionToken: pendingToken,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    });

    return res.json({
      success: true,
      mfaRequired: true,
      pendingToken,
      methods: { totp: mfaConfig?.totp_enabled || false },
    });
  }

  // No MFA - continue with normal session
  // ... existing code ...
});
```

---

### Phase 6: Frontend Components

#### MFA Setup Wizard (`user-ui/src/pages/mfa-setup.ts`)

Steps:

1. **Intro** - Explain MFA benefits
2. **QR Code** - Display QR and manual secret
3. **Verify** - Enter 6-digit code
4. **Backup Codes** - Display and download codes
5. **Done** - Confirmation

#### MFA Verification (`user-ui/src/pages/mfa-verify.ts`)

- Tab interface: Authenticator | Backup Code
- 6-digit code input with auto-advance
- Backup code input with formatting

#### API Client Methods

```typescript
// Add to user-ui/src/lib/api.ts
async getMfaStatus(): Promise<MfaStatus>;
async mfaTotpSetup(): Promise<{ qrCode: string; secret: string }>;
async mfaTotpVerify(code: string): Promise<{ success: boolean; backupCodes: string[] }>;
async mfaTotpDisable(code: string): Promise<{ success: boolean }>;
async mfaVerifyTotp(pendingToken: string, code: string): Promise<LoginResult>;
async mfaVerifyBackupCode(pendingToken: string, code: string): Promise<LoginResult>;
async mfaRegenerateBackupCodes(code: string): Promise<{ backupCodes: string[] }>;
```

---

### Phase 7: WebAuthn (Optional)

The existing `deviceKeys` table has WebAuthn fields. Implementation uses `@simplewebauthn/server`:

- `/webauthn/register/begin` - Generate registration options
- `/webauthn/register/complete` - Verify and store credential
- `/webauthn/authenticate/begin` - Generate authentication options
- `/webauthn/authenticate/complete` - Verify and complete login

---

## Security Considerations

### Timing Attack Prevention

- Use `crypto.timingSafeEqual()` for all code comparisons

### Brute Force Protection

- 5 MFA attempts per 15 minutes
- Account lockout after 10 failed attempts
- All attempts logged

### Secret Storage

- TOTP secrets encrypted with AES-256-GCM
- Backup codes hashed with Argon2id
- WebAuthn credentials stored with counter

### Session Security

- Pending MFA sessions expire in 5 minutes
- Cannot reuse magic link after MFA
- Session invalidated if MFA disabled

---

## MFA Enforcement Options

1. **User-Level** - Admin can require MFA for specific users
2. **Org-Level** - Org setting to require MFA for all members
3. **Global** - Environment variable `MFA_REQUIRED_GLOBAL=true`

---

## Dependencies

```json
{
  "dependencies": {
    "otpauth": "^9.2.0",
    "qrcode": "^1.5.3",
    "@simplewebauthn/server": "^9.0.0"
  }
}
```

---

## Files to Modify

| File                     | Changes                        |
| ------------------------ | ------------------------------ |
| `db/migrate.js`          | Add MFA tables                 |
| `db/index.js`            | Add MFA database operations    |
| `routes/auth.js`         | Add MFA check after magic link |
| `user-ui/src/lib/api.ts` | Add MFA API methods            |
| `server.js`              | Register MFA routes            |

## Files to Create

| File                              | Purpose                       |
| --------------------------------- | ----------------------------- |
| `lib/totp.js`                     | TOTP generation/verification  |
| `lib/backup-codes.js`             | Backup code generation        |
| `routes/mfa.js`                   | MFA API endpoints             |
| `routes/webauthn.js`              | WebAuthn endpoints (optional) |
| `user-ui/src/pages/mfa-setup.ts`  | Setup wizard                  |
| `user-ui/src/pages/mfa-verify.ts` | Login verification            |

---

## Testing

### Unit Tests

- TOTP generation/verification
- Backup code generation/verification
- Timing attack resistance

### Integration Tests

- Full MFA setup flow
- Login with MFA
- Backup code usage
- Rate limiting

### Security Review

- Code timing analysis
- Rate limit effectiveness
- Session handling

---

## Rollout Plan

1. Database migration (feature flag disabled)
2. Backend implementation
3. Frontend components
4. Testing
5. Beta rollout (opt-in)
6. General availability
7. Optional enforcement

---

## Priority

**High** - Critical for enterprise security requirements.

## Estimated Effort

- Phase 1-3 (Backend): 3-4 days
- Phase 4-5 (Routes + Auth flow): 2 days
- Phase 6 (Frontend): 3 days
- Phase 7 (WebAuthn): 2 days (optional)
- Testing: 2 days

**Total: ~10-12 days** (without WebAuthn: ~8 days)
