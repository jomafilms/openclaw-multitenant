# Security Plan 11: Encryption Key Versioning & Rotation

## Overview

**Problem**: The current encryption implementation doesn't support key rotation:

- Single `ENCRYPTION_KEY` environment variable
- No version tracking on encrypted data
- Rotating a key would break all existing encrypted secrets
- Compromised keys require re-encryption with downtime

**Solution**:

1. Add version prefix to encrypted data format
2. Support multiple keys (current + previous)
3. Migration script for re-encryption
4. Graceful rollout without downtime

---

## Current State

**Format**: `iv:authTag:encryptedData` (base64)

**Code in `db/index.js`:**

```javascript
const ENCRYPTION_KEY = Buffer.from(process.env.ENCRYPTION_KEY, "hex");

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENCRYPTION_KEY, iv);
  // ...
}
```

---

## New Format

**Format**: `v{version}:{iv}:{authTag}:{encryptedData}`

Examples:

- `v0:abc123:def456:encryptedstuff` - Legacy/initial key
- `v1:abc123:def456:encryptedstuff` - First rotated key
- `v2:abc123:def456:encryptedstuff` - Second rotated key

Backward compatibility:

- Data without `v` prefix is treated as `v0`

---

## Implementation

### 1. Updated Encryption Module

**Update `management-server/db/index.js`:**

```javascript
import crypto from "crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

/**
 * Load encryption keys from environment
 * Supports multiple versions for rotation
 */
function loadEncryptionKeys() {
  const keys = new Map();

  // Current key (required)
  const currentKey = process.env.ENCRYPTION_KEY;
  if (!currentKey) {
    throw new Error("ENCRYPTION_KEY environment variable is required");
  }

  // Determine current version
  const currentVersion = parseInt(process.env.ENCRYPTION_KEY_VERSION || "0", 10);
  keys.set(currentVersion, Buffer.from(currentKey, "hex"));

  // Load previous keys for decryption (optional)
  // ENCRYPTION_KEY_V0, ENCRYPTION_KEY_V1, etc.
  for (let v = 0; v < currentVersion; v++) {
    const envVar = `ENCRYPTION_KEY_V${v}`;
    const key = process.env[envVar];
    if (key) {
      keys.set(v, Buffer.from(key, "hex"));
    }
  }

  return { keys, currentVersion };
}

const { keys: ENCRYPTION_KEYS, currentVersion: CURRENT_VERSION } = loadEncryptionKeys();

/**
 * Encrypt data with current key version
 */
export function encrypt(text) {
  if (!text) return null;

  const key = ENCRYPTION_KEYS.get(CURRENT_VERSION);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");

  const authTag = cipher.getAuthTag().toString("base64");

  // New versioned format
  return `v${CURRENT_VERSION}:${iv.toString("base64")}:${authTag}:${encrypted}`;
}

/**
 * Decrypt data, supporting multiple key versions
 */
export function decrypt(encryptedText) {
  if (!encryptedText) return null;

  let version, iv, authTag, encrypted;

  // Parse format - check for version prefix
  if (encryptedText.startsWith("v")) {
    // New versioned format: v{version}:{iv}:{authTag}:{encrypted}
    const parts = encryptedText.split(":");
    if (parts.length !== 4) {
      throw new Error("Invalid encrypted data format");
    }

    version = parseInt(parts[0].substring(1), 10);
    iv = Buffer.from(parts[1], "base64");
    authTag = Buffer.from(parts[2], "base64");
    encrypted = parts[3];
  } else {
    // Legacy format: {iv}:{authTag}:{encrypted} (no version = v0)
    const parts = encryptedText.split(":");
    if (parts.length !== 3) {
      throw new Error("Invalid encrypted data format");
    }

    version = 0;
    iv = Buffer.from(parts[0], "base64");
    authTag = Buffer.from(parts[1], "base64");
    encrypted = parts[2];
  }

  // Get key for this version
  const key = ENCRYPTION_KEYS.get(version);
  if (!key) {
    throw new Error(`Encryption key version ${version} not available`);
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encrypted, "base64", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

/**
 * Check if data needs re-encryption (old version)
 */
export function needsReEncryption(encryptedText) {
  if (!encryptedText) return false;

  if (encryptedText.startsWith("v")) {
    const version = parseInt(encryptedText.split(":")[0].substring(1), 10);
    return version < CURRENT_VERSION;
  }

  // Legacy format always needs re-encryption
  return CURRENT_VERSION > 0;
}

/**
 * Re-encrypt data with current key
 */
export function reEncrypt(encryptedText) {
  const decrypted = decrypt(encryptedText);
  return encrypt(decrypted);
}

/**
 * Get encryption key version from encrypted data
 */
export function getKeyVersion(encryptedText) {
  if (!encryptedText) return null;

  if (encryptedText.startsWith("v")) {
    return parseInt(encryptedText.split(":")[0].substring(1), 10);
  }

  return 0; // Legacy format
}
```

### 2. Database Migration Tracking

**Add to `management-server/db/migrate.js`:**

```sql
CREATE TABLE IF NOT EXISTS encryption_migrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  table_name VARCHAR(100) NOT NULL,
  column_name VARCHAR(100) NOT NULL,
  from_version INTEGER NOT NULL,
  to_version INTEGER NOT NULL,
  rows_migrated INTEGER NOT NULL,
  started_at TIMESTAMP NOT NULL,
  completed_at TIMESTAMP,
  status VARCHAR(20) DEFAULT 'running'
);

CREATE INDEX IF NOT EXISTS idx_encryption_migrations_status
  ON encryption_migrations(status);
```

### 3. Key Rotation Script

**Create `management-server/scripts/rotate-encryption-key.js`:**

```javascript
#!/usr/bin/env node
/**
 * Encryption Key Rotation Script
 *
 * Usage:
 *   node scripts/rotate-encryption-key.js --check     # Show what needs migration
 *   node scripts/rotate-encryption-key.js --migrate   # Perform migration
 *   node scripts/rotate-encryption-key.js --generate  # Generate new key
 *
 * Before running:
 *   1. Generate new key: node scripts/rotate-encryption-key.js --generate
 *   2. Set ENCRYPTION_KEY=<new-key>
 *   3. Set ENCRYPTION_KEY_V{old}=<old-key>
 *   4. Set ENCRYPTION_KEY_VERSION=<new-version>
 *   5. Deploy with new env vars
 *   6. Run: node scripts/rotate-encryption-key.js --migrate
 */

import crypto from "crypto";
import { query } from "../db/index.js";
import { decrypt, encrypt, needsReEncryption, getKeyVersion } from "../db/encryption.js";
import dotenv from "dotenv";

dotenv.config();

// Tables and columns that contain encrypted data
const ENCRYPTED_COLUMNS = [
  { table: "org_secrets", column: "encrypted_value" },
  { table: "user_mfa", column: "totp_secret" },
  { table: "user_api_keys", column: "encrypted_key" },
  // Add other encrypted columns here
];

async function generateNewKey() {
  const key = crypto.randomBytes(32).toString("hex");
  console.log("\nNew encryption key generated:");
  console.log("━".repeat(64));
  console.log(key);
  console.log("━".repeat(64));
  console.log("\nStore this securely and add to environment:");
  console.log("  ENCRYPTION_KEY=<this-new-key>");
  console.log("  ENCRYPTION_KEY_V<old>=<your-current-key>");
  console.log("  ENCRYPTION_KEY_VERSION=<incremented-version>");
}

async function checkMigration() {
  console.log("\nEncryption Migration Status");
  console.log("═".repeat(60));

  let totalNeedsMigration = 0;

  for (const { table, column } of ENCRYPTED_COLUMNS) {
    try {
      const result = await query(`SELECT id, ${column} FROM ${table} WHERE ${column} IS NOT NULL`);

      let needsMigration = 0;
      const versionCounts = new Map();

      for (const row of result.rows) {
        const version = getKeyVersion(row[column]);
        versionCounts.set(version, (versionCounts.get(version) || 0) + 1);

        if (needsReEncryption(row[column])) {
          needsMigration++;
        }
      }

      console.log(`\n${table}.${column}:`);
      console.log(`  Total rows: ${result.rows.length}`);
      console.log(`  Needs migration: ${needsMigration}`);
      console.log(`  Version distribution:`);
      for (const [v, count] of versionCounts) {
        console.log(`    v${v}: ${count} rows`);
      }

      totalNeedsMigration += needsMigration;
    } catch (err) {
      console.log(`\n${table}.${column}: Error - ${err.message}`);
    }
  }

  console.log("\n" + "═".repeat(60));
  console.log(`Total rows needing migration: ${totalNeedsMigration}`);

  if (totalNeedsMigration === 0) {
    console.log("✓ All data is encrypted with the current key version");
  } else {
    console.log("Run with --migrate to re-encrypt data");
  }
}

async function runMigration() {
  console.log("\nStarting Encryption Key Migration");
  console.log("═".repeat(60));

  const currentVersion = parseInt(process.env.ENCRYPTION_KEY_VERSION || "0", 10);

  for (const { table, column } of ENCRYPTED_COLUMNS) {
    console.log(`\nMigrating ${table}.${column}...`);

    const startTime = Date.now();
    let migrated = 0;
    let failed = 0;

    // Record migration start
    const migrationResult = await query(
      `INSERT INTO encryption_migrations
       (table_name, column_name, from_version, to_version, rows_migrated, started_at, status)
       VALUES ($1, $2, $3, $4, 0, NOW(), 'running')
       RETURNING id`,
      [table, column, currentVersion - 1, currentVersion],
    );
    const migrationId = migrationResult.rows[0].id;

    try {
      // Fetch rows needing migration
      const result = await query(`SELECT id, ${column} FROM ${table} WHERE ${column} IS NOT NULL`);

      for (const row of result.rows) {
        if (!needsReEncryption(row[column])) {
          continue;
        }

        try {
          // Re-encrypt with current key
          const newValue = encrypt(decrypt(row[column]));

          await query(`UPDATE ${table} SET ${column} = $1 WHERE id = $2`, [newValue, row.id]);

          migrated++;

          // Progress indicator
          if (migrated % 100 === 0) {
            process.stdout.write(`  Migrated ${migrated} rows...\r`);
          }
        } catch (err) {
          console.error(`  Failed to migrate row ${row.id}: ${err.message}`);
          failed++;
        }
      }

      // Update migration record
      await query(
        `UPDATE encryption_migrations
         SET rows_migrated = $1, completed_at = NOW(), status = $2
         WHERE id = $3`,
        [migrated, failed > 0 ? "partial" : "completed", migrationId],
      );

      const duration = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`  Completed: ${migrated} migrated, ${failed} failed (${duration}s)`);
    } catch (err) {
      await query(`UPDATE encryption_migrations SET status = 'failed' WHERE id = $1`, [
        migrationId,
      ]);
      console.error(`  Migration failed: ${err.message}`);
    }
  }

  console.log("\n" + "═".repeat(60));
  console.log("Migration complete. Run --check to verify.");
}

// Main
const args = process.argv.slice(2);

if (args.includes("--generate")) {
  generateNewKey();
} else if (args.includes("--check")) {
  checkMigration()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
} else if (args.includes("--migrate")) {
  runMigration()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
} else {
  console.log("Usage:");
  console.log("  node rotate-encryption-key.js --generate  # Generate new key");
  console.log("  node rotate-encryption-key.js --check     # Check migration status");
  console.log("  node rotate-encryption-key.js --migrate   # Perform migration");
}
```

### 4. Background Re-encryption Job

For large datasets, run re-encryption in batches:

```javascript
// In lib/encryption-worker.js
export async function reEncryptBatch(table, column, batchSize = 100) {
  const result = await query(
    `SELECT id, ${column} FROM ${table}
     WHERE ${column} IS NOT NULL
     AND (${column} NOT LIKE 'v%' OR ${column} LIKE 'v0:%' OR ${column} LIKE 'v1:%')
     LIMIT $1`,
    [batchSize],
  );

  if (result.rows.length === 0) {
    return { done: true, migrated: 0 };
  }

  let migrated = 0;
  for (const row of result.rows) {
    if (needsReEncryption(row[column])) {
      const newValue = encrypt(decrypt(row[column]));
      await query(`UPDATE ${table} SET ${column} = $1 WHERE id = $2`, [newValue, row.id]);
      migrated++;
    }
  }

  return { done: false, migrated };
}
```

---

## Environment Variables

```bash
# Current key (always required)
ENCRYPTION_KEY=<64-char-hex-key>

# Current version number
ENCRYPTION_KEY_VERSION=1

# Previous keys (for decryption during migration)
ENCRYPTION_KEY_V0=<old-key-hex>
# ENCRYPTION_KEY_V1=<another-old-key>  # If rotating again
```

---

## Rotation Procedure

### Step 1: Generate New Key

```bash
node scripts/rotate-encryption-key.js --generate
# Save the output securely
```

### Step 2: Update Environment

```bash
# Move current key to versioned variable
export ENCRYPTION_KEY_V0=$ENCRYPTION_KEY

# Set new key
export ENCRYPTION_KEY=<new-64-char-hex>

# Increment version
export ENCRYPTION_KEY_VERSION=1
```

### Step 3: Deploy

Deploy application with new environment variables. The app can now:

- Decrypt old data (v0) using `ENCRYPTION_KEY_V0`
- Encrypt new data (v1) using `ENCRYPTION_KEY`

### Step 4: Migrate Data

```bash
# Check what needs migration
node scripts/rotate-encryption-key.js --check

# Run migration
node scripts/rotate-encryption-key.js --migrate

# Verify
node scripts/rotate-encryption-key.js --check
```

### Step 5: Remove Old Key

After verifying all data is migrated:

```bash
unset ENCRYPTION_KEY_V0
```

---

## Files to Create

| File                               | Purpose                        |
| ---------------------------------- | ------------------------------ |
| `scripts/rotate-encryption-key.js` | Key rotation CLI tool          |
| `lib/encryption-worker.js`         | Background batch re-encryption |

## Files to Modify

| File            | Changes                                 |
| --------------- | --------------------------------------- |
| `db/index.js`   | Updated encrypt/decrypt with versioning |
| `db/migrate.js` | Add encryption_migrations table         |

---

## Testing

```bash
# Generate test keys
KEY1=$(openssl rand -hex 32)
KEY2=$(openssl rand -hex 32)

# Test encryption with version
ENCRYPTION_KEY=$KEY1 ENCRYPTION_KEY_VERSION=0 node -e "
const { encrypt, decrypt, getKeyVersion } = require('./db/index.js');
const encrypted = encrypt('secret data');
console.log('Encrypted:', encrypted);
console.log('Version:', getKeyVersion(encrypted));
console.log('Decrypted:', decrypt(encrypted));
"

# Test migration
ENCRYPTION_KEY=$KEY2 ENCRYPTION_KEY_V0=$KEY1 ENCRYPTION_KEY_VERSION=1 \
  node scripts/rotate-encryption-key.js --check
```

---

## Priority

**HIGH** - Key rotation is essential for:

- Responding to potential key compromise
- Regular security hygiene (annual rotation)
- Compliance requirements (PCI-DSS, SOC2)

## Estimated Effort

- Encryption module update: 2 hours
- Rotation script: 3 hours
- Testing: 2 hours
- Documentation: 1 hour

**Total: ~8 hours**
