import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt",
});

const migrations = [
  // Relay messages table - stores encrypted message blobs
  // The relay CANNOT read content - it only stores and routes encrypted payloads
  `CREATE TABLE IF NOT EXISTS relay_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_container_id UUID NOT NULL,
    to_container_id UUID NOT NULL,
    payload_encrypted TEXT NOT NULL,
    payload_size INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    delivered_at TIMESTAMP,
    expired_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'pending'
  )`,

  // Rate limits per container - sliding window rate limiting
  `CREATE TABLE IF NOT EXISTS relay_rate_limits (
    container_id UUID PRIMARY KEY,
    window_start TIMESTAMP NOT NULL,
    message_count INTEGER DEFAULT 0
  )`,

  // Relay audit log - who talked to whom, when (NOT content)
  `CREATE TABLE IF NOT EXISTS relay_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    from_container_id UUID NOT NULL,
    to_container_id UUID NOT NULL,
    payload_size INTEGER NOT NULL,
    status VARCHAR(20) NOT NULL,
    error_message TEXT
  )`,

  // Indexes for efficient queries
  `CREATE INDEX IF NOT EXISTS idx_relay_messages_to ON relay_messages(to_container_id)`,
  `CREATE INDEX IF NOT EXISTS idx_relay_messages_status ON relay_messages(status)`,
  `CREATE INDEX IF NOT EXISTS idx_relay_messages_created ON relay_messages(created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_relay_messages_pending ON relay_messages(to_container_id, status) WHERE status = 'pending'`,
  `CREATE INDEX IF NOT EXISTS idx_relay_audit_from ON relay_audit_log(from_container_id)`,
  `CREATE INDEX IF NOT EXISTS idx_relay_audit_to ON relay_audit_log(to_container_id)`,
  `CREATE INDEX IF NOT EXISTS idx_relay_audit_timestamp ON relay_audit_log(timestamp)`,

  // Cached snapshots table for CACHED tier sharing
  // Stores encrypted snapshots for offline access
  `CREATE TABLE IF NOT EXISTS relay_cached_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    capability_id VARCHAR(256) UNIQUE NOT NULL,
    recipient_public_key VARCHAR(64) NOT NULL,
    issuer_public_key VARCHAR(64) NOT NULL,
    encrypted_data TEXT NOT NULL,
    ephemeral_public_key VARCHAR(64) NOT NULL,
    nonce VARCHAR(32) NOT NULL,
    tag VARCHAR(32) NOT NULL,
    signature VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL
  )`,

  // Indexes for snapshots
  `CREATE INDEX IF NOT EXISTS idx_snapshots_capability ON relay_cached_snapshots(capability_id)`,
  `CREATE INDEX IF NOT EXISTS idx_snapshots_recipient ON relay_cached_snapshots(recipient_public_key)`,
  `CREATE INDEX IF NOT EXISTS idx_snapshots_expires ON relay_cached_snapshots(expires_at)`,
  `CREATE INDEX IF NOT EXISTS idx_snapshots_recipient_active ON relay_cached_snapshots(recipient_public_key, expires_at) WHERE expires_at > NOW()`,

  // Container registry - callback URLs and public keys for message forwarding
  `CREATE TABLE IF NOT EXISTS relay_container_registry (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    container_id UUID NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    public_key_hash VARCHAR(32) NOT NULL,
    encryption_public_key TEXT,
    callback_url TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
  )`,

  // Indexes for container registry
  `CREATE INDEX IF NOT EXISTS idx_registry_container ON relay_container_registry(container_id)`,
  `CREATE INDEX IF NOT EXISTS idx_registry_pubkey_hash ON relay_container_registry(public_key_hash)`,
  `CREATE INDEX IF NOT EXISTS idx_registry_updated ON relay_container_registry(updated_at)`,
];

async function migrate() {
  console.log("Running relay-server migrations...");

  for (const sql of migrations) {
    try {
      await pool.query(sql);
      console.log("OK", sql.slice(0, 60) + "...");
    } catch (err) {
      console.error("FAIL Migration failed:", err.message);
      console.error("  SQL:", sql.slice(0, 100));
    }
  }

  console.log("Relay migrations complete.");
  await pool.end();
}

migrate().catch(console.error);
