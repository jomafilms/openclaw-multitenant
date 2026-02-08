// Core database utilities - pool, query helper, encryption
import dotenv from "dotenv";
import pg from "pg";
// Import versioned encryption from lib/encryption.js
// Supports key versioning for seamless rotation
import {
  encrypt as versionedEncrypt,
  decrypt as versionedDecrypt,
  getKeyVersion,
  needsReEncryption,
  reEncrypt,
} from "../lib/encryption.js";

dotenv.config();

// Re-export encryption functions with versioning support
// These are backward compatible - they can decrypt both legacy and versioned formats
export const encrypt = versionedEncrypt;
export const decrypt = versionedDecrypt;

// Export additional encryption utilities for key rotation
export { getKeyVersion, needsReEncryption, reEncrypt };

const { Pool } = pg;

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://localhost:5432/ocmt",
});

// Helper for queries
export async function query(text, params) {
  const start = Date.now();
  const res = await pool.query(text, params);
  const duration = Date.now() - start;
  if (process.env.NODE_ENV !== "production") {
    console.log("Query:", { text: text.slice(0, 50), duration, rows: res.rowCount });
  }
  return res;
}

export default pool;
