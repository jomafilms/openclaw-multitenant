// Device keys for biometric/WebAuthn authentication
import { query } from "./core.js";

export const deviceKeys = {
  async create({
    userId,
    deviceName,
    deviceFingerprint,
    encryptedDeviceKey,
    webauthnCredentialId,
    webauthnPublicKey,
  }) {
    const res = await query(
      `INSERT INTO device_keys (user_id, device_name, device_fingerprint, encrypted_device_key, webauthn_credential_id, webauthn_public_key)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (user_id, device_fingerprint)
       DO UPDATE SET
         encrypted_device_key = $4,
         webauthn_credential_id = COALESCE($5, device_keys.webauthn_credential_id),
         webauthn_public_key = COALESCE($6, device_keys.webauthn_public_key),
         last_used_at = NOW()
       RETURNING *`,
      [
        userId,
        deviceName,
        deviceFingerprint,
        encryptedDeviceKey,
        webauthnCredentialId,
        webauthnPublicKey,
      ],
    );
    return res.rows[0];
  },

  async findByUserAndFingerprint(userId, deviceFingerprint) {
    const res = await query(
      "SELECT * FROM device_keys WHERE user_id = $1 AND device_fingerprint = $2",
      [userId, deviceFingerprint],
    );
    return res.rows[0];
  },

  async findByCredentialId(credentialId) {
    const res = await query(
      "SELECT dk.*, u.* FROM device_keys dk JOIN users u ON dk.user_id = u.id WHERE dk.webauthn_credential_id = $1",
      [credentialId],
    );
    return res.rows[0];
  },

  async listForUser(userId) {
    const res = await query(
      `SELECT id, device_name, device_fingerprint, created_at, last_used_at,
              webauthn_credential_id IS NOT NULL as has_webauthn
       FROM device_keys
       WHERE user_id = $1
       ORDER BY last_used_at DESC NULLS LAST`,
      [userId],
    );
    return res.rows;
  },

  async updateLastUsed(id) {
    const res = await query(
      "UPDATE device_keys SET last_used_at = NOW() WHERE id = $1 RETURNING *",
      [id],
    );
    return res.rows[0];
  },

  async updateWebAuthnCounter(id, counter) {
    const res = await query(
      "UPDATE device_keys SET webauthn_counter = $2, last_used_at = NOW() WHERE id = $1 RETURNING *",
      [id, counter],
    );
    return res.rows[0];
  },

  async delete(id, userId) {
    await query("DELETE FROM device_keys WHERE id = $1 AND user_id = $2", [id, userId]);
  },

  async deleteAllForUser(userId) {
    await query("DELETE FROM device_keys WHERE user_id = $1", [userId]);
  },
};
