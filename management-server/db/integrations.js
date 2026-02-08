// User integrations (OAuth and API keys)
import { query, encrypt, decrypt } from "./core.js";

export const integrations = {
  async create({
    userId,
    provider,
    integrationType,
    accessToken,
    refreshToken,
    tokenExpiresAt,
    apiKey,
    providerEmail,
    metadata,
  }) {
    const res = await query(
      `INSERT INTO user_integrations
       (user_id, provider, integration_type, access_token_encrypted, refresh_token_encrypted, token_expires_at, api_key_encrypted, provider_email, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (user_id, provider)
       DO UPDATE SET
         integration_type = $3,
         access_token_encrypted = $4,
         refresh_token_encrypted = $5,
         token_expires_at = $6,
         api_key_encrypted = $7,
         provider_email = COALESCE($8, user_integrations.provider_email),
         metadata = user_integrations.metadata || $9,
         updated_at = NOW(),
         status = 'active'
       RETURNING *`,
      [
        userId,
        provider,
        integrationType,
        accessToken ? encrypt(accessToken) : null,
        refreshToken ? encrypt(refreshToken) : null,
        tokenExpiresAt,
        apiKey ? encrypt(apiKey) : null,
        providerEmail,
        metadata ? JSON.stringify(metadata) : "{}",
      ],
    );
    return res.rows[0];
  },

  async findByUserAndProvider(userId, provider) {
    const res = await query(
      "SELECT * FROM user_integrations WHERE user_id = $1 AND provider = $2",
      [userId, provider],
    );
    return res.rows[0];
  },

  async listForUser(userId) {
    const res = await query(
      "SELECT id, provider, integration_type, provider_email, metadata, status, created_at, updated_at FROM user_integrations WHERE user_id = $1 ORDER BY created_at DESC",
      [userId],
    );
    return res.rows;
  },

  async delete(userId, provider) {
    await query("DELETE FROM user_integrations WHERE user_id = $1 AND provider = $2", [
      userId,
      provider,
    ]);
  },

  async getDecryptedTokens(userId, provider) {
    const res = await query(
      "SELECT * FROM user_integrations WHERE user_id = $1 AND provider = $2",
      [userId, provider],
    );
    if (!res.rows[0]) return null;
    const row = res.rows[0];
    return {
      ...row,
      accessToken: row.access_token_encrypted ? decrypt(row.access_token_encrypted) : null,
      refreshToken: row.refresh_token_encrypted ? decrypt(row.refresh_token_encrypted) : null,
      apiKey: row.api_key_encrypted ? decrypt(row.api_key_encrypted) : null,
    };
  },

  async updateTokens(userId, provider, { accessToken, refreshToken, tokenExpiresAt }) {
    const res = await query(
      `UPDATE user_integrations
       SET access_token_encrypted = $3, refresh_token_encrypted = $4, token_expires_at = $5, updated_at = NOW()
       WHERE user_id = $1 AND provider = $2
       RETURNING *`,
      [
        userId,
        provider,
        accessToken ? encrypt(accessToken) : null,
        refreshToken ? encrypt(refreshToken) : null,
        tokenExpiresAt,
      ],
    );
    return res.rows[0];
  },
};
