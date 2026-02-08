// User operations
import { query } from "./core.js";

export const users = {
  async create({ name, email, passwordHash, gatewayToken, telegramBotToken, telegramBotUsername }) {
    const res = await query(
      `INSERT INTO users (name, email, password_hash, gateway_token, telegram_bot_token, telegram_bot_username)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [name, email, passwordHash, gatewayToken, telegramBotToken, telegramBotUsername],
    );
    return res.rows[0];
  },

  async findById(id) {
    const res = await query("SELECT * FROM users WHERE id = $1", [id]);
    return res.rows[0];
  },

  async findByEmail(email) {
    const res = await query("SELECT * FROM users WHERE email = $1", [email]);
    return res.rows[0];
  },

  async findByTelegramChatId(chatId) {
    const res = await query("SELECT * FROM users WHERE telegram_chat_id = $1", [chatId]);
    return res.rows[0];
  },

  async updateContainer(userId, { containerId, containerPort }) {
    const res = await query(
      `UPDATE users SET container_id = $2, container_port = $3, status = 'active', updated_at = NOW()
       WHERE id = $1 RETURNING *`,
      [userId, containerId, containerPort],
    );
    return res.rows[0];
  },

  async updateTelegramChatId(userId, chatId) {
    const res = await query(
      `UPDATE users SET telegram_chat_id = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [userId, chatId],
    );
    return res.rows[0];
  },

  async updateStatus(userId, status) {
    const res = await query(
      `UPDATE users SET status = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [userId, status],
    );
    return res.rows[0];
  },

  async updateGatewayToken(userId, gatewayToken) {
    const res = await query(
      `UPDATE users SET gateway_token = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [userId, gatewayToken],
    );
    return res.rows[0];
  },

  async list() {
    const res = await query("SELECT * FROM users ORDER BY created_at DESC");
    return res.rows;
  },

  async count() {
    const res = await query("SELECT COUNT(*) FROM users");
    return parseInt(res.rows[0].count, 10);
  },

  // Vault operations
  async setVault(userId, vault) {
    const res = await query(
      `UPDATE users
       SET vault = $1, vault_created_at = NOW(), updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [JSON.stringify(vault), userId],
    );
    return res.rows[0];
  },

  async getVault(userId) {
    const res = await query("SELECT vault FROM users WHERE id = $1", [userId]);
    return res.rows[0]?.vault;
  },

  async hasVault(userId) {
    const res = await query("SELECT vault IS NOT NULL as has_vault FROM users WHERE id = $1", [
      userId,
    ]);
    return res.rows[0]?.has_vault || false;
  },

  async updateVault(userId, vault) {
    const res = await query(
      `UPDATE users
       SET vault = $1, updated_at = NOW()
       WHERE id = $2
       RETURNING *`,
      [JSON.stringify(vault), userId],
    );
    return res.rows[0];
  },

  // Biometrics settings
  async setBiometricsEnabled(userId, enabled) {
    const res = await query(
      `UPDATE users
       SET biometrics_enabled = $2,
           biometrics_last_password_at = CASE WHEN $2 = true THEN NOW() ELSE biometrics_last_password_at END,
           updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [userId, enabled],
    );
    return res.rows[0];
  },

  async updateBiometricsLastPassword(userId) {
    const res = await query(
      `UPDATE users
       SET biometrics_last_password_at = NOW(), updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [userId],
    );
    return res.rows[0];
  },

  async getBiometricsStatus(userId) {
    const res = await query(
      `SELECT biometrics_enabled, biometrics_last_password_at, biometrics_max_age_days
       FROM users WHERE id = $1`,
      [userId],
    );
    return res.rows[0];
  },

  // User settings (stored in JSONB settings column)
  async getSettings(userId) {
    const res = await query("SELECT settings FROM users WHERE id = $1", [userId]);
    return res.rows[0]?.settings || {};
  },

  async updateSettings(userId, updates) {
    // Merge updates into existing settings
    const res = await query(
      `UPDATE users
       SET settings = COALESCE(settings, '{}'::jsonb) || $2::jsonb,
           updated_at = NOW()
       WHERE id = $1
       RETURNING settings`,
      [userId, JSON.stringify(updates)],
    );
    return res.rows[0]?.settings || {};
  },

  async getSetting(userId, key) {
    const res = await query(`SELECT settings->$2 as value FROM users WHERE id = $1`, [userId, key]);
    return res.rows[0]?.value;
  },

  async setSetting(userId, key, value) {
    const res = await query(
      `UPDATE users
       SET settings = COALESCE(settings, '{}'::jsonb) || jsonb_build_object($2::text, $3::jsonb),
           updated_at = NOW()
       WHERE id = $1
       RETURNING settings`,
      [userId, key, JSON.stringify(value)],
    );
    return res.rows[0]?.settings || {};
  },

  // MFA operations
  async updateMfaLastVerified(userId) {
    const res = await query(
      `UPDATE users SET mfa_last_verified_at = NOW(), updated_at = NOW() WHERE id = $1 RETURNING *`,
      [userId],
    );
    return res.rows[0];
  },

  async setMfaRequired(userId, required) {
    const res = await query(
      `UPDATE users SET mfa_required = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [userId, required],
    );
    return res.rows[0];
  },

  // Container vault operations (encrypted blob storage)
  // The container pushes its encrypted vault here for persistence
  // We never decrypt it - just store the blob
  async setContainerVault(userId, containerVault) {
    // Store in settings.containerVault to avoid requiring a migration
    const res = await query(
      `UPDATE users
       SET settings = COALESCE(settings, '{}'::jsonb) || jsonb_build_object('containerVault', $2::jsonb),
           updated_at = NOW()
       WHERE id = $1
       RETURNING settings->'containerVault' as container_vault`,
      [userId, JSON.stringify(containerVault)],
    );
    return res.rows[0]?.container_vault;
  },

  async getContainerVault(userId) {
    const res = await query(
      `SELECT settings->'containerVault' as container_vault FROM users WHERE id = $1`,
      [userId],
    );
    return res.rows[0]?.container_vault;
  },
};
