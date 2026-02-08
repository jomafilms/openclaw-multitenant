// Internal API routes for agent server
import crypto from 'crypto';
import { Router } from 'express';
import { users, audit, integrations, decrypt } from '../db/index.js';
import { unlockVault } from '../lib/vault.js';
import { vaultSessions } from '../lib/vault-sessions.js';
import { getEffectiveApiKey } from '../lib/api-keys.js';
import { getWakeOnRequestMetrics } from '../lib/wake-on-request.js';
import { AGENT_SERVER_TOKEN } from '../lib/context.js';

const router = Router();

// Middleware to check agent server token - timing-safe comparison
function requireAgentServerAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = auth.slice(7);
  const tokenBuf = Buffer.from(token);
  const expectedBuf = Buffer.from(AGENT_SERVER_TOKEN);
  if (tokenBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(tokenBuf, expectedBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// Get user by ID (for agent server to fetch config)
router.get('/users/:id', requireAgentServerAuth, async (req, res) => {
  const user = await users.findById(req.params.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});

// Update container status
router.post('/users/:id/container', requireAgentServerAuth, async (req, res) => {
  const { container_id, container_port } = req.body;
  const user = await users.updateContainer(req.params.id, {
    containerId: container_id,
    containerPort: container_port
  });
  await audit.log(req.params.id, 'container_started', { container_id, container_port }, req.ip);
  res.json(user);
});

// Lookup user by Telegram chat ID (for routing)
router.get('/telegram/lookup/:chatId', requireAgentServerAuth, async (req, res) => {
  const user = await users.findByTelegramChatId(req.params.chatId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user);
});

// Register Telegram chat ID for user
router.post('/telegram/register', requireAgentServerAuth, async (req, res) => {
  const { user_id, chat_id } = req.body;
  const user = await users.updateTelegramChatId(user_id, chat_id);
  await audit.log(user_id, 'telegram_connected', { chat_id }, req.ip);
  res.json(user);
});

// Check vault status for a user
router.get('/vault/status/:userId', requireAgentServerAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const vaultSessionToken = req.headers['x-vault-session'];

    const hasVault = await users.hasVault(userId);

    let isUnlocked = false;
    let expiresIn = 0;

    if (vaultSessionToken && vaultSessions.has(vaultSessionToken)) {
      const session = vaultSessions.get(vaultSessionToken);
      if (session.userId === userId && session.expiresAt > Date.now()) {
        isUnlocked = true;
        expiresIn = Math.floor((session.expiresAt - Date.now()) / 1000);
      }
    }

    res.json({
      hasVault,
      isUnlocked,
      expiresIn
    });
  } catch (err) {
    console.error('Internal vault status error:', err);
    res.status(500).json({ error: 'Failed to get vault status' });
  }
});

// Get vault credentials for a specific user
router.post('/vault/credentials/:userId', requireAgentServerAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { password, vaultSessionToken } = req.body;

    // Verify vault session is valid
    if (!vaultSessionToken || !vaultSessions.has(vaultSessionToken)) {
      return res.status(401).json({ error: 'Vault is locked', code: 'VAULT_LOCKED' });
    }

    const session = vaultSessions.get(vaultSessionToken);
    if (session.userId !== userId || session.expiresAt < Date.now()) {
      return res.status(401).json({ error: 'Vault session invalid or expired', code: 'VAULT_SESSION_INVALID' });
    }

    const vault = await users.getVault(userId);
    if (!vault) {
      return res.status(400).json({ error: 'No vault found' });
    }

    if (password) {
      const data = await unlockVault(vault, password);
      await audit.log(userId, 'vault.container_credentials_accessed', null, req.ip);

      return res.json({
        success: true,
        credentials: data.credentials || []
      });
    }

    res.json({
      success: true,
      isUnlocked: true,
      message: 'Vault unlocked. Provide password to retrieve credentials.'
    });
  } catch (err) {
    if (err.message === 'Invalid password') {
      return res.status(401).json({ error: 'Invalid password' });
    }
    console.error('Internal vault credentials error:', err);
    res.status(500).json({ error: 'Failed to get credentials' });
  }
});

// Get credentials for agent server
router.get('/credentials/:userId', requireAgentServerAuth, async (req, res) => {
  try {
    const { userId } = req.params;
    const { provider } = req.query;

    if (provider) {
      const result = await getEffectiveApiKey(userId, provider);
      if (!result) {
        return res.status(404).json({ error: `No ${provider} key available` });
      }
      return res.json({ provider, ...result });
    }

    // Get all available credentials
    const credentials = {};

    const anthropic = await getEffectiveApiKey(userId, 'anthropic');
    if (anthropic) credentials.anthropic = anthropic;

    const openai = await getEffectiveApiKey(userId, 'openai');
    if (openai) credentials.openai = openai;

    // Get user's OAuth tokens (these are always user-specific)
    const userIntegrations = await integrations.listForUser(userId);
    for (const int of userIntegrations) {
      if (int.integration_type === 'oauth' && int.access_token_encrypted) {
        credentials[int.provider] = {
          accessToken: decrypt(int.access_token_encrypted),
          refreshToken: int.refresh_token_encrypted ? decrypt(int.refresh_token_encrypted) : null,
          expiresAt: int.token_expires_at,
          source: 'user'
        };
      }
    }

    res.json({ credentials });
  } catch (err) {
    console.error('Get credentials error:', err);
    res.status(500).json({ error: 'Failed to get credentials' });
  }
});

// Get wake-on-request metrics
router.get('/metrics/wake', requireAgentServerAuth, async (req, res) => {
  try {
    const metrics = getWakeOnRequestMetrics();
    res.json(metrics);
  } catch (err) {
    console.error('Get wake metrics error:', err);
    res.status(500).json({ error: 'Failed to get wake metrics' });
  }
});

export default router;
