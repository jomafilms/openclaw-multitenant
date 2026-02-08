// Vault unlock token routes (for agent-generated magic links)
import { Router } from 'express';
import crypto from 'crypto';
import { users, audit } from '../db/index.js';
import { unlockVaultWithPasswordAndKey } from '../lib/vault.js';
import { vaultSessions, VAULT_SESSION_TIMEOUT_MS, VAULT_SESSION_TIMEOUT_SEC } from '../lib/vault-sessions.js';
import { createUnlockToken, validateUnlockToken, peekUnlockToken } from '../lib/unlock-tokens.js';
import { vaultUnlockLimiter, strictAuthLimiter } from '../lib/rate-limit.js';

const router = Router();

const USER_UI_URL = process.env.USER_UI_URL || 'http://localhost:5173';

// Handle magic links for vault unlock (from agent-generated links)
router.get('/', async (req, res) => {
  const { t: token } = req.query;

  if (!token) {
    return res.redirect(`${USER_UI_URL}/vault/unlock?error=missing_token`);
  }

  const tokenData = validateUnlockToken(token);

  if (!tokenData) {
    return res.redirect(`${USER_UI_URL}/vault/unlock?error=invalid_token`);
  }

  // Token is valid - create a new short-lived token for UI (since we consumed the original)
  const uiToken = createUnlockToken(tokenData.userId, 5 * 60 * 1000); // 5 minutes
  await audit.log(tokenData.userId, 'vault.unlock_link_accessed', null, req.ip);
  res.redirect(`${USER_UI_URL}/vault/unlock?t=${uiToken}`);
});

// Validate unlock token (called by User UI)
// Rate limited: strict auth limit to prevent token enumeration
router.post('/validate-unlock-token', strictAuthLimiter, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Token required' });
    }

    // Peek at token without consuming it
    const tokenData = peekUnlockToken(token);

    if (!tokenData || tokenData.expiresAt < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const user = await users.findById(tokenData.userId);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    res.json({
      valid: true,
      userId: tokenData.userId,
      userName: user.name,
      email: user.email,
      expiresIn: Math.floor((tokenData.expiresAt - Date.now()) / 1000)
    });
  } catch (err) {
    console.error('Validate unlock token error:', err);
    res.status(500).json({ error: 'Validation failed' });
  }
});

// Unlock vault with token (called by User UI)
// Rate limited: vault unlock limit to prevent password brute force
router.post('/unlock-with-token', vaultUnlockLimiter, async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password required' });
    }

    const tokenData = validateUnlockToken(token);

    if (!tokenData) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const userId = tokenData.userId;
    const vault = await users.getVault(userId);
    if (!vault) {
      return res.status(400).json({ error: 'No vault found' });
    }

    const { data, key } = await unlockVaultWithPasswordAndKey(vault, password);

    const vaultSessionToken = crypto.randomBytes(32).toString('hex');

    vaultSessions.set(vaultSessionToken, {
      userId,
      unlockedAt: Date.now(),
      expiresAt: Date.now() + VAULT_SESSION_TIMEOUT_MS,
      vaultKey: key
    });

    await users.updateBiometricsLastPassword(userId);
    await audit.log(userId, 'vault.unlocked_via_link', null, req.ip);

    res.json({
      success: true,
      vaultSessionToken,
      expiresIn: VAULT_SESSION_TIMEOUT_SEC
    });
  } catch (err) {
    if (err.message === 'Invalid password') {
      return res.status(401).json({ error: 'Invalid vault password' });
    }
    console.error('Unlock with token error:', err);
    res.status(500).json({ error: 'Failed to unlock vault' });
  }
});

export default router;
