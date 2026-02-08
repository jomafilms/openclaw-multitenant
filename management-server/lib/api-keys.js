// API key resolution helpers
import { integrations } from '../db/index.js';

// Business API keys (used when user doesn't have their own)
const DEFAULT_ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || null;
const DEFAULT_OPENAI_KEY = process.env.OPENAI_API_KEY || null;

/**
 * Get effective API key for a provider
 * First checks user's own key, then falls back to business default
 * @param {string} userId - User ID
 * @param {string} provider - Provider name ('anthropic' or 'openai')
 * @returns {Promise<{key: string, source: 'user' | 'business'} | null>}
 */
export async function getEffectiveApiKey(userId, provider) {
  // Try to get user's own key
  const userIntegration = await integrations.getDecryptedTokens(userId, provider);
  if (userIntegration?.apiKey) {
    return { key: userIntegration.apiKey, source: 'user' };
  }

  // Fall back to business default
  if (provider === 'anthropic' && DEFAULT_ANTHROPIC_KEY) {
    return { key: DEFAULT_ANTHROPIC_KEY, source: 'business' };
  }
  if (provider === 'openai' && DEFAULT_OPENAI_KEY) {
    return { key: DEFAULT_OPENAI_KEY, source: 'business' };
  }

  return null;
}
