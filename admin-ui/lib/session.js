'use strict';

const crypto = require('crypto');

// Session secret for signing (from environment or generate random)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

// In-memory session store
const sessions = new Map();

// Session expiry time: 24 hours in milliseconds
const SESSION_EXPIRY_MS = 24 * 60 * 60 * 1000;

// Cleanup interval: 1 hour in milliseconds
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

/**
 * Create a new session and store it in the session map.
 * @returns {string} The session token
 */
function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    createdAt: Date.now(),
    userId: undefined
  });
  return token;
}

/**
 * Validate a session token.
 * @param {string} token - The session token to validate
 * @returns {Object|null} The session data if valid, null otherwise
 */
function validateSession(token) {
  if (!token || typeof token !== 'string') {
    return null;
  }

  const session = sessions.get(token);
  if (!session) {
    return null;
  }

  // Check if session has expired
  const now = Date.now();
  if (now - session.createdAt > SESSION_EXPIRY_MS) {
    sessions.delete(token);
    return null;
  }

  return session;
}

/**
 * Destroy a session by removing it from the store.
 * @param {string} token - The session token to destroy
 */
function destroySession(token) {
  if (token && typeof token === 'string') {
    sessions.delete(token);
  }
}

/**
 * Clean up expired sessions from the store.
 */
function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (now - session.createdAt > SESSION_EXPIRY_MS) {
      sessions.delete(token);
    }
  }
}

// Run cleanup every hour
const cleanupInterval = setInterval(cleanupExpiredSessions, CLEANUP_INTERVAL_MS);

// Prevent the interval from keeping the process alive
if (cleanupInterval.unref) {
  cleanupInterval.unref();
}

module.exports = {
  createSession,
  validateSession,
  destroySession,
  SESSION_SECRET,
  // Export for testing purposes
  _sessions: sessions,
  _cleanupExpiredSessions: cleanupExpiredSessions
};
