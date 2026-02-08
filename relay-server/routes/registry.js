/**
 * Container Registry Routes
 *
 * Routes for container registration and discovery.
 * Containers register their callback URLs and public keys for
 * message forwarding and capability-based access.
 *
 * SECURITY NOTES:
 * - Registration requires valid gateway authentication
 * - Callback URLs are validated and rate-limited
 * - Public keys are verified to match container identity
 */
import { Router } from 'express';
import { createVerify, createPublicKey, createHash } from 'crypto';
import { requireContainer } from '../middleware/auth.js';
import { containerRegistry } from '../db/index.js';
import {
  validate,
  registerContainerSchema,
  updateRegistrationSchema,
  publicKeyLookupSchema,
} from '../lib/schemas.js';

const router = Router();

// Ed25519 SPKI prefix for DER-encoded public keys
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

/**
 * Hash a public key to create a lookup key.
 * Uses first 32 characters of SHA-256 hash for efficient indexing.
 */
function hashPublicKey(publicKeyBase64) {
  return createHash('sha256')
    .update(Buffer.from(publicKeyBase64, 'base64'))
    .digest('hex')
    .slice(0, 32);
}

/**
 * Verify a public key is valid Ed25519 format
 */
function isValidPublicKey(publicKeyBase64) {
  try {
    const rawKey = Buffer.from(publicKeyBase64, 'base64');
    if (rawKey.length !== 32) {
      return false;
    }
    // Try to create a KeyObject to validate the key
    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    createPublicKey({ key: spkiDer, type: 'spki', format: 'der' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify a signature to prove public key ownership
 */
function verifyOwnership(publicKeyBase64, challenge, signatureBase64) {
  try {
    const rawKey = Buffer.from(publicKeyBase64, 'base64');
    if (rawKey.length !== 32) {
      return false;
    }

    const spkiDer = Buffer.concat([ED25519_SPKI_PREFIX, rawKey]);
    const publicKey = createPublicKey({ key: spkiDer, type: 'spki', format: 'der' });

    const signatureBuffer = Buffer.from(signatureBase64, 'base64');
    if (signatureBuffer.length !== 64) {
      return false;
    }

    const verify = createVerify(null);
    verify.update(challenge);
    return verify.verify(publicKey, signatureBuffer);
  } catch (err) {
    console.error('[registry] Ownership verification failed:', err.message);
    return false;
  }
}

/**
 * Validate callback URL
 * - Must be HTTPS (or localhost for dev)
 * - Must be a valid URL
 * - Reject known-bad patterns
 */
function validateCallbackUrl(url) {
  try {
    const parsed = new URL(url);

    // Must be HTTPS (or localhost for development)
    if (parsed.protocol !== 'https:') {
      if (parsed.protocol === 'http:' && parsed.hostname === 'localhost') {
        // Allow localhost HTTP for development
        return { valid: true };
      }
      return { valid: false, error: 'Callback URL must use HTTPS' };
    }

    // Reject internal/private IPs (basic check)
    const hostname = parsed.hostname;
    if (
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.16.') ||
      hostname.endsWith('.internal') ||
      hostname.endsWith('.local')
    ) {
      return { valid: false, error: 'Callback URL cannot point to internal addresses' };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

/**
 * POST /relay/registry/register
 * Register a container's callback URL and public key.
 *
 * Body: {
 *   publicKey: string (base64 Ed25519 public key),
 *   encryptionPublicKey?: string (base64 X25519 public key),
 *   callbackUrl?: string (HTTPS URL for message delivery),
 *   challenge: string (random string signed to prove ownership),
 *   signature: string (Ed25519 signature of challenge)
 * }
 */
router.post('/register', requireContainer, validate({ body: registerContainerSchema }), async (req, res) => {
  const {
    publicKey,
    encryptionPublicKey,
    callbackUrl,
    challenge,
    signature,
  } = req.validatedBody;
  const containerId = req.container.userId;

  try {
    // Validate public key format
    if (!isValidPublicKey(publicKey)) {
      return res.status(400).json({
        error: 'Invalid public key format'
      });
    }

    // Verify ownership of the public key
    if (!verifyOwnership(publicKey, challenge, signature)) {
      return res.status(403).json({
        error: 'Public key ownership verification failed'
      });
    }

    // Validate callback URL if provided
    if (callbackUrl) {
      const urlValidation = validateCallbackUrl(callbackUrl);
      if (!urlValidation.valid) {
        return res.status(400).json({
          error: urlValidation.error
        });
      }
    }

    // Hash public key for lookup
    const publicKeyHash = hashPublicKey(publicKey);

    // Check if already registered
    const existing = await containerRegistry.findByContainerId(containerId);

    if (existing) {
      // Update existing registration
      await containerRegistry.update(containerId, {
        publicKey,
        publicKeyHash,
        encryptionPublicKey: encryptionPublicKey || null,
        callbackUrl: callbackUrl || null,
      });

      console.log(`[registry] Updated registration for container ${containerId.slice(0, 8)}`);
    } else {
      // Create new registration
      await containerRegistry.create({
        containerId,
        publicKey,
        publicKeyHash,
        encryptionPublicKey: encryptionPublicKey || null,
        callbackUrl: callbackUrl || null,
      });

      console.log(`[registry] New registration for container ${containerId.slice(0, 8)}`);
    }

    res.status(200).json({
      success: true,
      containerId,
      publicKeyHash,
      hasCallback: !!callbackUrl,
    });

  } catch (err) {
    console.error('[registry] Registration error:', err);
    res.status(500).json({ error: 'Failed to register container' });
  }
});

/**
 * PATCH /relay/registry/update
 * Update container registration (callback URL, encryption key).
 *
 * Body: {
 *   callbackUrl?: string,
 *   encryptionPublicKey?: string
 * }
 */
router.patch('/update', requireContainer, validate({ body: updateRegistrationSchema }), async (req, res) => {
  const { callbackUrl, encryptionPublicKey } = req.validatedBody;
  const containerId = req.container.userId;

  try {
    // Check if registered
    const existing = await containerRegistry.findByContainerId(containerId);
    if (!existing) {
      return res.status(404).json({
        error: 'Container not registered'
      });
    }

    // Validate callback URL if provided
    if (callbackUrl) {
      const urlValidation = validateCallbackUrl(callbackUrl);
      if (!urlValidation.valid) {
        return res.status(400).json({
          error: urlValidation.error
        });
      }
    }

    // Update registration
    const updates = {};
    if (callbackUrl !== undefined) {
      updates.callbackUrl = callbackUrl || null;
    }
    if (encryptionPublicKey !== undefined) {
      updates.encryptionPublicKey = encryptionPublicKey || null;
    }

    await containerRegistry.update(containerId, updates);

    console.log(`[registry] Updated registration for container ${containerId.slice(0, 8)}`);

    res.json({
      success: true,
      containerId,
      hasCallback: !!callbackUrl || !!existing.callback_url,
    });

  } catch (err) {
    console.error('[registry] Update error:', err);
    res.status(500).json({ error: 'Failed to update registration' });
  }
});

/**
 * DELETE /relay/registry
 * Unregister a container.
 */
router.delete('/', requireContainer, async (req, res) => {
  const containerId = req.container.userId;

  try {
    await containerRegistry.delete(containerId);

    console.log(`[registry] Unregistered container ${containerId.slice(0, 8)}`);

    res.json({
      success: true,
      containerId,
    });

  } catch (err) {
    console.error('[registry] Unregister error:', err);
    res.status(500).json({ error: 'Failed to unregister container' });
  }
});

/**
 * GET /relay/registry
 * Get current container's registration.
 */
router.get('/', requireContainer, async (req, res) => {
  const containerId = req.container.userId;

  try {
    const registration = await containerRegistry.findByContainerId(containerId);

    if (!registration) {
      return res.status(404).json({
        error: 'Container not registered'
      });
    }

    res.json({
      containerId: registration.container_id,
      publicKey: registration.public_key,
      publicKeyHash: registration.public_key_hash,
      encryptionPublicKey: registration.encryption_public_key,
      hasCallback: !!registration.callback_url,
      registeredAt: registration.created_at,
      updatedAt: registration.updated_at,
    });

  } catch (err) {
    console.error('[registry] Get error:', err);
    res.status(500).json({ error: 'Failed to get registration' });
  }
});

/**
 * GET /relay/registry/lookup/:publicKeyHash
 * Look up a container by public key hash.
 *
 * This enables discovery of container IDs from public keys.
 * The callback URL is NOT exposed to prevent probing attacks.
 */
router.get('/lookup/:publicKeyHash', validate({ params: publicKeyLookupSchema }), async (req, res) => {
  const { publicKeyHash } = req.validatedParams;

  try {
    const registration = await containerRegistry.findByPublicKeyHash(publicKeyHash);

    if (!registration) {
      return res.status(404).json({
        error: 'Container not found'
      });
    }

    // Only expose limited information (not callback URL)
    res.json({
      containerId: registration.container_id,
      publicKey: registration.public_key,
      encryptionPublicKey: registration.encryption_public_key,
      registeredAt: registration.created_at,
    });

  } catch (err) {
    console.error('[registry] Lookup error:', err);
    res.status(500).json({ error: 'Failed to lookup container' });
  }
});

/**
 * POST /relay/registry/lookup
 * Look up a container by full public key.
 *
 * Body: {
 *   publicKey: string (base64 public key)
 * }
 */
router.post('/lookup', async (req, res) => {
  const { publicKey } = req.body;

  if (!publicKey || typeof publicKey !== 'string') {
    return res.status(400).json({
      error: 'Missing publicKey in request body'
    });
  }

  try {
    if (!isValidPublicKey(publicKey)) {
      return res.status(400).json({
        error: 'Invalid public key format'
      });
    }

    const publicKeyHash = hashPublicKey(publicKey);
    const registration = await containerRegistry.findByPublicKeyHash(publicKeyHash);

    if (!registration) {
      return res.status(404).json({
        error: 'Container not found'
      });
    }

    // Only expose limited information (not callback URL)
    res.json({
      containerId: registration.container_id,
      publicKey: registration.public_key,
      encryptionPublicKey: registration.encryption_public_key,
      registeredAt: registration.created_at,
    });

  } catch (err) {
    console.error('[registry] Lookup by key error:', err);
    res.status(500).json({ error: 'Failed to lookup container' });
  }
});

export default router;
