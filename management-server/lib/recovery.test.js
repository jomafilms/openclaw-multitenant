import { describe, it, expect } from 'vitest';
import crypto from 'crypto';
import {
  setupSocialRecovery,
  decryptContactShard,
  recoverSeedFromShards,
  generateHardwareBackupKey,
  setupHardwareRecovery,
  recoverWithHardwareKey,
  createRecoveryToken,
  hashRecoveryToken,
  RecoveryMethodType
} from './recovery.js';

describe('Recovery Methods', () => {
  describe('RecoveryMethodType', () => {
    it('should define all recovery method types', () => {
      expect(RecoveryMethodType.BIP39).toBe('bip39');
      expect(RecoveryMethodType.SOCIAL).toBe('social');
      expect(RecoveryMethodType.HARDWARE).toBe('hardware');
    });
  });

  describe('Social Recovery', () => {
    const testSeed = crypto.randomBytes(32);
    const testContacts = [
      { email: 'alice@example.com', name: 'Alice' },
      { email: 'bob@example.com', name: 'Bob' },
      { email: 'carol@example.com', name: 'Carol' },
      { email: 'dave@example.com', name: 'Dave' },
      { email: 'eve@example.com', name: 'Eve' },
    ];

    describe('setupSocialRecovery', () => {
      it('should create recovery setup with default threshold (3 of 5)', () => {
        const setup = setupSocialRecovery(testSeed, testContacts);

        expect(setup.recoveryId).toBeDefined();
        expect(setup.recoveryId.length).toBe(32); // 16 bytes hex
        expect(setup.threshold).toBe(3);
        expect(setup.totalShares).toBe(5);
        expect(setup.contacts).toHaveLength(5);
        expect(setup.createdAt).toBeDefined();
      });

      it('should create encrypted shards for each contact', () => {
        const setup = setupSocialRecovery(testSeed, testContacts);

        for (const contact of setup.contacts) {
          expect(contact.email).toBeDefined();
          expect(contact.name).toBeDefined();
          expect(contact.shareIndex).toBeGreaterThan(0);
          expect(contact.encryptedShard).toBeDefined();
          expect(contact.encryptedShard.nonce).toBeDefined();
          expect(contact.encryptedShard.tag).toBeDefined();
          expect(contact.encryptedShard.ciphertext).toBeDefined();
        }
      });

      it('should support custom threshold', () => {
        const setup = setupSocialRecovery(testSeed, testContacts, 4);
        expect(setup.threshold).toBe(4);
      });

      it('should reject insufficient contacts', () => {
        expect(() => setupSocialRecovery(testSeed, [
          { email: 'a@x.com', name: 'A' },
          { email: 'b@x.com', name: 'B' },
        ])).toThrow('Need at least 3 contacts');
      });

      it('should reject too many contacts', () => {
        const tooManyContacts = Array(11).fill(null).map((_, i) => ({
          email: `user${i}@x.com`,
          name: `User ${i}`
        }));
        expect(() => setupSocialRecovery(testSeed, tooManyContacts)).toThrow('Maximum 10 contacts');
      });

      it('should reject invalid threshold', () => {
        expect(() => setupSocialRecovery(testSeed, testContacts, 1)).toThrow();
        expect(() => setupSocialRecovery(testSeed, testContacts, 6)).toThrow();
      });
    });

    describe('decryptContactShard', () => {
      it('should decrypt a contact shard', () => {
        const setup = setupSocialRecovery(testSeed, testContacts);
        const contact = setup.contacts[0];

        const decrypted = decryptContactShard(
          setup.recoveryId,
          contact.email,
          contact.encryptedShard
        );

        expect(decrypted).toBeDefined();
        expect(typeof decrypted).toBe('string');
        // Should be valid base64
        expect(() => Buffer.from(decrypted, 'base64')).not.toThrow();
      });

      it('should fail with wrong recovery ID', () => {
        const setup = setupSocialRecovery(testSeed, testContacts);
        const contact = setup.contacts[0];
        const wrongRecoveryId = crypto.randomBytes(16).toString('hex');

        expect(() => decryptContactShard(
          wrongRecoveryId,
          contact.email,
          contact.encryptedShard
        )).toThrow();
      });

      it('should fail with wrong email', () => {
        const setup = setupSocialRecovery(testSeed, testContacts);
        const contact = setup.contacts[0];

        expect(() => decryptContactShard(
          setup.recoveryId,
          'wrong@example.com',
          contact.encryptedShard
        )).toThrow();
      });
    });

    describe('full social recovery flow', () => {
      it('should recover seed from 3 of 5 shards', () => {
        const setup = setupSocialRecovery(testSeed, testContacts, 3);

        // Decrypt 3 shards
        const decryptedShards = [
          { shard: decryptContactShard(setup.recoveryId, setup.contacts[0].email, setup.contacts[0].encryptedShard) },
          { shard: decryptContactShard(setup.recoveryId, setup.contacts[2].email, setup.contacts[2].encryptedShard) },
          { shard: decryptContactShard(setup.recoveryId, setup.contacts[4].email, setup.contacts[4].encryptedShard) },
        ];

        const recovered = recoverSeedFromShards(decryptedShards);
        expect(recovered.equals(testSeed)).toBe(true);
      });

      it('should recover with any valid combination of shards', () => {
        const setup = setupSocialRecovery(testSeed, testContacts, 3);

        // Try different combinations
        const combinations = [
          [0, 1, 2],
          [0, 1, 3],
          [1, 2, 4],
          [0, 3, 4],
          [2, 3, 4],
        ];

        for (const combo of combinations) {
          const decryptedShards = combo.map(i => ({
            shard: decryptContactShard(
              setup.recoveryId,
              setup.contacts[i].email,
              setup.contacts[i].encryptedShard
            )
          }));

          const recovered = recoverSeedFromShards(decryptedShards);
          expect(recovered.equals(testSeed)).toBe(true);
        }
      });

      it('should fail with insufficient shards', () => {
        const setup = setupSocialRecovery(testSeed, testContacts, 3);

        const decryptedShards = [
          { shard: decryptContactShard(setup.recoveryId, setup.contacts[0].email, setup.contacts[0].encryptedShard) },
          { shard: decryptContactShard(setup.recoveryId, setup.contacts[1].email, setup.contacts[1].encryptedShard) },
        ];

        // With only 2 shards (threshold is 3), reconstruction fails
        const recovered = recoverSeedFromShards(decryptedShards);
        expect(recovered.equals(testSeed)).toBe(false);
      });
    });
  });

  describe('Hardware Backup', () => {
    describe('generateHardwareBackupKey', () => {
      it('should generate a formatted backup key', () => {
        const { backupKey, keyBytes, keyHash } = generateHardwareBackupKey();

        expect(backupKey).toBeDefined();
        expect(typeof backupKey).toBe('string');
        // Should be formatted with dashes (base32 in 4-char groups)
        expect(backupKey).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4})*$/);
        expect(keyBytes).toBeInstanceOf(Buffer);
        expect(keyBytes.length).toBe(32);
        expect(keyHash).toBeDefined();
      });

      it('should generate unique keys', () => {
        const key1 = generateHardwareBackupKey();
        const key2 = generateHardwareBackupKey();

        expect(key1.backupKey).not.toBe(key2.backupKey);
        expect(key1.keyHash).not.toBe(key2.keyHash);
      });
    });

    describe('setupHardwareRecovery', () => {
      it('should encrypt seed with hardware key', async () => {
        const seed = crypto.randomBytes(32);
        const { keyBytes, keyHash } = generateHardwareBackupKey();

        const recovery = await setupHardwareRecovery(seed, keyBytes);

        expect(recovery.encryptedSeed).toBeDefined();
        expect(recovery.encryptedSeed.nonce).toBeDefined();
        expect(recovery.encryptedSeed.tag).toBeDefined();
        expect(recovery.encryptedSeed.ciphertext).toBeDefined();
        expect(recovery.keyHash).toBe(keyHash);
        expect(recovery.createdAt).toBeDefined();
      });
    });

    describe('recoverWithHardwareKey', () => {
      it('should recover seed with correct backup key', async () => {
        const seed = crypto.randomBytes(32);
        const { backupKey, keyBytes } = generateHardwareBackupKey();

        const recovery = await setupHardwareRecovery(seed, keyBytes);
        const recovered = await recoverWithHardwareKey(backupKey, recovery.encryptedSeed);

        expect(recovered.equals(seed)).toBe(true);
      });

      it('should fail with wrong backup key', async () => {
        const seed = crypto.randomBytes(32);
        const { keyBytes } = generateHardwareBackupKey();
        const { backupKey: wrongKey } = generateHardwareBackupKey();

        const recovery = await setupHardwareRecovery(seed, keyBytes);

        await expect(recoverWithHardwareKey(wrongKey, recovery.encryptedSeed)).rejects.toThrow();
      });

      it('should handle key with/without formatting', async () => {
        const seed = crypto.randomBytes(32);
        const { backupKey, keyBytes } = generateHardwareBackupKey();

        const recovery = await setupHardwareRecovery(seed, keyBytes);

        // Key without dashes
        const keyNoDashes = backupKey.replace(/-/g, '');
        const recovered = await recoverWithHardwareKey(keyNoDashes, recovery.encryptedSeed);

        expect(recovered.equals(seed)).toBe(true);
      });

      it('should be case-insensitive', async () => {
        const seed = crypto.randomBytes(32);
        const { backupKey, keyBytes } = generateHardwareBackupKey();

        const recovery = await setupHardwareRecovery(seed, keyBytes);

        // Lowercase key
        const lowerKey = backupKey.toLowerCase();
        const recovered = await recoverWithHardwareKey(lowerKey, recovery.encryptedSeed);

        expect(recovered.equals(seed)).toBe(true);
      });
    });
  });

  describe('Recovery Token', () => {
    describe('createRecoveryToken', () => {
      it('should create a random token', () => {
        const token = createRecoveryToken();
        expect(token).toBeDefined();
        expect(typeof token).toBe('string');
        expect(token.length).toBe(64); // 32 bytes hex
      });

      it('should create unique tokens', () => {
        const token1 = createRecoveryToken();
        const token2 = createRecoveryToken();
        expect(token1).not.toBe(token2);
      });
    });

    describe('hashRecoveryToken', () => {
      it('should hash a token deterministically', () => {
        const token = createRecoveryToken();
        const hash1 = hashRecoveryToken(token);
        const hash2 = hashRecoveryToken(token);

        expect(hash1).toBe(hash2);
        expect(hash1.length).toBe(64); // SHA-256 hex
      });

      it('should produce different hashes for different tokens', () => {
        const token1 = createRecoveryToken();
        const token2 = createRecoveryToken();

        expect(hashRecoveryToken(token1)).not.toBe(hashRecoveryToken(token2));
      });
    });
  });
});
