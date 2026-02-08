/**
 * Migration Tests
 *
 * Tests for the vault migration from management server to container.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  migrateUserToContainerVault,
  getMigrationStatus,
  checkMigrationEligibility,
  listMigrationCandidates,
  MIGRATION_STATUS
} from './migration.js';

// Mock dependencies
vi.mock('../db/index.js', () => ({
  users: {
    findById: vi.fn(),
    list: vi.fn(),
    getSettings: vi.fn(),
    updateSettings: vi.fn()
  },
  audit: {
    log: vi.fn()
  }
}));

vi.mock('./vault.js', () => ({
  unlockVaultWithKey: vi.fn()
}));

vi.mock('./vault-sessions.js', () => ({
  getVaultSession: vi.fn()
}));

vi.mock('axios', () => ({
  default: {
    post: vi.fn(),
    get: vi.fn(),
    put: vi.fn()
  }
}));

import { users, audit } from '../db/index.js';
import { unlockVaultWithKey } from './vault.js';
import { getVaultSession } from './vault-sessions.js';
import axios from 'axios';

describe('Migration', () => {
  const mockUserId = 'user-123';
  const mockVaultKey = Buffer.from('test-vault-key-32-bytes-long!!!');
  const mockVaultSessionToken = 'session-token-abc';

  const mockUser = {
    id: mockUserId,
    email: 'test@example.com',
    name: 'Test User',
    container_id: 'container-abc',
    container_port: 19001,
    gateway_token: 'gateway-token-xyz',
    vault: { version: 1, ciphertext: 'encrypted-data' },
    status: 'active'
  };

  const mockVaultData = {
    integrations: {
      google_calendar: {
        accessToken: 'access-token-123',
        refreshToken: 'refresh-token-456',
        expiresAt: '2025-12-31T23:59:59Z',
        email: 'test@example.com'
      },
      github: {
        accessToken: 'github-token-789',
        expiresAt: '2025-12-31T23:59:59Z'
      }
    }
  };

  beforeEach(() => {
    vi.clearAllMocks();

    // Default mock implementations
    users.findById.mockResolvedValue(mockUser);
    users.getSettings.mockResolvedValue({ containerVaultMigration: { status: MIGRATION_STATUS.NOT_STARTED } });
    users.updateSettings.mockResolvedValue({});
    users.list.mockResolvedValue([mockUser]);

    getVaultSession.mockReturnValue({
      userId: mockUserId,
      vaultKey: mockVaultKey,
      expiresAt: Date.now() + 3600000
    });

    unlockVaultWithKey.mockReturnValue(mockVaultData);

    // Mock axios calls
    axios.post.mockImplementation((url) => {
      if (url.includes('/wake')) {
        return Promise.resolve({ data: { status: 'running', wakeTime: 100 } });
      }
      if (url.includes('/initialize')) {
        return Promise.resolve({ data: { success: true } });
      }
      if (url.includes('/unlock')) {
        return Promise.resolve({ data: { success: true, expiresIn: 1800 } });
      }
      return Promise.resolve({ data: {} });
    });

    axios.get.mockImplementation((url) => {
      if (url.includes('/status')) {
        return Promise.resolve({ data: { initialized: false, locked: true } });
      }
      return Promise.resolve({ data: {} });
    });

    axios.put.mockImplementation(() => {
      return Promise.resolve({ data: { success: true } });
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getMigrationStatus', () => {
    it('returns NOT_STARTED when no status exists', async () => {
      users.getSettings.mockResolvedValue({});
      const status = await getMigrationStatus(mockUserId);
      expect(status.status).toBe(MIGRATION_STATUS.NOT_STARTED);
    });

    it('returns stored status', async () => {
      users.getSettings.mockResolvedValue({
        containerVaultMigration: {
          status: MIGRATION_STATUS.COMPLETED,
          completedAt: '2025-01-01T00:00:00Z'
        }
      });
      const status = await getMigrationStatus(mockUserId);
      expect(status.status).toBe(MIGRATION_STATUS.COMPLETED);
      expect(status.completedAt).toBe('2025-01-01T00:00:00Z');
    });
  });

  describe('checkMigrationEligibility', () => {
    it('returns eligible for user with container and vault', async () => {
      const result = await checkMigrationEligibility(mockUserId);
      expect(result.eligible).toBe(true);
      expect(result.checks.hasContainer).toBe(true);
      expect(result.checks.hasVault).toBe(true);
    });

    it('returns not eligible when user not found', async () => {
      users.findById.mockResolvedValue(null);
      const result = await checkMigrationEligibility(mockUserId);
      expect(result.eligible).toBe(false);
      expect(result.reason).toBe('User not found');
    });

    it('returns not eligible when no container', async () => {
      users.findById.mockResolvedValue({ ...mockUser, container_id: null, container_port: null });
      const result = await checkMigrationEligibility(mockUserId);
      expect(result.eligible).toBe(false);
      expect(result.reason).toBe('No container provisioned');
    });

    it('returns not eligible when no vault', async () => {
      users.findById.mockResolvedValue({ ...mockUser, vault: null });
      const result = await checkMigrationEligibility(mockUserId);
      expect(result.eligible).toBe(false);
      expect(result.reason).toBe('No vault configured');
    });
  });

  describe('migrateUserToContainerVault', () => {
    it('fails if migration already completed without force', async () => {
      users.getSettings.mockResolvedValue({
        containerVaultMigration: { status: MIGRATION_STATUS.COMPLETED }
      });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('already completed');
    });

    it('allows re-migration with force flag', async () => {
      users.getSettings.mockResolvedValue({
        containerVaultMigration: { status: MIGRATION_STATUS.COMPLETED }
      });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken,
        force: true
      });

      // Should proceed with migration
      expect(result.success).toBe(true);
    });

    it('fails if user not found', async () => {
      users.findById.mockResolvedValue(null);

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('User not found');
    });

    it('fails if no container provisioned', async () => {
      users.findById.mockResolvedValue({ ...mockUser, container_id: null });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe('User does not have a provisioned container');
    });

    it('fails if no vault session', async () => {
      getVaultSession.mockReturnValue(null);

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('vault session required');
    });

    it('fails if vault session belongs to different user', async () => {
      getVaultSession.mockReturnValue({
        userId: 'different-user',
        vaultKey: mockVaultKey
      });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('vault session required');
    });

    it('successfully migrates integrations', async () => {
      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken,
        adminUserId: 'admin-123',
        ipAddress: '127.0.0.1'
      });

      expect(result.success).toBe(true);
      expect(result.integrationsMigrated).toContain('google_calendar');
      expect(result.integrationsMigrated).toContain('github');
      expect(result.integrationsFailed).toHaveLength(0);

      // Should have called wake
      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining('/wake'),
        expect.any(Object),
        expect.any(Object)
      );

      // Should have initialized vault
      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining('/initialize'),
        expect.any(Object),
        expect.any(Object)
      );

      // Should have imported each integration
      expect(axios.put).toHaveBeenCalledTimes(2);

      // Should have logged audit
      expect(audit.log).toHaveBeenCalledWith(
        'admin-123',
        'vault.migration',
        expect.objectContaining({
          targetUserId: mockUserId,
          status: 'completed'
        }),
        '127.0.0.1',
        mockUserId
      );
    });

    it('handles partial migration failure', async () => {
      // Make github import fail
      axios.put.mockImplementation((url) => {
        if (url.includes('github')) {
          return Promise.resolve({ data: { success: false, error: 'Token expired' } });
        }
        return Promise.resolve({ data: { success: true } });
      });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(true);
      expect(result.partial).toBe(true);
      expect(result.integrationsMigrated).toContain('google_calendar');
      expect(result.integrationsFailed).toHaveLength(1);
      expect(result.integrationsFailed[0].provider).toBe('github');
    });

    it('handles container wake failure', async () => {
      axios.post.mockImplementation((url) => {
        if (url.includes('/wake')) {
          return Promise.reject(new Error('Container unreachable'));
        }
        return Promise.resolve({ data: {} });
      });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(false);
      expect(result.errors).toContainEqual(expect.stringContaining('wake'));
    });

    it('unlocks existing container vault instead of initializing', async () => {
      // Container vault already initialized
      axios.get.mockImplementation((url) => {
        if (url.includes('/status')) {
          return Promise.resolve({ data: { initialized: true, locked: true } });
        }
        return Promise.resolve({ data: {} });
      });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(true);
      expect(result.containerVaultUnlocked).toBe(true);

      // Should have called unlock, not initialize
      expect(axios.post).toHaveBeenCalledWith(
        expect.stringContaining('/unlock'),
        expect.any(Object),
        expect.any(Object)
      );
    });

    it('handles empty integrations gracefully', async () => {
      unlockVaultWithKey.mockReturnValue({ integrations: {} });

      const result = await migrateUserToContainerVault(mockUserId, {
        vaultSessionToken: mockVaultSessionToken
      });

      expect(result.success).toBe(true);
      expect(result.message).toBe('No integrations to migrate');
      expect(result.integrationsMigrated).toHaveLength(0);
    });
  });

  describe('listMigrationCandidates', () => {
    it('returns eligible users with their status', async () => {
      const candidates = await listMigrationCandidates();

      expect(candidates).toHaveLength(1);
      expect(candidates[0].userId).toBe(mockUserId);
      expect(candidates[0].email).toBe('test@example.com');
      expect(candidates[0].migrationStatus).toBe(MIGRATION_STATUS.NOT_STARTED);
    });

    it('excludes ineligible users', async () => {
      const ineligibleUser = { ...mockUser, id: 'user-456', email: 'other@example.com', container_id: null };
      users.list.mockResolvedValue([
        mockUser,
        ineligibleUser
      ]);
      // Mock findById to return the appropriate user based on ID
      users.findById.mockImplementation((id) => {
        if (id === mockUserId) return Promise.resolve(mockUser);
        if (id === 'user-456') return Promise.resolve(ineligibleUser);
        return Promise.resolve(null);
      });

      const candidates = await listMigrationCandidates();

      expect(candidates).toHaveLength(1);
      expect(candidates[0].userId).toBe(mockUserId);
    });
  });
});
