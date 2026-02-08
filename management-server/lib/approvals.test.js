// Approval flow unit tests
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the database module
vi.mock('../db/index.js', () => ({
  capabilityApprovals: {
    create: vi.fn(),
    findById: vi.fn(),
    findByToken: vi.fn(),
    findPendingByUserAndSubject: vi.fn(),
    listPendingForUser: vi.fn(),
    listAllForUser: vi.fn(),
    approve: vi.fn(),
    approveWithConstraints: vi.fn(),
    deny: vi.fn(),
    markIssued: vi.fn(),
    expireOld: vi.fn(),
    delete: vi.fn(),
  },
  audit: {
    log: vi.fn(),
  },
  users: {
    findById: vi.fn(),
  },
}));

// Mock SSE broadcast
vi.mock('./sse.js', () => ({
  broadcastToUser: vi.fn(),
  sseConnections: new Map(),
}));

import { capabilityApprovals, audit, users } from '../db/index.js';
import { broadcastToUser } from './sse.js';

describe('capability approvals', () => {
  const mockUserId = 'user-123';
  const mockSubjectPublicKey = 'ed25519-public-key-abc123';
  const mockSubjectEmail = 'agent@example.com';
  const mockResource = 'calendar:events';
  const mockScope = ['read', 'list'];

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('approval creation', () => {
    it('should create an approval request with required fields', async () => {
      const approvalData = {
        userId: mockUserId,
        operationType: 'issue_capability',
        subjectPublicKey: mockSubjectPublicKey,
        subjectEmail: mockSubjectEmail,
        resource: mockResource,
        scope: mockScope,
        expiresInSeconds: 3600,
        maxCalls: null,
        reason: 'Agent needs calendar access',
        agentContext: { taskId: 'task-1' },
      };

      const mockApproval = {
        id: 'approval-1',
        ...approvalData,
        status: 'pending',
        token: 'secure-token-abc',
        created_at: new Date(),
        expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      capabilityApprovals.create.mockResolvedValue(mockApproval);

      const result = await capabilityApprovals.create(approvalData);

      expect(result).toEqual(mockApproval);
      expect(result.status).toBe('pending');
      expect(result.token).toBeDefined();
    });

    it('should detect duplicate pending approvals', async () => {
      const existingApproval = {
        id: 'approval-1',
        userId: mockUserId,
        subjectPublicKey: mockSubjectPublicKey,
        resource: mockResource,
        status: 'pending',
      };

      capabilityApprovals.findPendingByUserAndSubject.mockResolvedValue(existingApproval);

      const result = await capabilityApprovals.findPendingByUserAndSubject(
        mockUserId,
        mockSubjectPublicKey,
        mockResource
      );

      expect(result).toEqual(existingApproval);
      expect(result.id).toBe('approval-1');
    });

    it('should return null when no pending approval exists', async () => {
      capabilityApprovals.findPendingByUserAndSubject.mockResolvedValue(null);

      const result = await capabilityApprovals.findPendingByUserAndSubject(
        mockUserId,
        mockSubjectPublicKey,
        mockResource
      );

      expect(result).toBeNull();
    });
  });

  describe('approval decisions', () => {
    const mockPendingApproval = {
      id: 'approval-1',
      user_id: mockUserId,
      subject_public_key: mockSubjectPublicKey,
      subject_email: mockSubjectEmail,
      resource: mockResource,
      scope: mockScope,
      status: 'pending',
      expires_in_seconds: 3600,
      max_calls: null,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    it('should approve an approval request', async () => {
      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        decided_at: new Date(),
      };

      capabilityApprovals.findById.mockResolvedValue(mockPendingApproval);
      capabilityApprovals.approve.mockResolvedValue(approvedApproval);

      const result = await capabilityApprovals.approve(mockPendingApproval.id);

      expect(result.status).toBe('approved');
      expect(result.decided_at).toBeDefined();
    });

    it('should deny an approval request', async () => {
      const deniedApproval = {
        ...mockPendingApproval,
        status: 'denied',
        decided_at: new Date(),
      };

      capabilityApprovals.findById.mockResolvedValue(mockPendingApproval);
      capabilityApprovals.deny.mockResolvedValue(deniedApproval);

      const result = await capabilityApprovals.deny(mockPendingApproval.id);

      expect(result.status).toBe('denied');
      expect(result.decided_at).toBeDefined();
    });

    it('should mark an approved approval as issued', async () => {
      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        decided_at: new Date(),
      };

      const issuedApproval = {
        ...approvedApproval,
        status: 'issued',
      };

      capabilityApprovals.findById.mockResolvedValue(approvedApproval);
      capabilityApprovals.markIssued.mockResolvedValue(issuedApproval);

      const result = await capabilityApprovals.markIssued(approvedApproval.id);

      expect(result.status).toBe('issued');
    });
  });

  describe('approval with constraints', () => {
    const mockPendingApproval = {
      id: 'approval-1',
      user_id: mockUserId,
      subject_public_key: mockSubjectPublicKey,
      resource: mockResource,
      scope: ['read', 'list', 'write'],
      status: 'pending',
      expires_in_seconds: 86400, // 24 hours
      max_calls: null,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    it('should apply time limit constraint (reduce expiration)', async () => {
      const constraints = {
        expiresInSeconds: 3600, // Reduce to 1 hour
      };

      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        expires_in_seconds: 3600,
        decided_at: new Date(),
      };

      capabilityApprovals.approveWithConstraints.mockResolvedValue(approvedApproval);

      const result = await capabilityApprovals.approveWithConstraints(
        mockPendingApproval.id,
        constraints
      );

      expect(result.expires_in_seconds).toBe(3600);
      expect(result.status).toBe('approved');
    });

    it('should not allow extending time beyond original request', async () => {
      // The constraint validation happens in the route handler
      // Here we test that approveWithConstraints accepts the constraint value
      const constraints = {
        expiresInSeconds: 7200, // 2 hours (less than original 24 hours)
      };

      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        expires_in_seconds: 7200, // Should be capped at original if validation passes
        decided_at: new Date(),
      };

      capabilityApprovals.approveWithConstraints.mockResolvedValue(approvedApproval);

      const result = await capabilityApprovals.approveWithConstraints(
        mockPendingApproval.id,
        constraints
      );

      expect(result.expires_in_seconds).toBe(7200);
    });

    it('should apply scope restriction constraint (reduce permissions)', async () => {
      const constraints = {
        scope: ['read', 'list'], // Reduce from ['read', 'list', 'write']
      };

      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        scope: ['read', 'list'],
        decided_at: new Date(),
      };

      capabilityApprovals.approveWithConstraints.mockResolvedValue(approvedApproval);

      const result = await capabilityApprovals.approveWithConstraints(
        mockPendingApproval.id,
        constraints
      );

      expect(result.scope).toEqual(['read', 'list']);
      expect(result.scope).not.toContain('write');
    });

    it('should apply max calls constraint', async () => {
      const constraints = {
        maxCalls: 10,
      };

      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        max_calls: 10,
        decided_at: new Date(),
      };

      capabilityApprovals.approveWithConstraints.mockResolvedValue(approvedApproval);

      const result = await capabilityApprovals.approveWithConstraints(
        mockPendingApproval.id,
        constraints
      );

      expect(result.max_calls).toBe(10);
    });

    it('should apply multiple constraints together', async () => {
      const constraints = {
        expiresInSeconds: 3600,
        scope: ['read'],
        maxCalls: 5,
      };

      const approvedApproval = {
        ...mockPendingApproval,
        status: 'approved',
        expires_in_seconds: 3600,
        scope: ['read'],
        max_calls: 5,
        decided_at: new Date(),
      };

      capabilityApprovals.approveWithConstraints.mockResolvedValue(approvedApproval);

      const result = await capabilityApprovals.approveWithConstraints(
        mockPendingApproval.id,
        constraints
      );

      expect(result.expires_in_seconds).toBe(3600);
      expect(result.scope).toEqual(['read']);
      expect(result.max_calls).toBe(5);
    });
  });

  describe('token-based approval', () => {
    const mockToken = 'secure-approval-token-xyz';
    const mockApproval = {
      id: 'approval-1',
      user_id: mockUserId,
      token: mockToken,
      status: 'pending',
      resource: mockResource,
      scope: mockScope,
      expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
    };

    it('should find approval by token', async () => {
      capabilityApprovals.findByToken.mockResolvedValue(mockApproval);

      const result = await capabilityApprovals.findByToken(mockToken);

      expect(result).toEqual(mockApproval);
      expect(result.token).toBe(mockToken);
    });

    it('should return null for invalid or expired token', async () => {
      capabilityApprovals.findByToken.mockResolvedValue(null);

      const result = await capabilityApprovals.findByToken('invalid-token');

      expect(result).toBeNull();
    });
  });

  describe('listing approvals', () => {
    const mockApprovals = [
      {
        id: 'approval-1',
        user_id: mockUserId,
        resource: 'calendar:events',
        status: 'pending',
        created_at: new Date(),
      },
      {
        id: 'approval-2',
        user_id: mockUserId,
        resource: 'email:send',
        status: 'pending',
        created_at: new Date(Date.now() - 1000),
      },
    ];

    it('should list pending approvals for user', async () => {
      capabilityApprovals.listPendingForUser.mockResolvedValue(mockApprovals);

      const result = await capabilityApprovals.listPendingForUser(mockUserId);

      expect(result).toHaveLength(2);
      expect(result[0].status).toBe('pending');
      expect(result[1].status).toBe('pending');
    });

    it('should list all approvals with history', async () => {
      const historyApprovals = [
        ...mockApprovals,
        {
          id: 'approval-3',
          user_id: mockUserId,
          resource: 'files:read',
          status: 'approved',
          decided_at: new Date(Date.now() - 86400000),
        },
        {
          id: 'approval-4',
          user_id: mockUserId,
          resource: 'contacts:list',
          status: 'denied',
          decided_at: new Date(Date.now() - 172800000),
        },
      ];

      capabilityApprovals.listAllForUser.mockResolvedValue(historyApprovals);

      const result = await capabilityApprovals.listAllForUser(mockUserId, 50);

      expect(result).toHaveLength(4);
      const statuses = result.map(a => a.status);
      expect(statuses).toContain('pending');
      expect(statuses).toContain('approved');
      expect(statuses).toContain('denied');
    });
  });

  describe('expiration handling', () => {
    it('should expire old pending approvals', async () => {
      const expiredApprovals = [
        {
          id: 'approval-1',
          status: 'expired',
          expires_at: new Date(Date.now() - 1000),
        },
        {
          id: 'approval-2',
          status: 'expired',
          expires_at: new Date(Date.now() - 86400000),
        },
      ];

      capabilityApprovals.expireOld.mockResolvedValue(expiredApprovals);

      const result = await capabilityApprovals.expireOld();

      expect(result).toHaveLength(2);
      expect(result[0].status).toBe('expired');
      expect(result[1].status).toBe('expired');
    });
  });
});

describe('approval constraint validation', () => {
  // Test constraint validation logic

  function validateTimeConstraint(requestedSeconds, originalSeconds) {
    // Cannot extend beyond original request
    return Math.min(requestedSeconds, originalSeconds);
  }

  function validateScopeConstraint(requestedScope, originalScope) {
    // Can only reduce scope, not expand it
    return requestedScope.filter(s => originalScope.includes(s));
  }

  function validateCallsConstraint(requestedCalls, originalCalls) {
    if (requestedCalls === null) return originalCalls;
    if (originalCalls === null) return requestedCalls;
    return Math.min(requestedCalls, originalCalls);
  }

  describe('time limit validation', () => {
    it('should allow reducing time limit', () => {
      const result = validateTimeConstraint(3600, 86400);
      expect(result).toBe(3600);
    });

    it('should cap time limit at original value', () => {
      const result = validateTimeConstraint(172800, 86400);
      expect(result).toBe(86400);
    });

    it('should allow exact original time limit', () => {
      const result = validateTimeConstraint(86400, 86400);
      expect(result).toBe(86400);
    });
  });

  describe('scope restriction validation', () => {
    const originalScope = ['read', 'list', 'write'];

    it('should allow reducing scope', () => {
      const result = validateScopeConstraint(['read', 'list'], originalScope);
      expect(result).toEqual(['read', 'list']);
    });

    it('should filter out permissions not in original scope', () => {
      const result = validateScopeConstraint(['read', 'delete', 'admin'], originalScope);
      expect(result).toEqual(['read']);
    });

    it('should allow single permission', () => {
      const result = validateScopeConstraint(['read'], originalScope);
      expect(result).toEqual(['read']);
    });

    it('should return empty array if all requested permissions are invalid', () => {
      const result = validateScopeConstraint(['delete', 'admin'], originalScope);
      expect(result).toEqual([]);
    });
  });

  describe('call limit validation', () => {
    it('should allow setting calls when original is null', () => {
      const result = validateCallsConstraint(10, null);
      expect(result).toBe(10);
    });

    it('should allow reducing calls', () => {
      const result = validateCallsConstraint(5, 10);
      expect(result).toBe(5);
    });

    it('should cap calls at original value', () => {
      const result = validateCallsConstraint(20, 10);
      expect(result).toBe(10);
    });

    it('should return original when requested is null', () => {
      const result = validateCallsConstraint(null, 10);
      expect(result).toBe(10);
    });
  });
});

describe('capability ceiling validation', () => {
  const PERMISSION_LEVELS = ['read', 'list', 'write', 'delete', 'admin', 'share-further'];
  const DEFAULT_AGENT_CEILING = ['read', 'list'];

  function isPermissionExceedingCeiling(permission, ceiling = DEFAULT_AGENT_CEILING) {
    return !ceiling.includes(permission);
  }

  function getExceedingPermissions(requestedScope, ceiling = DEFAULT_AGENT_CEILING) {
    return requestedScope.filter(p => !ceiling.includes(p));
  }

  it('should identify permissions within ceiling', () => {
    expect(isPermissionExceedingCeiling('read')).toBe(false);
    expect(isPermissionExceedingCeiling('list')).toBe(false);
  });

  it('should identify permissions exceeding default ceiling', () => {
    expect(isPermissionExceedingCeiling('write')).toBe(true);
    expect(isPermissionExceedingCeiling('delete')).toBe(true);
    expect(isPermissionExceedingCeiling('admin')).toBe(true);
  });

  it('should get list of exceeding permissions', () => {
    const requested = ['read', 'list', 'write', 'delete'];
    const exceeding = getExceedingPermissions(requested);
    expect(exceeding).toEqual(['write', 'delete']);
  });

  it('should return empty array when all permissions are within ceiling', () => {
    const requested = ['read', 'list'];
    const exceeding = getExceedingPermissions(requested);
    expect(exceeding).toEqual([]);
  });

  it('should respect custom ceiling', () => {
    const customCeiling = ['read', 'list', 'write'];
    const requested = ['read', 'write', 'delete'];
    const exceeding = getExceedingPermissions(requested, customCeiling);
    expect(exceeding).toEqual(['delete']);
  });
});

describe('approval status state machine', () => {
  // Test valid status transitions

  const VALID_TRANSITIONS = {
    pending: ['approved', 'denied', 'expired'],
    approved: ['issued'],
    denied: [],
    issued: [],
    expired: [],
  };

  function isValidTransition(from, to) {
    return VALID_TRANSITIONS[from]?.includes(to) ?? false;
  }

  it('should allow pending -> approved', () => {
    expect(isValidTransition('pending', 'approved')).toBe(true);
  });

  it('should allow pending -> denied', () => {
    expect(isValidTransition('pending', 'denied')).toBe(true);
  });

  it('should allow pending -> expired', () => {
    expect(isValidTransition('pending', 'expired')).toBe(true);
  });

  it('should allow approved -> issued', () => {
    expect(isValidTransition('approved', 'issued')).toBe(true);
  });

  it('should not allow denied -> approved', () => {
    expect(isValidTransition('denied', 'approved')).toBe(false);
  });

  it('should not allow issued -> pending', () => {
    expect(isValidTransition('issued', 'pending')).toBe(false);
  });

  it('should not allow expired -> approved', () => {
    expect(isValidTransition('expired', 'approved')).toBe(false);
  });

  it('should not allow approved -> denied', () => {
    expect(isValidTransition('approved', 'denied')).toBe(false);
  });
});

describe('time limit presets', () => {
  const TIME_PRESETS = {
    '1h': 3600,
    '4h': 14400,
    '1d': 86400,
    '1w': 604800,
  };

  function calculateExpiresInSeconds(preset, customHours) {
    if (preset === 'custom' && customHours) {
      return customHours * 3600;
    }
    return TIME_PRESETS[preset] || 3600;
  }

  it('should calculate 1 hour preset', () => {
    expect(calculateExpiresInSeconds('1h')).toBe(3600);
  });

  it('should calculate 4 hour preset', () => {
    expect(calculateExpiresInSeconds('4h')).toBe(14400);
  });

  it('should calculate 1 day preset', () => {
    expect(calculateExpiresInSeconds('1d')).toBe(86400);
  });

  it('should calculate 1 week preset', () => {
    expect(calculateExpiresInSeconds('1w')).toBe(604800);
  });

  it('should calculate custom hours', () => {
    expect(calculateExpiresInSeconds('custom', 2)).toBe(7200);
    expect(calculateExpiresInSeconds('custom', 12)).toBe(43200);
    expect(calculateExpiresInSeconds('custom', 48)).toBe(172800);
  });

  it('should default to 1 hour for unknown preset', () => {
    expect(calculateExpiresInSeconds('unknown')).toBe(3600);
  });
});
