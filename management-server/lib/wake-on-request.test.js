// Wake-on-request tests
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock axios before importing the module
vi.mock('axios', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

// Mock context
vi.mock('./context.js', () => ({
  AGENT_SERVER_URL: 'http://localhost:4000',
  AGENT_SERVER_TOKEN: 'test-token',
}));

describe('wake-on-request', () => {
  let axios;
  let wakeModule;

  beforeEach(async () => {
    vi.clearAllMocks();
    axios = (await import('axios')).default;
    wakeModule = await import('./wake-on-request.js');
  });

  describe('isContainerRunning', () => {
    it('returns true if container status shows ready', async () => {
      axios.get.mockResolvedValueOnce({
        data: { ready: true, hibernationState: 'running' },
      });

      const result = await wakeModule.isContainerRunning('user-123');

      expect(result).toBe(true);
      expect(axios.get).toHaveBeenCalledWith(
        'http://localhost:4000/api/containers/user-123/status/quick',
        expect.any(Object)
      );
    });

    it('returns false if container is not ready', async () => {
      axios.get.mockResolvedValueOnce({
        data: { ready: false, hibernationState: 'paused' },
      });

      const result = await wakeModule.isContainerRunning('user-123');

      expect(result).toBe(false);
    });

    it('returns false if container does not exist (404)', async () => {
      axios.get.mockRejectedValueOnce({ response: { status: 404 } });

      const result = await wakeModule.isContainerRunning('user-123');

      expect(result).toBe(false);
    });
  });

  describe('wakeContainerIfNeeded', () => {
    it('returns already-running if container is ready', async () => {
      axios.get.mockResolvedValueOnce({
        data: { ready: true },
      });

      const result = await wakeModule.wakeContainerIfNeeded('user-123', 'on-request');

      expect(result).toEqual({
        success: true,
        status: 'already-running',
        wakeTime: 0,
      });
      expect(axios.post).not.toHaveBeenCalled();
    });

    it('calls wake endpoint if container is hibernated', async () => {
      axios.get.mockResolvedValueOnce({
        data: { ready: false, hibernationState: 'paused' },
      });
      axios.post.mockResolvedValueOnce({
        data: { status: 'awoke', wakeTime: 1500 },
      });

      const result = await wakeModule.wakeContainerIfNeeded('user-123', 'on-request');

      expect(result.success).toBe(true);
      expect(result.status).toBe('awoke');
      expect(axios.post).toHaveBeenCalledWith(
        'http://localhost:4000/api/containers/user-123/wake',
        expect.objectContaining({ reason: 'on-request' }),
        expect.any(Object)
      );
    });

    it('handles timeout error', async () => {
      axios.get.mockResolvedValueOnce({
        data: { ready: false },
      });
      axios.post.mockRejectedValueOnce({
        code: 'ECONNABORTED',
        response: { status: 504 },
      });

      const result = await wakeModule.wakeContainerIfNeeded('user-123', 'on-request');

      expect(result.success).toBe(false);
      expect(result.status).toBe('timeout');
    });

    it('handles other errors', async () => {
      axios.get.mockResolvedValueOnce({
        data: { ready: false },
      });
      axios.post.mockRejectedValueOnce(new Error('Network error'));

      const result = await wakeModule.wakeContainerIfNeeded('user-123', 'on-request');

      expect(result.success).toBe(false);
      expect(result.status).toBe('failed');
    });
  });

  describe('wakeContainers (parallel)', () => {
    it('wakes multiple containers in parallel', async () => {
      axios.get.mockResolvedValue({ data: { ready: false } });
      axios.post.mockResolvedValue({
        data: { status: 'awoke', wakeTime: 1000 },
      });

      const results = await wakeModule.wakeContainers(
        ['user-1', 'user-2', 'user-3'],
        'batch-wake'
      );

      expect(results).toHaveLength(3);
      expect(results[0]).toEqual(expect.objectContaining({
        userId: 'user-1',
        success: true,
      }));
    });
  });

  describe('getWakeOnRequestMetrics', () => {
    it('returns metrics object', () => {
      const metrics = wakeModule.getWakeOnRequestMetrics();

      expect(metrics).toHaveProperty('totalRequests');
      expect(metrics).toHaveProperty('alreadyRunning');
      expect(metrics).toHaveProperty('successfulWakes');
      expect(metrics).toHaveProperty('failedWakes');
      expect(metrics).toHaveProperty('timeouts');
      expect(metrics).toHaveProperty('avgWakeLatencyMs');
    });
  });

  describe('createWakeMiddleware', () => {
    it('wakes container and proceeds to next', async () => {
      axios.get.mockResolvedValueOnce({ data: { ready: false } });
      axios.post.mockResolvedValueOnce({
        data: { status: 'awoke', wakeTime: 500 },
      });

      const getTargetUserId = vi.fn().mockResolvedValue('target-user-id');
      const middleware = wakeModule.createWakeMiddleware(getTargetUserId);

      const req = {};
      const res = {};
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.wakeResult).toBeDefined();
      expect(req.wakeResult.success).toBe(true);
    });

    it('skips wake if no target user', async () => {
      const getTargetUserId = vi.fn().mockResolvedValue(null);
      const middleware = wakeModule.createWakeMiddleware(getTargetUserId);

      const req = {};
      const res = {};
      const next = vi.fn();

      await middleware(req, res, next);

      expect(next).toHaveBeenCalled();
      expect(req.wakeResult).toBeUndefined();
    });

    it('returns 503 on timeout', async () => {
      axios.get.mockResolvedValueOnce({ data: { ready: false } });
      axios.post.mockRejectedValueOnce({ response: { status: 504 } });

      const getTargetUserId = vi.fn().mockResolvedValue('target-user-id');
      const middleware = wakeModule.createWakeMiddleware(getTargetUserId);

      const req = {};
      const res = {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
      };
      const next = vi.fn();

      await middleware(req, res, next);

      expect(res.status).toHaveBeenCalledWith(503);
      expect(next).not.toHaveBeenCalled();
    });
  });
});
