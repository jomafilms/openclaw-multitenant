/**
 * Tests for Secret Store Gateway Runtime Integration
 *
 * Tests the gateway runtime integration that initializes and manages
 * the container-side secret store.
 *
 * Uses mocks to avoid SecretStore initialization overhead (scrypt).
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { CredentialProvider, AgentCredential } from "../container/agent-credentials.js";
import type { SecretStore } from "../container/secret-store.js";

// Mock state for testing
let mockVaultUnlocked = false;
let mockVaultInitialized = false;
let mockIntegrations: Map<
  string,
  {
    accessToken: string;
    refreshToken?: string;
    expiresAt: string;
    email?: string;
    scopes?: string[];
  }
> = new Map();

const mockStore: Partial<SecretStore> = {
  isUnlocked: () => mockVaultUnlocked,
  getSessionTimeRemaining: () => (mockVaultUnlocked ? 1800 : 0),
  getPublicKey: () => (mockVaultUnlocked ? "test-public-key" : null),
  unlock: vi.fn().mockImplementation(async (password: string) => {
    if (password === "test-password") {
      mockVaultUnlocked = true;
      return true;
    }
    return false;
  }),
  lock: vi.fn().mockImplementation(() => {
    mockVaultUnlocked = false;
  }),
  extendSession: vi.fn(),
  getIntegration: (provider: string) => {
    if (!mockVaultUnlocked) {
      return null;
    }
    const int = mockIntegrations.get(provider);
    if (!int) {
      return null;
    }
    return int;
  },
  setIntegration: vi.fn().mockImplementation(
    async (
      provider: string,
      integration: {
        accessToken: string;
        refreshToken?: string;
        expiresAt: string;
        email?: string;
        scopes?: string[];
      },
    ) => {
      mockIntegrations.set(provider, integration);
    },
  ),
  listIntegrations: () => {
    if (!mockVaultUnlocked) {
      return [];
    }
    return Array.from(mockIntegrations.entries()).map(([provider, int]) => ({
      provider,
      email: int.email,
      expiresAt: int.expiresAt,
    }));
  },
  getSalt: () => (mockVaultInitialized ? "test-salt" : null),
};

const mockCredentialProvider: CredentialProvider = {
  getCredential: (provider: string): AgentCredential | null => {
    if (!mockVaultUnlocked) {
      return null;
    }
    const int = mockIntegrations.get(provider);
    if (!int) {
      return null;
    }
    return {
      provider,
      accessToken: int.accessToken,
      refreshToken: int.refreshToken,
      expiresAt: new Date(int.expiresAt),
      email: int.email,
      scopes: int.scopes,
    };
  },
  listProviders: () => {
    if (!mockVaultUnlocked) {
      return [];
    }
    return Array.from(mockIntegrations.entries()).map(([provider, int]) => ({
      provider,
      email: int.email,
      expiresAt: new Date(int.expiresAt),
    }));
  },
  isReady: () => mockVaultUnlocked,
  hasCredential: (provider: string) => {
    if (!mockVaultUnlocked) {
      return false;
    }
    return mockIntegrations.has(provider);
  },
};

// Mock the modules
vi.mock("../container/secret-store.js", () => ({
  getSecretStore: () => mockStore,
  resetSecretStore: () => {
    mockVaultUnlocked = false;
  },
}));

vi.mock("../container/agent-credentials.js", () => ({
  getCredentialProvider: () => mockCredentialProvider,
}));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  return {
    ...actual,
    existsSync: (path: string) => {
      if (path.endsWith("secrets.enc")) {
        return mockVaultInitialized;
      }
      return actual.existsSync(path);
    },
  };
});

// Import after mocks are set up
import {
  initSecretStoreRuntime,
  getSecretStoreStatus,
  getCredentialFromStore,
  isVaultReady,
  listCredentialProviders,
  resetSecretStoreRuntime,
} from "./secret-store-runtime.js";

describe("secret-store-runtime", () => {
  beforeEach(() => {
    mockVaultUnlocked = false;
    mockVaultInitialized = false;
    mockIntegrations.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetSecretStoreRuntime();
    delete process.env.OCMT_VAULT_PASSWORD;
    delete process.env.TEST_VAULT_PASSWORD;
  });

  describe("initSecretStoreRuntime", () => {
    it("returns initialized=false when vault does not exist", async () => {
      mockVaultInitialized = false;

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: false,
      });

      expect(state.initialized).toBe(false);
      expect(state.unlocked).toBe(false);
      state.stop();
    });

    it("returns initialized=true when vault exists", async () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = false;

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: false,
      });

      expect(state.initialized).toBe(true);
      expect(state.unlocked).toBe(false);
      state.stop();
    });

    it("auto-unlocks vault when password is in environment", async () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = false;
      process.env.TEST_VAULT_PASSWORD = "test-password";

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: true,
        passwordEnvVar: "TEST_VAULT_PASSWORD",
      });

      expect(state.initialized).toBe(true);
      expect(state.unlocked).toBe(true);
      expect(mockStore.unlock).toHaveBeenCalledWith("test-password");
      state.stop();
    });

    it("does not auto-unlock with wrong password", async () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = false;
      process.env.TEST_VAULT_PASSWORD = "wrong-password";

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: true,
        passwordEnvVar: "TEST_VAULT_PASSWORD",
      });

      expect(state.initialized).toBe(true);
      expect(state.unlocked).toBe(false);
      state.stop();
    });

    it("does not attempt unlock when no password in env", async () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = false;

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: true,
        passwordEnvVar: "NONEXISTENT_VAR",
      });

      expect(state.initialized).toBe(true);
      expect(state.unlocked).toBe(false);
      expect(mockStore.unlock).not.toHaveBeenCalled();
      state.stop();
    });

    it("provides credential provider in returned state", async () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = true;

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: false,
      });

      expect(state.credentialProvider).toBeDefined();
      expect(typeof state.credentialProvider.getCredential).toBe("function");
      expect(typeof state.credentialProvider.listProviders).toBe("function");
      expect(typeof state.credentialProvider.isReady).toBe("function");
      state.stop();
    });

    it("stop() can be called safely multiple times", async () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = true;

      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: false,
      });

      // Should not throw
      state.stop();
      state.stop();
      state.stop();
    });
  });

  describe("getSecretStoreStatus", () => {
    it("returns correct status when vault is not initialized", () => {
      mockVaultInitialized = false;
      mockVaultUnlocked = false;

      const status = getSecretStoreStatus();

      expect(status.initialized).toBe(false);
      expect(status.locked).toBe(true);
      expect(status.sessionTimeRemaining).toBe(0);
      expect(status.publicKey).toBeNull();
    });

    it("returns correct status when vault is locked", () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = false;

      const status = getSecretStoreStatus();

      expect(status.initialized).toBe(true);
      expect(status.locked).toBe(true);
      expect(status.sessionTimeRemaining).toBe(0);
      expect(status.publicKey).toBeNull();
    });

    it("returns correct status when vault is unlocked", () => {
      mockVaultInitialized = true;
      mockVaultUnlocked = true;

      const status = getSecretStoreStatus();

      expect(status.initialized).toBe(true);
      expect(status.locked).toBe(false);
      expect(status.sessionTimeRemaining).toBeGreaterThan(0);
      expect(status.publicKey).toBe("test-public-key");
    });
  });

  describe("getCredentialFromStore", () => {
    it("returns null when vault is locked", () => {
      mockVaultUnlocked = false;
      mockIntegrations.set("google", {
        accessToken: "test-token",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      });

      const credential = getCredentialFromStore("google");

      expect(credential).toBeNull();
    });

    it("returns null for non-existent provider", () => {
      mockVaultUnlocked = true;

      const credential = getCredentialFromStore("nonexistent");

      expect(credential).toBeNull();
    });

    it("returns credential when available", () => {
      mockVaultUnlocked = true;
      mockIntegrations.set("google", {
        accessToken: "test-token",
        refreshToken: "refresh-token",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        email: "test@example.com",
        scopes: ["email", "profile"],
      });

      const credential = getCredentialFromStore("google");

      expect(credential).not.toBeNull();
      expect(credential!.provider).toBe("google");
      expect(credential!.accessToken).toBe("test-token");
      expect(credential!.refreshToken).toBe("refresh-token");
      expect(credential!.email).toBe("test@example.com");
      expect(credential!.scopes).toEqual(["email", "profile"]);
    });
  });

  describe("isVaultReady", () => {
    it("returns false when vault is locked", () => {
      mockVaultUnlocked = false;

      expect(isVaultReady()).toBe(false);
    });

    it("returns true when vault is unlocked", () => {
      mockVaultUnlocked = true;

      expect(isVaultReady()).toBe(true);
    });
  });

  describe("listCredentialProviders", () => {
    it("returns empty array when vault is locked", () => {
      mockVaultUnlocked = false;
      mockIntegrations.set("google", {
        accessToken: "token",
        expiresAt: new Date().toISOString(),
      });

      const providers = listCredentialProviders();

      expect(providers).toEqual([]);
    });

    it("returns providers when vault is unlocked", () => {
      mockVaultUnlocked = true;
      mockIntegrations.set("google", {
        accessToken: "token1",
        expiresAt: new Date().toISOString(),
        email: "user1@example.com",
      });
      mockIntegrations.set("github", {
        accessToken: "token2",
        expiresAt: new Date().toISOString(),
        email: "user2@example.com",
      });

      const providers = listCredentialProviders();

      expect(providers).toHaveLength(2);
      expect(providers.map((p) => p.provider).toSorted()).toEqual(["github", "google"]);
    });
  });

  describe("integration flow", () => {
    it("full lifecycle: init, credential access, status checks", async () => {
      // Start with locked vault
      mockVaultInitialized = true;
      mockVaultUnlocked = false;

      // Init runtime
      const state = await initSecretStoreRuntime(undefined, {
        autoUnlockFromEnv: false,
      });

      expect(state.initialized).toBe(true);
      expect(state.unlocked).toBe(false);
      expect(isVaultReady()).toBe(false);

      // Simulate vault being unlocked
      mockVaultUnlocked = true;

      // Add credentials
      mockIntegrations.set("google", {
        accessToken: "my-access-token",
        refreshToken: "my-refresh-token",
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
        email: "user@example.com",
        scopes: ["email", "calendar.readonly"],
      });

      // Verify we can now access credentials
      expect(isVaultReady()).toBe(true);

      const credential = getCredentialFromStore("google");
      expect(credential).not.toBeNull();
      expect(credential!.accessToken).toBe("my-access-token");
      expect(credential!.refreshToken).toBe("my-refresh-token");
      expect(credential!.email).toBe("user@example.com");
      expect(credential!.scopes).toEqual(["email", "calendar.readonly"]);

      // List providers
      const providers = listCredentialProviders();
      expect(providers).toHaveLength(1);
      expect(providers[0].provider).toBe("google");
      expect(providers[0].email).toBe("user@example.com");

      // Lock and verify access is denied
      mockVaultUnlocked = false;
      expect(isVaultReady()).toBe(false);
      expect(getCredentialFromStore("google")).toBeNull();
      expect(listCredentialProviders()).toEqual([]);

      state.stop();
    });
  });
});
