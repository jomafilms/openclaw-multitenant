import { describe, it, expect } from "vitest";
import type { OpenClawConfig } from "../config/config.js";
import type { AgentBinding } from "../config/types.agents.js";
import {
  listBindings,
  listBoundAccountIds,
  resolveDefaultAgentBoundAccountId,
  buildChannelAccountBindings,
  resolvePreferredAccountId,
} from "./bindings.js";

function makeConfig(bindings: AgentBinding[]): OpenClawConfig {
  return { bindings } as OpenClawConfig;
}

describe("bindings", () => {
  describe("listBindings", () => {
    it("should return empty array when bindings is undefined", () => {
      const cfg = {} as OpenClawConfig;
      expect(listBindings(cfg)).toEqual([]);
    });

    it("should return empty array when bindings is not an array", () => {
      const cfg = { bindings: "not-an-array" } as unknown as OpenClawConfig;
      expect(listBindings(cfg)).toEqual([]);
    });

    it("should return bindings array when present", () => {
      const bindings: AgentBinding[] = [
        { agentId: "agent1", match: { channel: "telegram", accountId: "user1" } },
      ];
      const cfg = makeConfig(bindings);
      expect(listBindings(cfg)).toEqual(bindings);
    });
  });

  describe("listBoundAccountIds", () => {
    it("should return empty array when channel is empty", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(listBoundAccountIds(cfg, "")).toEqual([]);
    });

    it("should return empty array when no bindings match channel", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(listBoundAccountIds(cfg, "discord")).toEqual([]);
    });

    it("should return account IDs for matching channel", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
        { agentId: "main", match: { channel: "telegram", accountId: "user2" } },
        { agentId: "main", match: { channel: "discord", accountId: "user3" } },
      ]);
      expect(listBoundAccountIds(cfg, "telegram")).toEqual(["user1", "user2"]);
    });

    it("should normalize channel ID for comparison", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "Telegram", accountId: "user1" } },
      ]);
      expect(listBoundAccountIds(cfg, "telegram")).toEqual(["user1"]);
    });

    it("should skip wildcard account IDs", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "*" } },
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(listBoundAccountIds(cfg, "telegram")).toEqual(["user1"]);
    });

    it("should skip bindings with invalid structure", () => {
      const cfg = makeConfig([
        null as unknown as AgentBinding,
        { agentId: "main" } as AgentBinding,
        { agentId: "main", match: null } as unknown as AgentBinding,
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(listBoundAccountIds(cfg, "telegram")).toEqual(["user1"]);
    });

    it("should deduplicate account IDs", () => {
      const cfg = makeConfig([
        { agentId: "agent1", match: { channel: "telegram", accountId: "user1" } },
        { agentId: "agent2", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(listBoundAccountIds(cfg, "telegram")).toEqual(["user1"]);
    });

    it("should sort account IDs alphabetically", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "zebra" } },
        { agentId: "main", match: { channel: "telegram", accountId: "alpha" } },
      ]);
      expect(listBoundAccountIds(cfg, "telegram")).toEqual(["alpha", "zebra"]);
    });
  });

  describe("resolveDefaultAgentBoundAccountId", () => {
    it("should return null when channel is empty", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(resolveDefaultAgentBoundAccountId(cfg, "")).toBeNull();
    });

    it("should return null when no binding matches default agent", () => {
      const cfg = makeConfig([
        { agentId: "other-agent", match: { channel: "telegram", accountId: "user1" } },
      ]);
      // Default agent is "main"
      expect(resolveDefaultAgentBoundAccountId(cfg, "telegram")).toBeNull();
    });

    it("should return account ID for default agent binding", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(resolveDefaultAgentBoundAccountId(cfg, "telegram")).toBe("user1");
    });

    it("should return first matching account ID", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "first" } },
        { agentId: "main", match: { channel: "telegram", accountId: "second" } },
      ]);
      expect(resolveDefaultAgentBoundAccountId(cfg, "telegram")).toBe("first");
    });

    it("should skip wildcard account IDs", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "*" } },
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      expect(resolveDefaultAgentBoundAccountId(cfg, "telegram")).toBe("user1");
    });
  });

  describe("buildChannelAccountBindings", () => {
    it("should return empty map when no bindings", () => {
      const cfg = makeConfig([]);
      const result = buildChannelAccountBindings(cfg);
      expect(result.size).toBe(0);
    });

    it("should build map of channel -> agent -> accountIds", () => {
      const cfg = makeConfig([
        { agentId: "agent1", match: { channel: "telegram", accountId: "user1" } },
        { agentId: "agent1", match: { channel: "telegram", accountId: "user2" } },
        { agentId: "agent2", match: { channel: "telegram", accountId: "user3" } },
      ]);
      const result = buildChannelAccountBindings(cfg);

      expect(result.size).toBe(1);
      const telegramBindings = result.get("telegram");
      expect(telegramBindings?.get("agent1")).toEqual(["user1", "user2"]);
      expect(telegramBindings?.get("agent2")).toEqual(["user3"]);
    });

    it("should skip invalid bindings", () => {
      const cfg = makeConfig([
        null as unknown as AgentBinding,
        { agentId: "main", match: { channel: "", accountId: "user1" } },
        { agentId: "main", match: { channel: "telegram", accountId: "*" } },
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      const result = buildChannelAccountBindings(cfg);

      expect(result.size).toBe(1);
      expect(result.get("telegram")?.get("main")).toEqual(["user1"]);
    });

    it("should not duplicate account IDs for same agent", () => {
      const cfg = makeConfig([
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
        { agentId: "main", match: { channel: "telegram", accountId: "user1" } },
      ]);
      const result = buildChannelAccountBindings(cfg);

      expect(result.get("telegram")?.get("main")).toEqual(["user1"]);
    });
  });

  describe("resolvePreferredAccountId", () => {
    it("should return first bound account when available", () => {
      const result = resolvePreferredAccountId({
        accountIds: ["account1", "account2"],
        defaultAccountId: "default",
        boundAccounts: ["bound1", "bound2"],
      });
      expect(result).toBe("bound1");
    });

    it("should return default account when no bound accounts", () => {
      const result = resolvePreferredAccountId({
        accountIds: ["account1"],
        defaultAccountId: "default",
        boundAccounts: [],
      });
      expect(result).toBe("default");
    });
  });
});
