import { describe, it, expect } from "vitest";
import {
  DEFAULT_AGENT_ID,
  DEFAULT_MAIN_KEY,
  DEFAULT_ACCOUNT_ID,
  normalizeMainKey,
  toAgentRequestSessionKey,
  toAgentStoreSessionKey,
  resolveAgentIdFromSessionKey,
  normalizeAgentId,
  sanitizeAgentId,
  normalizeAccountId,
  buildAgentMainSessionKey,
  buildAgentPeerSessionKey,
  buildGroupHistoryKey,
  resolveThreadSessionKeys,
  classifySessionKeyShape,
} from "./session-key.js";

describe("session-key", () => {
  describe("constants", () => {
    it("should have expected default values", () => {
      expect(DEFAULT_AGENT_ID).toBe("main");
      expect(DEFAULT_MAIN_KEY).toBe("main");
      expect(DEFAULT_ACCOUNT_ID).toBe("default");
    });
  });

  describe("normalizeMainKey", () => {
    it("should return DEFAULT_MAIN_KEY for empty/null/undefined", () => {
      expect(normalizeMainKey(null)).toBe(DEFAULT_MAIN_KEY);
      expect(normalizeMainKey(undefined)).toBe(DEFAULT_MAIN_KEY);
      expect(normalizeMainKey("")).toBe(DEFAULT_MAIN_KEY);
      expect(normalizeMainKey("   ")).toBe(DEFAULT_MAIN_KEY);
    });

    it("should lowercase and trim the value", () => {
      expect(normalizeMainKey("  MyKey  ")).toBe("mykey");
      expect(normalizeMainKey("TEST")).toBe("test");
    });
  });

  describe("normalizeAgentId", () => {
    it("should return DEFAULT_AGENT_ID for empty/null/undefined", () => {
      expect(normalizeAgentId(null)).toBe(DEFAULT_AGENT_ID);
      expect(normalizeAgentId(undefined)).toBe(DEFAULT_AGENT_ID);
      expect(normalizeAgentId("")).toBe(DEFAULT_AGENT_ID);
      expect(normalizeAgentId("   ")).toBe(DEFAULT_AGENT_ID);
    });

    it("should lowercase valid IDs", () => {
      expect(normalizeAgentId("MyAgent")).toBe("myagent");
      expect(normalizeAgentId("agent-1")).toBe("agent-1");
      expect(normalizeAgentId("agent_2")).toBe("agent_2");
    });

    it("should preserve valid IDs with numbers", () => {
      expect(normalizeAgentId("agent123")).toBe("agent123");
      expect(normalizeAgentId("123agent")).toBe("123agent");
    });

    it("should sanitize invalid characters", () => {
      expect(normalizeAgentId("my.agent")).toBe("my-agent");
      expect(normalizeAgentId("my agent")).toBe("my-agent");
      expect(normalizeAgentId("my@agent#test")).toBe("my-agent-test");
    });

    it("should remove leading/trailing dashes from sanitized IDs", () => {
      expect(normalizeAgentId("--test--")).toBe("test");
      expect(normalizeAgentId("@test@")).toBe("test");
    });

    it("should truncate to 64 characters", () => {
      const longId = "a".repeat(100);
      expect(normalizeAgentId(longId).length).toBe(64);
    });

    it("should return DEFAULT_AGENT_ID if sanitized result is empty", () => {
      expect(normalizeAgentId("@@@")).toBe(DEFAULT_AGENT_ID);
      expect(normalizeAgentId("---")).toBe(DEFAULT_AGENT_ID);
    });
  });

  describe("sanitizeAgentId", () => {
    it("should behave like normalizeAgentId", () => {
      expect(sanitizeAgentId(null)).toBe(DEFAULT_AGENT_ID);
      expect(sanitizeAgentId("MyAgent")).toBe("myagent");
      expect(sanitizeAgentId("my.agent")).toBe("my-agent");
    });
  });

  describe("normalizeAccountId", () => {
    it("should return DEFAULT_ACCOUNT_ID for empty/null/undefined", () => {
      expect(normalizeAccountId(null)).toBe(DEFAULT_ACCOUNT_ID);
      expect(normalizeAccountId(undefined)).toBe(DEFAULT_ACCOUNT_ID);
      expect(normalizeAccountId("")).toBe(DEFAULT_ACCOUNT_ID);
    });

    it("should lowercase valid account IDs", () => {
      expect(normalizeAccountId("User123")).toBe("user123");
      expect(normalizeAccountId("user-name")).toBe("user-name");
    });

    it("should sanitize invalid characters", () => {
      expect(normalizeAccountId("user@email.com")).toBe("user-email-com");
    });
  });

  describe("buildAgentMainSessionKey", () => {
    it("should build key with default main key", () => {
      expect(buildAgentMainSessionKey({ agentId: "test" })).toBe("agent:test:main");
    });

    it("should build key with custom main key", () => {
      expect(buildAgentMainSessionKey({ agentId: "test", mainKey: "custom" })).toBe(
        "agent:test:custom",
      );
    });

    it("should normalize agent ID and main key", () => {
      expect(buildAgentMainSessionKey({ agentId: "TEST", mainKey: "KEY" })).toBe("agent:test:key");
    });
  });

  describe("toAgentRequestSessionKey", () => {
    it("should return undefined for empty input", () => {
      expect(toAgentRequestSessionKey(null)).toBeUndefined();
      expect(toAgentRequestSessionKey("")).toBeUndefined();
      expect(toAgentRequestSessionKey("  ")).toBeUndefined();
    });

    it("should extract rest from agent session key", () => {
      expect(toAgentRequestSessionKey("agent:test:main")).toBe("main");
      expect(toAgentRequestSessionKey("agent:test:custom:extra")).toBe("custom:extra");
    });

    it("should return original if not parseable as agent key", () => {
      expect(toAgentRequestSessionKey("not-an-agent-key")).toBe("not-an-agent-key");
    });
  });

  describe("toAgentStoreSessionKey", () => {
    it("should build main session key for empty request key", () => {
      expect(toAgentStoreSessionKey({ agentId: "test", requestKey: "" })).toBe("agent:test:main");
      expect(toAgentStoreSessionKey({ agentId: "test", requestKey: null })).toBe("agent:test:main");
    });

    it("should build main session key for 'main' request key", () => {
      expect(toAgentStoreSessionKey({ agentId: "test", requestKey: "main" })).toBe(
        "agent:test:main",
      );
    });

    it("should preserve agent: prefixed keys", () => {
      expect(toAgentStoreSessionKey({ agentId: "test", requestKey: "agent:other:key" })).toBe(
        "agent:other:key",
      );
    });

    it("should wrap subagent: prefixed keys", () => {
      expect(toAgentStoreSessionKey({ agentId: "test", requestKey: "subagent:child:key" })).toBe(
        "agent:test:subagent:child:key",
      );
    });

    it("should wrap other keys with agent prefix", () => {
      expect(toAgentStoreSessionKey({ agentId: "test", requestKey: "custom-key" })).toBe(
        "agent:test:custom-key",
      );
    });
  });

  describe("resolveAgentIdFromSessionKey", () => {
    it("should return DEFAULT_AGENT_ID for empty/invalid keys", () => {
      expect(resolveAgentIdFromSessionKey(null)).toBe(DEFAULT_AGENT_ID);
      expect(resolveAgentIdFromSessionKey("")).toBe(DEFAULT_AGENT_ID);
      expect(resolveAgentIdFromSessionKey("invalid")).toBe(DEFAULT_AGENT_ID);
    });

    it("should extract agent ID from valid session key", () => {
      expect(resolveAgentIdFromSessionKey("agent:myagent:main")).toBe("myagent");
      expect(resolveAgentIdFromSessionKey("agent:test:custom:extra")).toBe("test");
    });
  });

  describe("buildAgentPeerSessionKey", () => {
    it("should build main session key for DM with main scope", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: "dm",
        peerId: "user123",
        dmScope: "main",
      });
      expect(result).toBe("agent:test:main");
    });

    it("should build per-peer session key for DM", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: "dm",
        peerId: "USER123",
        dmScope: "per-peer",
      });
      expect(result).toBe("agent:test:dm:user123");
    });

    it("should build per-channel-peer session key for DM", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: "dm",
        peerId: "user123",
        dmScope: "per-channel-peer",
      });
      expect(result).toBe("agent:test:telegram:dm:user123");
    });

    it("should build per-account-channel-peer session key for DM", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        accountId: "myaccount",
        peerKind: "dm",
        peerId: "user123",
        dmScope: "per-account-channel-peer",
      });
      expect(result).toBe("agent:test:telegram:myaccount:dm:user123");
    });

    it("should build group session key", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: "group",
        peerId: "group123",
      });
      expect(result).toBe("agent:test:telegram:group:group123");
    });

    it("should build channel session key", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "discord",
        peerKind: "channel",
        peerId: "channel456",
      });
      expect(result).toBe("agent:test:discord:channel:channel456");
    });

    it("should default to dm when peerKind is null", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: null,
        peerId: "user123",
        dmScope: "per-peer",
      });
      expect(result).toBe("agent:test:dm:user123");
    });

    it("should use identity links for peer resolution", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: "dm",
        peerId: "telegram:user123",
        dmScope: "per-peer",
        identityLinks: {
          canonical_user: ["telegram:user123", "discord:user456"],
        },
      });
      expect(result).toBe("agent:test:dm:canonical_user");
    });

    it("should handle empty peer ID", () => {
      const result = buildAgentPeerSessionKey({
        agentId: "test",
        channel: "telegram",
        peerKind: "dm",
        peerId: "",
        dmScope: "per-peer",
      });
      // Empty peerId falls back to main session
      expect(result).toBe("agent:test:main");
    });
  });

  describe("buildGroupHistoryKey", () => {
    it("should build group history key", () => {
      const result = buildGroupHistoryKey({
        channel: "telegram",
        accountId: "myaccount",
        peerKind: "group",
        peerId: "group123",
      });
      expect(result).toBe("telegram:myaccount:group:group123");
    });

    it("should normalize all parts", () => {
      const result = buildGroupHistoryKey({
        channel: "TELEGRAM",
        accountId: null,
        peerKind: "channel",
        peerId: "  CHANNEL456  ",
      });
      expect(result).toBe("telegram:default:channel:channel456");
    });

    it("should use 'unknown' for empty channel/peerId", () => {
      const result = buildGroupHistoryKey({
        channel: "",
        peerKind: "group",
        peerId: "",
      });
      expect(result).toBe("unknown:default:group:unknown");
    });
  });

  describe("resolveThreadSessionKeys", () => {
    it("should return base key when no thread ID", () => {
      const result = resolveThreadSessionKeys({
        baseSessionKey: "agent:test:main",
        threadId: null,
      });
      expect(result).toEqual({
        sessionKey: "agent:test:main",
        parentSessionKey: undefined,
      });
    });

    it("should return base key for empty thread ID", () => {
      const result = resolveThreadSessionKeys({
        baseSessionKey: "agent:test:main",
        threadId: "",
      });
      expect(result).toEqual({
        sessionKey: "agent:test:main",
        parentSessionKey: undefined,
      });
    });

    it("should append thread suffix when useSuffix is true", () => {
      const result = resolveThreadSessionKeys({
        baseSessionKey: "agent:test:main",
        threadId: "thread123",
        useSuffix: true,
      });
      expect(result).toEqual({
        sessionKey: "agent:test:main:thread:thread123",
        parentSessionKey: undefined,
      });
    });

    it("should not append suffix when useSuffix is false", () => {
      const result = resolveThreadSessionKeys({
        baseSessionKey: "agent:test:main",
        threadId: "thread123",
        useSuffix: false,
      });
      expect(result).toEqual({
        sessionKey: "agent:test:main",
        parentSessionKey: undefined,
      });
    });

    it("should include parent session key when provided", () => {
      const result = resolveThreadSessionKeys({
        baseSessionKey: "agent:test:main",
        threadId: "thread123",
        parentSessionKey: "agent:test:parent",
      });
      expect(result).toEqual({
        sessionKey: "agent:test:main:thread:thread123",
        parentSessionKey: "agent:test:parent",
      });
    });

    it("should lowercase thread ID", () => {
      const result = resolveThreadSessionKeys({
        baseSessionKey: "agent:test:main",
        threadId: "THREAD123",
      });
      expect(result.sessionKey).toBe("agent:test:main:thread:thread123");
    });
  });

  describe("classifySessionKeyShape", () => {
    it("classifies empty keys as missing", () => {
      expect(classifySessionKeyShape(undefined)).toBe("missing");
      expect(classifySessionKeyShape("   ")).toBe("missing");
    });

    it("classifies valid agent keys", () => {
      expect(classifySessionKeyShape("agent:main:main")).toBe("agent");
      expect(classifySessionKeyShape("agent:research:subagent:worker")).toBe("agent");
    });

    it("classifies malformed agent keys", () => {
      expect(classifySessionKeyShape("agent::broken")).toBe("malformed_agent");
      expect(classifySessionKeyShape("agent:main")).toBe("malformed_agent");
    });

    it("treats non-agent legacy or alias keys as non-malformed", () => {
      expect(classifySessionKeyShape("main")).toBe("legacy_or_alias");
      expect(classifySessionKeyShape("custom-main")).toBe("legacy_or_alias");
      expect(classifySessionKeyShape("subagent:worker")).toBe("legacy_or_alias");
    });
  });
});
