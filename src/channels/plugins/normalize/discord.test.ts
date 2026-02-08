import { describe, expect, it } from "vitest";
import { normalizeDiscordMessagingTarget, looksLikeDiscordTargetId } from "./discord.js";

describe("discord target normalization", () => {
  describe("normalizeDiscordMessagingTarget", () => {
    it("returns undefined for empty input", () => {
      expect(normalizeDiscordMessagingTarget("")).toBeUndefined();
      expect(normalizeDiscordMessagingTarget("   ")).toBeUndefined();
    });

    it("normalizes user mentions", () => {
      const result = normalizeDiscordMessagingTarget("<@123456789>");
      expect(result).toBe("user:123456789");
    });

    it("normalizes user mentions with exclamation mark", () => {
      const result = normalizeDiscordMessagingTarget("<@!123456789>");
      expect(result).toBe("user:123456789");
    });

    it("normalizes user: prefixed targets", () => {
      const result = normalizeDiscordMessagingTarget("user:987654321");
      expect(result).toBe("user:987654321");
    });

    it("normalizes channel: prefixed targets", () => {
      const result = normalizeDiscordMessagingTarget("channel:123456789");
      expect(result).toBe("channel:123456789");
    });

    it("normalizes discord: prefixed targets as user", () => {
      const result = normalizeDiscordMessagingTarget("discord:123456789");
      expect(result).toBe("user:123456789");
    });

    it("defaults bare numeric IDs to channel", () => {
      // The normalizer uses defaultKind: "channel" for bare IDs
      const result = normalizeDiscordMessagingTarget("123456789012345678");
      expect(result).toBe("channel:123456789012345678");
    });

    it("normalizes @ prefixed numeric IDs as user", () => {
      const result = normalizeDiscordMessagingTarget("@123456789");
      expect(result).toBe("user:123456789");
    });

    it("treats non-numeric strings as channel names", () => {
      const result = normalizeDiscordMessagingTarget("general");
      expect(result).toBe("channel:general");
    });
  });

  describe("looksLikeDiscordTargetId", () => {
    it("returns false for empty strings", () => {
      expect(looksLikeDiscordTargetId("")).toBe(false);
      expect(looksLikeDiscordTargetId("   ")).toBe(false);
    });

    it("recognizes user mentions", () => {
      expect(looksLikeDiscordTargetId("<@123456789>")).toBe(true);
      expect(looksLikeDiscordTargetId("<@!123456789>")).toBe(true);
    });

    it("recognizes user: prefix", () => {
      expect(looksLikeDiscordTargetId("user:123456789")).toBe(true);
    });

    it("recognizes channel: prefix", () => {
      expect(looksLikeDiscordTargetId("channel:123456789")).toBe(true);
    });

    it("recognizes discord: prefix", () => {
      expect(looksLikeDiscordTargetId("discord:123456789")).toBe(true);
    });

    it("recognizes numeric IDs (6+ digits)", () => {
      expect(looksLikeDiscordTargetId("123456")).toBe(true);
      expect(looksLikeDiscordTargetId("123456789012345678")).toBe(true);
    });

    it("rejects short numeric IDs", () => {
      expect(looksLikeDiscordTargetId("12345")).toBe(false);
    });

    it("rejects plain text", () => {
      expect(looksLikeDiscordTargetId("general")).toBe(false);
      expect(looksLikeDiscordTargetId("some-channel")).toBe(false);
    });

    it("rejects malformed mentions", () => {
      expect(looksLikeDiscordTargetId("<@>")).toBe(false);
      expect(looksLikeDiscordTargetId("<@abc>")).toBe(false);
    });
  });
});
