import { describe, expect, it } from "vitest";
import { normalizeSlackMessagingTarget, looksLikeSlackTargetId } from "./slack.js";

describe("slack target normalization", () => {
  describe("normalizeSlackMessagingTarget", () => {
    it("returns undefined for empty input", () => {
      expect(normalizeSlackMessagingTarget("")).toBeUndefined();
      expect(normalizeSlackMessagingTarget("   ")).toBeUndefined();
    });

    it("normalizes user mentions", () => {
      const result = normalizeSlackMessagingTarget("<@U123ABC456>");
      // ID is lowercased in normalized output
      expect(result).toBe("user:u123abc456");
    });

    it("normalizes user: prefixed targets", () => {
      const result = normalizeSlackMessagingTarget("user:U123ABC456");
      expect(result).toBe("user:u123abc456");
    });

    it("normalizes channel: prefixed targets", () => {
      const result = normalizeSlackMessagingTarget("channel:C123ABC456");
      expect(result).toBe("channel:c123abc456");
    });

    it("normalizes slack: prefixed targets as user", () => {
      const result = normalizeSlackMessagingTarget("slack:U123ABC456");
      expect(result).toBe("user:u123abc456");
    });

    it("normalizes @ prefixed IDs as user", () => {
      const result = normalizeSlackMessagingTarget("@U123ABC456");
      expect(result).toBe("user:u123abc456");
    });

    it("normalizes # prefixed IDs as channel", () => {
      const result = normalizeSlackMessagingTarget("#C123ABC456");
      expect(result).toBe("channel:c123abc456");
    });

    it("defaults unrecognized strings to channel", () => {
      const result = normalizeSlackMessagingTarget("C123ABC456");
      expect(result).toBe("channel:c123abc456");
    });
  });

  describe("looksLikeSlackTargetId", () => {
    it("returns false for empty strings", () => {
      expect(looksLikeSlackTargetId("")).toBe(false);
      expect(looksLikeSlackTargetId("   ")).toBe(false);
    });

    it("recognizes user mentions", () => {
      expect(looksLikeSlackTargetId("<@U123ABC456>")).toBe(true);
      expect(looksLikeSlackTargetId("<@u123abc456>")).toBe(true);
    });

    it("recognizes user: prefix", () => {
      expect(looksLikeSlackTargetId("user:U123ABC456")).toBe(true);
    });

    it("recognizes channel: prefix", () => {
      expect(looksLikeSlackTargetId("channel:C123ABC456")).toBe(true);
    });

    it("recognizes slack: prefix", () => {
      expect(looksLikeSlackTargetId("slack:U123ABC456")).toBe(true);
    });

    it("recognizes @ prefixed targets", () => {
      expect(looksLikeSlackTargetId("@U123ABC456")).toBe(true);
    });

    it("recognizes # prefixed targets", () => {
      expect(looksLikeSlackTargetId("#C123ABC456")).toBe(true);
    });

    it("recognizes Slack channel IDs (C prefix)", () => {
      expect(looksLikeSlackTargetId("C123ABC456")).toBe(true);
      expect(looksLikeSlackTargetId("C12345678")).toBe(true);
    });

    it("recognizes Slack user IDs (U prefix)", () => {
      expect(looksLikeSlackTargetId("U123ABC456")).toBe(true);
    });

    it("recognizes Slack workspace IDs (W prefix)", () => {
      expect(looksLikeSlackTargetId("W123ABC456")).toBe(true);
    });

    it("recognizes Slack DM IDs (D prefix)", () => {
      expect(looksLikeSlackTargetId("D123ABC456")).toBe(true);
    });

    it("recognizes Slack group IDs (G prefix)", () => {
      expect(looksLikeSlackTargetId("G123ABC456")).toBe(true);
    });

    it("rejects short IDs", () => {
      expect(looksLikeSlackTargetId("C1234567")).toBe(false);
    });

    it("rejects plain text", () => {
      expect(looksLikeSlackTargetId("general")).toBe(false);
      expect(looksLikeSlackTargetId("random")).toBe(false);
    });

    it("rejects malformed mentions", () => {
      expect(looksLikeSlackTargetId("<@>")).toBe(false);
    });
  });
});
