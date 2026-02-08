import { describe, expect, it } from "vitest";
import { normalizeTelegramMessagingTarget, looksLikeTelegramTargetId } from "./telegram.js";

describe("telegram target normalization", () => {
  describe("normalizeTelegramMessagingTarget", () => {
    it("returns undefined for empty input", () => {
      expect(normalizeTelegramMessagingTarget("")).toBeUndefined();
      expect(normalizeTelegramMessagingTarget("   ")).toBeUndefined();
    });

    it("normalizes @username targets", () => {
      const result = normalizeTelegramMessagingTarget("@johndoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("normalizes bare usernames (adds telegram: prefix)", () => {
      const result = normalizeTelegramMessagingTarget("johndoe");
      expect(result).toBe("telegram:johndoe");
    });

    it("normalizes numeric chat IDs", () => {
      const result = normalizeTelegramMessagingTarget("123456789");
      expect(result).toBe("telegram:123456789");
    });

    it("normalizes negative group IDs", () => {
      const result = normalizeTelegramMessagingTarget("-100123456789");
      expect(result).toBe("telegram:-100123456789");
    });

    it("strips telegram: prefix and re-adds it normalized", () => {
      const result = normalizeTelegramMessagingTarget("telegram:@johndoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("strips tg: prefix and normalizes", () => {
      const result = normalizeTelegramMessagingTarget("tg:@johndoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("normalizes t.me links", () => {
      const result = normalizeTelegramMessagingTarget("https://t.me/johndoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("normalizes t.me links without protocol", () => {
      const result = normalizeTelegramMessagingTarget("t.me/johndoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("normalizes http t.me links", () => {
      const result = normalizeTelegramMessagingTarget("http://t.me/johndoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("lowercases the result", () => {
      // Note: prefix stripping is case-sensitive, so TELEGRAM: is preserved and lowercased
      const result = normalizeTelegramMessagingTarget("@JohnDoe");
      expect(result).toBe("telegram:@johndoe");
    });

    it("handles uppercase telegram: prefix", () => {
      // Case-sensitive prefix check means TELEGRAM: is not stripped
      const result = normalizeTelegramMessagingTarget("TELEGRAM:@JohnDoe");
      expect(result).toBe("telegram:telegram:@johndoe");
    });

    it("returns undefined for empty after stripping prefix", () => {
      expect(normalizeTelegramMessagingTarget("telegram:")).toBeUndefined();
      expect(normalizeTelegramMessagingTarget("tg:")).toBeUndefined();
    });
  });

  describe("looksLikeTelegramTargetId", () => {
    it("returns false for empty strings", () => {
      expect(looksLikeTelegramTargetId("")).toBe(false);
      expect(looksLikeTelegramTargetId("   ")).toBe(false);
    });

    it("recognizes telegram: prefix", () => {
      expect(looksLikeTelegramTargetId("telegram:@johndoe")).toBe(true);
      expect(looksLikeTelegramTargetId("telegram:123456789")).toBe(true);
    });

    it("recognizes tg: prefix", () => {
      expect(looksLikeTelegramTargetId("tg:@johndoe")).toBe(true);
      expect(looksLikeTelegramTargetId("tg:123456789")).toBe(true);
    });

    it("recognizes @ prefixed usernames", () => {
      expect(looksLikeTelegramTargetId("@johndoe")).toBe(true);
      expect(looksLikeTelegramTargetId("@some_user")).toBe(true);
    });

    it("recognizes numeric chat IDs (6+ digits)", () => {
      expect(looksLikeTelegramTargetId("123456")).toBe(true);
      expect(looksLikeTelegramTargetId("123456789")).toBe(true);
    });

    it("recognizes negative group IDs", () => {
      expect(looksLikeTelegramTargetId("-100123456")).toBe(true);
      expect(looksLikeTelegramTargetId("-123456789")).toBe(true);
    });

    it("rejects short numeric IDs", () => {
      expect(looksLikeTelegramTargetId("12345")).toBe(false);
    });

    it("rejects plain text without @ or prefix", () => {
      expect(looksLikeTelegramTargetId("johndoe")).toBe(false);
      expect(looksLikeTelegramTargetId("some-channel")).toBe(false);
    });
  });
});
