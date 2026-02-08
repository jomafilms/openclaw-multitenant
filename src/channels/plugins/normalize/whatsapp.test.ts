import { describe, expect, it } from "vitest";
import { normalizeWhatsAppMessagingTarget, looksLikeWhatsAppTargetId } from "./whatsapp.js";

describe("whatsapp target normalization", () => {
  describe("normalizeWhatsAppMessagingTarget", () => {
    it("returns undefined for empty input", () => {
      expect(normalizeWhatsAppMessagingTarget("")).toBeUndefined();
      expect(normalizeWhatsAppMessagingTarget("   ")).toBeUndefined();
    });

    it("normalizes phone numbers to E164", () => {
      const result = normalizeWhatsAppMessagingTarget("+1234567890");
      expect(result).toBe("+1234567890");
    });

    it("normalizes phone numbers without plus", () => {
      const result = normalizeWhatsAppMessagingTarget("1234567890");
      expect(result).toBe("+1234567890");
    });

    it("normalizes group JIDs", () => {
      const result = normalizeWhatsAppMessagingTarget("120363123456789@g.us");
      expect(result).toBe("120363123456789@g.us");
    });

    it("strips whatsapp: prefix and normalizes", () => {
      const result = normalizeWhatsAppMessagingTarget("whatsapp:+1234567890");
      expect(result).toBe("+1234567890");
    });

    it("normalizes user JIDs to phone number", () => {
      const result = normalizeWhatsAppMessagingTarget("41796666864:0@s.whatsapp.net");
      expect(result).toBe("+41796666864");
    });

    it("normalizes LID format", () => {
      const result = normalizeWhatsAppMessagingTarget("123456@lid");
      expect(result).toBe("+123456");
    });

    it("returns undefined for unrecognized @ format", () => {
      // Strings with @ that aren't recognized JID formats should return null
      const result = normalizeWhatsAppMessagingTarget("invalid@unknown");
      expect(result).toBeUndefined();
    });

    it("normalizes group JIDs with dashes", () => {
      const result = normalizeWhatsAppMessagingTarget("120363-123456@g.us");
      expect(result).toBe("120363-123456@g.us");
    });
  });

  describe("looksLikeWhatsAppTargetId", () => {
    it("returns false for empty strings", () => {
      expect(looksLikeWhatsAppTargetId("")).toBe(false);
      expect(looksLikeWhatsAppTargetId("   ")).toBe(false);
    });

    it("recognizes whatsapp: prefix", () => {
      expect(looksLikeWhatsAppTargetId("whatsapp:+1234567890")).toBe(true);
      expect(looksLikeWhatsAppTargetId("WHATSAPP:+1234567890")).toBe(true);
    });

    it("recognizes strings with @ (JIDs)", () => {
      expect(looksLikeWhatsAppTargetId("123456@s.whatsapp.net")).toBe(true);
      expect(looksLikeWhatsAppTargetId("123456@g.us")).toBe(true);
      expect(looksLikeWhatsAppTargetId("user@example")).toBe(true);
    });

    it("recognizes phone numbers with +", () => {
      expect(looksLikeWhatsAppTargetId("+1234567890")).toBe(true);
      expect(looksLikeWhatsAppTargetId("+123")).toBe(true);
    });

    it("recognizes numeric strings (3+ digits)", () => {
      expect(looksLikeWhatsAppTargetId("123")).toBe(true);
      expect(looksLikeWhatsAppTargetId("1234567890")).toBe(true);
    });

    it("rejects very short numeric strings", () => {
      expect(looksLikeWhatsAppTargetId("12")).toBe(false);
      expect(looksLikeWhatsAppTargetId("1")).toBe(false);
    });

    it("rejects plain text without special markers", () => {
      expect(looksLikeWhatsAppTargetId("johndoe")).toBe(false);
      expect(looksLikeWhatsAppTargetId("some-name")).toBe(false);
    });
  });
});
