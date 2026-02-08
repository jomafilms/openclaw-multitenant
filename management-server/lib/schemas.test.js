/**
 * Tests for Zod validation schemas
 */
import { describe, it, expect } from "vitest";
import {
  emailSchema,
  uuidSchema,
  passwordSchema,
  vaultPasswordSchema,
  slugSchema,
  base64Schema,
  isoDateSchema,
  permissionsSchema,
  permissionsArraySchema,
  permissionsObjectSchema,
  orgRoleSchema,
  createGroupSchema,
  inviteToGroupSchema,
  createGrantSchema,
  vaultSetupSchema,
  vaultRecoverSchema,
  formatZodError,
  validateBody,
  validateParams,
} from "./schemas.js";

describe("Primitive Schemas", () => {
  describe("emailSchema", () => {
    it("should accept valid emails", () => {
      expect(emailSchema.parse("user@example.com")).toBe("user@example.com");
      expect(emailSchema.parse("USER@EXAMPLE.COM")).toBe("user@example.com"); // lowercased
      expect(emailSchema.parse("  user@example.com  ")).toBe("user@example.com"); // trimmed
    });

    it("should reject invalid emails", () => {
      expect(() => emailSchema.parse("invalid")).toThrow();
      expect(() => emailSchema.parse("invalid@")).toThrow();
      expect(() => emailSchema.parse("@example.com")).toThrow();
      expect(() => emailSchema.parse("")).toThrow();
    });
  });

  describe("uuidSchema", () => {
    it("should accept valid UUIDs", () => {
      expect(uuidSchema.parse("550e8400-e29b-41d4-a716-446655440000")).toBeDefined();
      expect(uuidSchema.parse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")).toBeDefined();
    });

    it("should reject invalid UUIDs", () => {
      expect(() => uuidSchema.parse("not-a-uuid")).toThrow();
      expect(() => uuidSchema.parse("550e8400-e29b-41d4-a716")).toThrow();
      expect(() => uuidSchema.parse("")).toThrow();
    });
  });

  describe("passwordSchema", () => {
    it("should accept passwords with 12+ characters", () => {
      expect(passwordSchema.parse("123456789012")).toBeDefined();
      expect(passwordSchema.parse("a_very_long_password_indeed")).toBeDefined();
    });

    it("should reject short passwords", () => {
      expect(() => passwordSchema.parse("12345678901")).toThrow(); // 11 chars
      expect(() => passwordSchema.parse("")).toThrow();
    });
  });

  describe("vaultPasswordSchema", () => {
    it("should accept passwords with 16+ characters", () => {
      expect(vaultPasswordSchema.parse("1234567890123456")).toBeDefined();
    });

    it("should reject short passwords", () => {
      expect(() => vaultPasswordSchema.parse("123456789012345")).toThrow(); // 15 chars
    });
  });

  describe("slugSchema", () => {
    it("should accept valid slugs", () => {
      expect(slugSchema.parse("my-org")).toBeDefined();
      expect(slugSchema.parse("org123")).toBeDefined();
      expect(slugSchema.parse("test-org-2024")).toBeDefined();
    });

    it("should reject invalid slugs", () => {
      expect(() => slugSchema.parse("My-Org")).toThrow(); // uppercase
      expect(() => slugSchema.parse("my org")).toThrow(); // space
      expect(() => slugSchema.parse("my_org")).toThrow(); // underscore
      expect(() => slugSchema.parse("a")).toThrow(); // too short
    });
  });

  describe("base64Schema", () => {
    it("should accept valid base64", () => {
      expect(base64Schema.parse("SGVsbG8=")).toBeDefined();
      expect(base64Schema.parse("SGVsbG8gV29ybGQ=")).toBeDefined();
      expect(base64Schema.parse("YWJjZGVm")).toBeDefined();
    });

    it("should reject invalid base64", () => {
      expect(() => base64Schema.parse("Hello!")).toThrow(); // has !
      expect(() => base64Schema.parse("SGVsbG8===")).toThrow(); // too many =
    });
  });

  describe("isoDateSchema", () => {
    it("should accept valid ISO dates", () => {
      expect(isoDateSchema.parse("2024-01-15T10:30:00Z")).toBeDefined();
      expect(isoDateSchema.parse("2024-01-15T10:30:00.000Z")).toBeDefined();
    });

    it("should reject invalid dates", () => {
      expect(() => isoDateSchema.parse("2024-01-15")).toThrow(); // missing time
      expect(() => isoDateSchema.parse("not a date")).toThrow();
    });
  });
});

describe("Permission Schemas", () => {
  describe("permissionsArraySchema", () => {
    it("should accept valid permission arrays", () => {
      expect(permissionsArraySchema.parse(["read"])).toEqual(["read"]);
      expect(permissionsArraySchema.parse(["read", "write"])).toEqual(["read", "write"]);
      expect(
        permissionsArraySchema.parse(["read", "write", "delete", "admin", "share", "list"]),
      ).toEqual(["read", "write", "delete", "admin", "share", "list"]);
    });

    it("should reject invalid permissions", () => {
      expect(() => permissionsArraySchema.parse([])).toThrow(); // empty
      expect(() => permissionsArraySchema.parse(["unknown"])).toThrow();
      expect(() => permissionsArraySchema.parse(["read", "execute"])).toThrow();
    });
  });

  describe("permissionsObjectSchema", () => {
    it("should accept valid permission objects", () => {
      expect(permissionsObjectSchema.parse({ read: true })).toBeDefined();
      expect(permissionsObjectSchema.parse({ read: true, write: true })).toBeDefined();
    });

    it("should reject objects with no true permissions", () => {
      expect(() => permissionsObjectSchema.parse({})).toThrow();
      expect(() => permissionsObjectSchema.parse({ read: false })).toThrow();
    });
  });

  describe("permissionsSchema (union)", () => {
    it("should accept both array and object formats", () => {
      expect(permissionsSchema.parse(["read", "write"])).toBeDefined();
      expect(permissionsSchema.parse({ read: true, write: true })).toBeDefined();
    });
  });

  describe("orgRoleSchema", () => {
    it("should accept valid roles", () => {
      expect(orgRoleSchema.parse("member")).toBe("member");
      expect(orgRoleSchema.parse("admin")).toBe("admin");
    });

    it("should reject invalid roles", () => {
      expect(() => orgRoleSchema.parse("owner")).toThrow();
      expect(() => orgRoleSchema.parse("superadmin")).toThrow();
    });
  });
});

describe("Complex Schemas", () => {
  describe("createGroupSchema", () => {
    it("should accept valid org creation data", () => {
      const result = createGroupSchema.parse({
        name: "My Organization",
        slug: "my-org",
        description: "A test organization",
      });
      expect(result.name).toBe("My Organization");
      expect(result.slug).toBe("my-org");
    });

    it("should reject missing required fields", () => {
      expect(() => createGroupSchema.parse({ name: "My Org" })).toThrow(); // missing slug
      expect(() => createGroupSchema.parse({ slug: "my-org" })).toThrow(); // missing name
    });
  });

  describe("inviteToGroupSchema", () => {
    it("should accept valid invite data", () => {
      const result = inviteToGroupSchema.parse({
        email: "user@example.com",
        role: "member",
      });
      expect(result.email).toBe("user@example.com");
      expect(result.role).toBe("member");
    });

    it("should use default role", () => {
      const result = inviteToGroupSchema.parse({ email: "user@example.com" });
      expect(result.role).toBe("member");
    });

    it("should reject invalid email", () => {
      expect(() => inviteToGroupSchema.parse({ email: "invalid" })).toThrow();
    });
  });

  describe("createGrantSchema", () => {
    it("should accept valid grant data", () => {
      const result = createGrantSchema.parse({
        resourceId: "550e8400-e29b-41d4-a716-446655440000",
        userId: "550e8400-e29b-41d4-a716-446655440001",
        permissions: { read: true, write: true },
      });
      expect(result.resourceId).toBeDefined();
      expect(result.userId).toBeDefined();
    });

    it("should reject invalid UUIDs", () => {
      expect(() =>
        createGrantSchema.parse({
          resourceId: "not-a-uuid",
          userId: "550e8400-e29b-41d4-a716-446655440001",
        }),
      ).toThrow();
    });
  });

  describe("vaultSetupSchema", () => {
    it("should accept valid password", () => {
      const result = vaultSetupSchema.parse({ password: "123456789012" });
      expect(result.password).toBe("123456789012");
    });

    it("should reject short password", () => {
      expect(() => vaultSetupSchema.parse({ password: "12345678901" })).toThrow();
    });
  });

  describe("vaultRecoverSchema", () => {
    it("should accept valid recovery data", () => {
      const result = vaultRecoverSchema.parse({
        recoveryPhrase:
          "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12",
        newPassword: "123456789012",
      });
      expect(result.recoveryPhrase).toBeDefined();
    });

    it("should reject short recovery phrase", () => {
      expect(() =>
        vaultRecoverSchema.parse({
          recoveryPhrase: "word1 word2 word3",
          newPassword: "123456789012",
        }),
      ).toThrow();
    });
  });
});

describe("Validation Helpers", () => {
  describe("formatZodError", () => {
    it("should format errors with paths", () => {
      const result = emailSchema.safeParse("invalid");
      if (!result.success) {
        const formatted = formatZodError(result.error);
        expect(formatted).toContain("email");
      }
    });

    it("should join multiple errors", () => {
      const result = createGroupSchema.safeParse({});
      if (!result.success) {
        const formatted = formatZodError(result.error);
        expect(formatted).toContain(";");
      }
    });
  });

  describe("validateBody", () => {
    it("should return success with valid data", () => {
      const result = validateBody(vaultSetupSchema, { password: "123456789012" });
      expect(result.success).toBe(true);
      expect(result.data.password).toBe("123456789012");
    });

    it("should return error with invalid data", () => {
      const result = validateBody(vaultSetupSchema, { password: "short" });
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe("validateParams", () => {
    it("should validate params successfully", async () => {
      // Use the actual schema approach
      const { z } = await import("zod");
      const testParamSchema = z.object({ id: uuidSchema });
      const result = validateParams(testParamSchema, {
        id: "550e8400-e29b-41d4-a716-446655440000",
      });
      expect(result.success).toBe(true);
    });
  });
});
