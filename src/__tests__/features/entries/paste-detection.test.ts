import { describe, it, expect } from "vitest";
import { detectPasteType } from "../../../features/entries/paste-detection";

describe("detectPasteType", () => {
  describe("URI detection", () => {
    it("detects a valid otpauth:// TOTP URI", () => {
      const result = detectPasteType(
        "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
      );
      expect(result.type).toBe("uri");
      if (result.type === "uri") {
        expect(result.parsed.name).toBe("user@example.com");
        expect(result.parsed.issuer).toBe("GitHub");
        expect(result.parsed.secret).toBe("JBSWY3DPEHPK3PXP");
      }
    });

    it("detects a valid otpauth:// HOTP URI", () => {
      const result = detectPasteType(
        "otpauth://hotp/Service:admin?secret=GEZDGNBVGY3TQOJQ&counter=5",
      );
      expect(result.type).toBe("uri");
      if (result.type === "uri") {
        expect(result.parsed.type).toBe("hotp");
        expect(result.parsed.counter).toBe(5);
      }
    });

    it("returns unknown for otpauth URI without secret", () => {
      const result = detectPasteType("otpauth://totp/Test?issuer=Test");
      expect(result.type).toBe("unknown");
    });

    it("trims whitespace before detecting URI", () => {
      const result = detectPasteType(
        "  otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP  ",
      );
      expect(result.type).toBe("uri");
    });
  });

  describe("Base32 detection", () => {
    it("detects a valid Base32 key", () => {
      const result = detectPasteType("JBSWY3DPEHPK3PXP");
      expect(result.type).toBe("base32");
      if (result.type === "base32") {
        expect(result.secret).toBe("JBSWY3DPEHPK3PXP");
      }
    });

    it("detects lowercase Base32 and normalizes to uppercase", () => {
      const result = detectPasteType("jbswy3dpehpk3pxp");
      expect(result.type).toBe("base32");
      if (result.type === "base32") {
        expect(result.secret).toBe("JBSWY3DPEHPK3PXP");
      }
    });

    it("detects Base32 with spaces (common copy-paste format)", () => {
      const result = detectPasteType("JBSW Y3DP EHPK 3PXP");
      expect(result.type).toBe("base32");
      if (result.type === "base32") {
        expect(result.secret).toBe("JBSWY3DPEHPK3PXP");
      }
    });

    it("detects Base32 with trailing padding", () => {
      const result = detectPasteType("MFRA====");
      expect(result.type).toBe("base32");
    });

    it("trims whitespace before detecting Base32", () => {
      const result = detectPasteType("  JBSWY3DPEHPK3PXP  ");
      expect(result.type).toBe("base32");
    });
  });

  describe("unknown / invalid input", () => {
    it("returns unknown for empty string", () => {
      expect(detectPasteType("").type).toBe("unknown");
    });

    it("returns unknown for whitespace only", () => {
      expect(detectPasteType("   ").type).toBe("unknown");
    });

    it("returns unknown for random text", () => {
      expect(detectPasteType("hello world!").type).toBe("unknown");
    });

    it("returns unknown for a regular URL", () => {
      expect(detectPasteType("https://example.com").type).toBe("unknown");
    });

    it("returns unknown for numeric string", () => {
      expect(detectPasteType("123456").type).toBe("unknown");
    });
  });
});
