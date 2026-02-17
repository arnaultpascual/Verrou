import { describe, expect, it } from "vitest";
import { formatTotpCode } from "../../../features/entries/formatCode";

describe("formatTotpCode", () => {
  describe("6-digit codes", () => {
    it("formats with 3-digit grouping", () => {
      expect(formatTotpCode("483291", 6)).toBe("483 291");
    });

    it("preserves leading zeros", () => {
      expect(formatTotpCode("012345", 6)).toBe("012 345");
    });

    it("formats all-zeros", () => {
      expect(formatTotpCode("000000", 6)).toBe("000 000");
    });
  });

  describe("8-digit codes", () => {
    it("formats with 4-digit grouping", () => {
      expect(formatTotpCode("48329157", 8)).toBe("4832 9157");
    });

    it("preserves leading zeros", () => {
      expect(formatTotpCode("00123456", 8)).toBe("0012 3456");
    });
  });

  describe("edge cases", () => {
    it("returns raw code if length doesn't match digits", () => {
      expect(formatTotpCode("123", 6)).toBe("123");
    });

    it("returns empty string for empty input", () => {
      expect(formatTotpCode("", 6)).toBe("");
    });
  });
});
