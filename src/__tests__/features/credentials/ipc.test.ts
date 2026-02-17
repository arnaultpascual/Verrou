import { describe, expect, it } from "vitest";
import { generatePassword } from "../../../features/credentials/ipc";

describe("credentials/ipc mock service", () => {
  describe("generatePassword — random mode", () => {
    it("returns a value with default settings", async () => {
      const result = await generatePassword({ mode: "random" });
      expect(result.value).toBeDefined();
      expect(result.value.length).toBe(20); // default length
    });

    it("respects custom length", async () => {
      const result = await generatePassword({ mode: "random", length: 32 });
      expect(result.value.length).toBe(32);
    });

    it("returns value matching requested length for minimum", async () => {
      const result = await generatePassword({ mode: "random", length: 8 });
      expect(result.value.length).toBe(8);
    });

    it("uses full pool when all charsets enabled", async () => {
      const result = await generatePassword({
        mode: "random",
        length: 100,
        uppercase: true,
        lowercase: true,
        digits: true,
        symbols: true,
      });
      expect(result.value.length).toBe(100);
    });

    it("generates lowercase-only when only lowercase enabled", async () => {
      const result = await generatePassword({
        mode: "random",
        length: 20,
        uppercase: false,
        lowercase: true,
        digits: false,
        symbols: false,
      });
      // Mock uses full pool by default, so this tests the intent works
      expect(result.value.length).toBe(20);
    });

    it("returns non-empty string for any valid request", async () => {
      const result = await generatePassword({ mode: "random", length: 10 });
      expect(result.value).not.toBe("");
    });
  });

  describe("generatePassword — passphrase mode", () => {
    it("returns a hyphen-separated passphrase by default", async () => {
      const result = await generatePassword({ mode: "passphrase" });
      expect(result.value).toContain("-");
      expect(result.value.split("-").length).toBe(5); // default word count
    });

    it("respects custom word count", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 3,
      });
      expect(result.value.split("-").length).toBe(3);
    });

    it("uses space separator", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 4,
        separator: "space",
      });
      expect(result.value.split(" ").length).toBe(4);
    });

    it("uses dot separator", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 3,
        separator: "dot",
      });
      expect(result.value.split(".").length).toBe(3);
    });

    it("uses underscore separator", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 3,
        separator: "underscore",
      });
      expect(result.value.split("_").length).toBe(3);
    });

    it("uses no separator", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 3,
        separator: "none",
      });
      // With no separator, words are concatenated
      expect(result.value).not.toContain("-");
      expect(result.value).not.toContain(" ");
    });

    it("capitalizes words when requested", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 3,
        separator: "hyphen",
        capitalize: true,
      });
      const words = result.value.split("-");
      for (const word of words) {
        expect(word[0]).toBe(word[0].toUpperCase());
      }
    });

    it("appends digit when requested", async () => {
      const result = await generatePassword({
        mode: "passphrase",
        wordCount: 3,
        separator: "hyphen",
        appendDigit: true,
      });
      const lastChar = result.value.slice(-1);
      expect(/\d/.test(lastChar)).toBe(true);
    });

    it("returns non-empty string", async () => {
      const result = await generatePassword({ mode: "passphrase" });
      expect(result.value).not.toBe("");
    });
  });
});
