import { describe, expect, it } from "vitest";
import { validateWord, suggestWords, validatePhrase } from "../../../features/seed/ipc";

describe("BIP39 IPC mock service", () => {
  describe("validateWord", () => {
    it("returns valid for known BIP39 word", async () => {
      const result = await validateWord("abandon", "english");
      expect(result.valid).toBe(true);
    });

    it("returns invalid for unknown word", async () => {
      const result = await validateWord("xyz123", "english");
      expect(result.valid).toBe(false);
    });

    it("returns valid for last word in mock list", async () => {
      const result = await validateWord("zoo", "english");
      expect(result.valid).toBe(true);
    });

    it("returns invalid for empty string", async () => {
      const result = await validateWord("", "english");
      expect(result.valid).toBe(false);
    });
  });

  describe("suggestWords", () => {
    it("returns suggestions for valid prefix", async () => {
      const results = await suggestWords("aban", "english");
      expect(results.length).toBeGreaterThan(0);
      expect(results).toContain("abandon");
      for (const s of results) {
        expect(s.startsWith("aban")).toBe(true);
      }
    });

    it("respects max limit", async () => {
      const results = await suggestWords("a", "english", 2);
      expect(results.length).toBeLessThanOrEqual(2);
    });

    it("returns empty array for no match", async () => {
      const results = await suggestWords("zzzzzzz", "english");
      expect(results).toEqual([]);
    });

    it("defaults to max 5 suggestions", async () => {
      const results = await suggestWords("a", "english");
      expect(results.length).toBeLessThanOrEqual(5);
    });
  });

  describe("validatePhrase", () => {
    it("returns valid for correct word count with known words", async () => {
      const words = Array(12).fill("abandon");
      const result = await validatePhrase(words, "english");
      expect(result.valid).toBe(true);
    });

    it("returns invalid for wrong word count", async () => {
      const words = ["abandon", "ability", "able"];
      const result = await validatePhrase(words, "english");
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain("word count");
    });

    it("returns invalid when phrase contains unknown word", async () => {
      const words = Array(11).fill("abandon");
      words.push("notaword");
      const result = await validatePhrase(words, "english");
      expect(result.valid).toBe(false);
      expect(result.error).toContain("notaword");
    });
  });
});
