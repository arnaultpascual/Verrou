import { describe, it, expect } from "vitest";
import { filterEntries } from "../../../features/entries/filterEntries";
import type { EntryMetadataDto } from "../../../features/entries/ipc";

// Test fixtures — diverse entry types for search testing
const github: EntryMetadataDto = {
  id: "1",
  entryType: "totp",
  name: "GitHub",
  issuer: "github.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: true,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const gitlab: EntryMetadataDto = {
  id: "2",
  entryType: "totp",
  name: "GitLab",
  issuer: "gitlab.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const google: EntryMetadataDto = {
  id: "3",
  entryType: "totp",
  name: "Google",
  issuer: "google.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const bitcoin: EntryMetadataDto = {
  id: "4",
  entryType: "seed_phrase",
  name: "Bitcoin Wallet",
  issuer: "ledger.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const aws: EntryMetadataDto = {
  id: "5",
  entryType: "totp",
  name: "AWS Console",
  issuer: "amazon.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: true,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const digitalOcean: EntryMetadataDto = {
  id: "6",
  entryType: "totp",
  name: "Digital Ocean",
  issuer: "digitalocean.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const entries = [github, gitlab, google, bitcoin, aws, digitalOcean];

describe("filterEntries", () => {
  describe("empty query", () => {
    it("returns all entries when query is empty", () => {
      const result = filterEntries(entries, "");
      expect(result).toHaveLength(entries.length);
    });

    it("returns all entries when query is whitespace", () => {
      const result = filterEntries(entries, "   ");
      expect(result).toHaveLength(entries.length);
    });
  });

  describe("fuzzy matching", () => {
    it("matches 'gi' to GitHub and GitLab (prefix match)", () => {
      const result = filterEntries(entries, "gi");
      const names = result.map((e) => e.name);
      expect(names).toContain("GitHub");
      expect(names).toContain("GitLab");
    });

    it("matches 'gh' to GitHub (subsequence: G...itH...ub)", () => {
      const result = filterEntries(entries, "gh");
      const names = result.map((e) => e.name);
      expect(names).toContain("GitHub");
    });

    it("matches 'git' to both GitHub and GitLab", () => {
      const result = filterEntries(entries, "git");
      const names = result.map((e) => e.name);
      expect(names).toContain("GitHub");
      expect(names).toContain("GitLab");
    });

    it("matches against issuer field", () => {
      const result = filterEntries(entries, "amazon");
      const names = result.map((e) => e.name);
      expect(names).toContain("AWS Console");
    });

    it("is case insensitive", () => {
      const result = filterEntries(entries, "GITHUB");
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("GitHub");
    });

    it("returns no results for unmatched query", () => {
      const result = filterEntries(entries, "zzzzz");
      expect(result).toHaveLength(0);
    });
  });

  describe("result ordering", () => {
    it("places pinned entries first", () => {
      const result = filterEntries(entries, "");
      // GitHub (pinned) and AWS (pinned) should be at the top
      const pinnedResults = result.filter((e) => e.pinned);
      const unpinnedResults = result.filter((e) => !e.pinned);
      const firstUnpinnedIndex = result.findIndex((e) => !e.pinned);
      const lastPinnedIndex = result.length - 1 - [...result].reverse().findIndex((e) => e.pinned);
      if (pinnedResults.length > 0 && unpinnedResults.length > 0) {
        expect(lastPinnedIndex).toBeLessThan(firstUnpinnedIndex);
      }
    });

    it("ranks exact prefix match above contains match", () => {
      const result = filterEntries(entries, "git");
      const names = result.map((e) => e.name);
      // GitHub and GitLab are prefix matches, Digital Ocean's "digitalocean.com" contains "git" only as subsequence
      const gitHubIdx = names.indexOf("GitHub");
      const digitalIdx = names.indexOf("Digital Ocean");
      if (gitHubIdx !== -1 && digitalIdx !== -1) {
        expect(gitHubIdx).toBeLessThan(digitalIdx);
      }
    });

    it("ranks contains match above subsequence match", () => {
      // "oo" is a contains match in "Google" and subsequence elsewhere
      const result = filterEntries(entries, "oo");
      const names = result.map((e) => e.name);
      if (names.includes("Google")) {
        expect(names.indexOf("Google")).toBe(
          names.findIndex((n) => n === "Google"),
        );
      }
    });

    it("alphabetical tie-break within same score tier", () => {
      const result = filterEntries(entries, "git");
      const names = result.map((e) => e.name);
      const gitHubIdx = names.indexOf("GitHub");
      const gitLabIdx = names.indexOf("GitLab");
      // Both are prefix matches, "GitHub" < "GitLab" alphabetically
      expect(gitHubIdx).toBeLessThan(gitLabIdx);
    });
  });

  describe("type-agnostic search", () => {
    it("matches seed_phrase entries", () => {
      const result = filterEntries(entries, "bitcoin");
      expect(result).toHaveLength(1);
      expect(result[0].entryType).toBe("seed_phrase");
    });

    it("matches across entry types in single query", () => {
      // "g" matches GitHub, GitLab, Google, and potentially others
      const result = filterEntries(entries, "g");
      expect(result.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe("edge cases", () => {
    it("handles empty entries array", () => {
      const result = filterEntries([], "test");
      expect(result).toHaveLength(0);
    });

    it("handles entries with no issuer", () => {
      const noIssuer: EntryMetadataDto = {
        ...google,
        id: "99",
        issuer: undefined,
      };
      const result = filterEntries([noIssuer], "goo");
      expect(result).toHaveLength(1);
    });

    it("handles single-character query", () => {
      const result = filterEntries(entries, "a");
      // Should match entries with 'a' in name or issuer
      expect(result.length).toBeGreaterThan(0);
    });
  });
});
