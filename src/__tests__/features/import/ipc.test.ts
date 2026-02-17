import { describe, expect, it, beforeEach } from "vitest";
import {
  validateGoogleAuthImport,
  confirmGoogleAuthImport,
  validateAegisImport,
  confirmAegisImport,
  validateTwofasImport,
  confirmTwofasImport,
  readImportFile,
  pickImportFile,
  _resetMockState,
} from "../../../features/import/ipc";

describe("import/ipc", () => {
  beforeEach(() => {
    _resetMockState();
  });

  // ---------------------------------------------------------------------------
  // Google Authenticator
  // ---------------------------------------------------------------------------

  describe("validateGoogleAuthImport", () => {
    it("returns a validation report for valid input", async () => {
      const report = await validateGoogleAuthImport("otpauth-migration://offline?data=abc");
      expect(report.totalParsed).toBeGreaterThan(0);
      expect(report.validCount).toBeGreaterThanOrEqual(0);
      expect(report.validEntries).toBeDefined();
      expect(report.duplicates).toBeDefined();
      expect(report.unsupported).toBeDefined();
      expect(report.malformed).toBeDefined();
    });

    it("throws on empty input", async () => {
      await expect(validateGoogleAuthImport("")).rejects.toBe(
        "Invalid migration data: empty input.",
      );
    });

    it("throws on whitespace-only input", async () => {
      await expect(validateGoogleAuthImport("   ")).rejects.toBe(
        "Invalid migration data: empty input.",
      );
    });
  });

  describe("confirmGoogleAuthImport", () => {
    it("returns import summary", async () => {
      const summary = await confirmGoogleAuthImport("valid-data", []);
      expect(summary.imported).toBeGreaterThan(0);
      expect(summary.importedIds).toHaveLength(summary.imported);
    });

    it("subtracts skip indices from imported count", async () => {
      const full = await confirmGoogleAuthImport("valid-data", []);
      const partial = await confirmGoogleAuthImport("valid-data", [0, 1]);
      expect(partial.imported).toBe(full.imported - 2);
    });

    it("throws on empty input", async () => {
      await expect(confirmGoogleAuthImport("", [])).rejects.toBe(
        "Invalid migration data: empty input.",
      );
    });
  });

  // ---------------------------------------------------------------------------
  // Aegis
  // ---------------------------------------------------------------------------

  describe("validateAegisImport", () => {
    it("returns a validation report for valid input", async () => {
      const report = await validateAegisImport('{"entries": []}');
      expect(report.totalParsed).toBeGreaterThan(0);
      expect(report.validEntries.length).toBe(report.validCount);
    });

    it("throws on empty input", async () => {
      await expect(validateAegisImport("")).rejects.toBe(
        "Invalid Aegis export: empty file.",
      );
    });

    it("throws when encrypted and no password", async () => {
      const encrypted = '{"db": "encrypted-blob"}';
      await expect(validateAegisImport(encrypted)).rejects.toContain("encrypted");
    });

    it("succeeds with password for encrypted data", async () => {
      const encrypted = '{"db": "encrypted-blob"}';
      const report = await validateAegisImport(encrypted, "mypassword");
      expect(report.totalParsed).toBeGreaterThan(0);
    });
  });

  describe("confirmAegisImport", () => {
    it("returns import summary", async () => {
      const summary = await confirmAegisImport("valid-data");
      expect(summary.imported).toBeGreaterThan(0);
    });

    it("handles skip indices", async () => {
      const full = await confirmAegisImport("valid-data", undefined, []);
      const partial = await confirmAegisImport("valid-data", undefined, [0, 1, 2]);
      expect(partial.imported).toBe(full.imported - 3);
    });
  });

  // ---------------------------------------------------------------------------
  // 2FAS
  // ---------------------------------------------------------------------------

  describe("validateTwofasImport", () => {
    it("returns a validation report for valid input", async () => {
      const report = await validateTwofasImport('{"services": []}');
      expect(report.totalParsed).toBeGreaterThan(0);
    });

    it("throws on empty input", async () => {
      await expect(validateTwofasImport("")).rejects.toBe(
        "Invalid 2FAS export: empty file.",
      );
    });

    it("throws when encrypted and no password", async () => {
      const encrypted = '{"servicesEncrypted": "blob"}';
      await expect(validateTwofasImport(encrypted)).rejects.toContain("encrypted");
    });

    it("succeeds with password for encrypted data", async () => {
      const encrypted = '{"servicesEncrypted": "blob"}';
      const report = await validateTwofasImport(encrypted, "pass");
      expect(report.totalParsed).toBeGreaterThan(0);
    });
  });

  describe("confirmTwofasImport", () => {
    it("returns import summary", async () => {
      const summary = await confirmTwofasImport("valid-data");
      expect(summary.imported).toBeGreaterThan(0);
    });
  });

  // ---------------------------------------------------------------------------
  // File operations
  // ---------------------------------------------------------------------------

  describe("readImportFile", () => {
    it("returns mock data in non-Tauri environment", async () => {
      const content = await readImportFile("/fake/path.json");
      const parsed = JSON.parse(content);
      expect(parsed.services).toBeDefined();
    });
  });

  describe("pickImportFile", () => {
    it("returns a mock path for aegis source", async () => {
      const path = await pickImportFile("aegis");
      expect(path).toContain(".json");
    });

    it("returns a mock path for google-auth source", async () => {
      const path = await pickImportFile("google-auth");
      expect(path).toContain(".txt");
    });

    it("returns a mock path for twofas source", async () => {
      const path = await pickImportFile("twofas");
      expect(path).toContain(".json");
    });
  });

  // ---------------------------------------------------------------------------
  // Mock ID uniqueness
  // ---------------------------------------------------------------------------

  describe("mock ID generation", () => {
    it("produces unique IDs across imports", async () => {
      const s1 = await confirmGoogleAuthImport("data", []);
      const s2 = await confirmGoogleAuthImport("data", []);
      const allIds = [...s1.importedIds, ...s2.importedIds];
      const uniqueIds = new Set(allIds);
      expect(uniqueIds.size).toBe(allIds.length);
    });
  });
});
