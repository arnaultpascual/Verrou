import { describe, expect, it } from "vitest";
import {
  revealRecoveryCodes,
  getRecoveryStats,
  getAllRecoveryStats,
  deleteRecoveryCodeEntry,
  toggleRecoveryCodeUsed,
  updateRecoveryCodes,
  getLinkedRecoveryCount,
} from "../../../features/recovery/ipc";
import type {
  RecoveryCodeDisplay,
  RecoveryStats,
  RecoveryStatsMap,
} from "../../../features/recovery/ipc";

describe("Recovery code IPC mock service", () => {
  describe("revealRecoveryCodes", () => {
    it("returns RecoveryCodeDisplay with correct shape", async () => {
      const result = await revealRecoveryCodes("test-id", "password");
      expect(result.codes).toBeInstanceOf(Array);
      expect(result.codes.length).toBeGreaterThan(0);
      expect(result.used).toBeInstanceOf(Array);
      expect(typeof result.totalCodes).toBe("number");
      expect(typeof result.remainingCodes).toBe("number");
      expect(typeof result.hasLinkedEntry).toBe("boolean");
    });

    it("returns consistent total and remaining counts", async () => {
      const result = await revealRecoveryCodes("test-id", "password");
      expect(result.totalCodes).toBe(result.codes.length);
      expect(result.remainingCodes).toBe(
        result.totalCodes - result.used.length,
      );
    });

    it("used indexes are valid for the codes array", async () => {
      const result = await revealRecoveryCodes("test-id", "password");
      for (const idx of result.used) {
        expect(idx).toBeGreaterThanOrEqual(0);
        expect(idx).toBeLessThan(result.codes.length);
      }
    });
  });

  describe("getRecoveryStats", () => {
    it("returns RecoveryStats with total and remaining", async () => {
      const result = await getRecoveryStats("test-entry-id");
      expect(typeof result.total).toBe("number");
      expect(typeof result.remaining).toBe("number");
      expect(result.remaining).toBeLessThanOrEqual(result.total);
    });
  });

  describe("getAllRecoveryStats", () => {
    it("returns a RecoveryStatsMap", async () => {
      const result = await getAllRecoveryStats();
      expect(result).toBeInstanceOf(Map);
    });

    it("map values have total and remaining", async () => {
      const result = await getAllRecoveryStats();
      for (const [key, stats] of result) {
        expect(typeof key).toBe("string");
        expect(typeof stats.total).toBe("number");
        expect(typeof stats.remaining).toBe("number");
        expect(stats.remaining).toBeLessThanOrEqual(stats.total);
      }
    });
  });

  describe("toggleRecoveryCodeUsed", () => {
    it("returns RecoveryCodeDisplay with correct shape", async () => {
      const result = await toggleRecoveryCodeUsed("test-id", 0, "password");
      expect(result.codes).toBeInstanceOf(Array);
      expect(result.codes.length).toBeGreaterThan(0);
      expect(result.used).toBeInstanceOf(Array);
      expect(typeof result.totalCodes).toBe("number");
      expect(typeof result.remainingCodes).toBe("number");
      expect(typeof result.hasLinkedEntry).toBe("boolean");
    });

    it("returns consistent remaining count after toggle", async () => {
      const result = await toggleRecoveryCodeUsed("test-id", 0, "password");
      expect(result.remainingCodes).toBe(
        result.totalCodes - result.used.length,
      );
    });
  });

  describe("updateRecoveryCodes", () => {
    it("returns RecoveryCodeDisplay with correct shape", async () => {
      const result = await updateRecoveryCodes("test-id", ["NEW-CODE"], [], "password");
      expect(result.codes).toBeInstanceOf(Array);
      expect(result.codes.length).toBeGreaterThan(0);
      expect(result.used).toBeInstanceOf(Array);
      expect(typeof result.totalCodes).toBe("number");
      expect(typeof result.remainingCodes).toBe("number");
      expect(typeof result.hasLinkedEntry).toBe("boolean");
    });

    it("returns updated codes reflecting additions", async () => {
      const result = await updateRecoveryCodes("test-id", ["ADDED-1", "ADDED-2"], [], "password");
      expect(result.totalCodes).toBe(result.codes.length);
      expect(result.remainingCodes).toBe(result.totalCodes - result.used.length);
    });
  });

  describe("getLinkedRecoveryCount", () => {
    it("returns a number", async () => {
      const result = await getLinkedRecoveryCount("test-entry-id");
      expect(typeof result).toBe("number");
      expect(result).toBeGreaterThanOrEqual(0);
    });
  });

  describe("deleteRecoveryCodeEntry", () => {
    it("resolves without error", async () => {
      await expect(
        deleteRecoveryCodeEntry("test-id", "password"),
      ).resolves.toBeUndefined();
    });
  });

  describe("DTO type shapes", () => {
    it("RecoveryCodeDisplay has all required fields", async () => {
      const dto: RecoveryCodeDisplay = {
        codes: ["CODE-1", "CODE-2"],
        used: [0],
        totalCodes: 2,
        remainingCodes: 1,
        linkedEntryId: "linked-id",
        hasLinkedEntry: true,
      };
      expect(dto.codes).toHaveLength(2);
      expect(dto.used).toEqual([0]);
      expect(dto.totalCodes).toBe(2);
      expect(dto.remainingCodes).toBe(1);
      expect(dto.linkedEntryId).toBe("linked-id");
      expect(dto.hasLinkedEntry).toBe(true);
    });

    it("RecoveryCodeDisplay allows optional linkedEntryId", () => {
      const dto: RecoveryCodeDisplay = {
        codes: ["CODE-1"],
        used: [],
        totalCodes: 1,
        remainingCodes: 1,
        hasLinkedEntry: false,
      };
      expect(dto.linkedEntryId).toBeUndefined();
      expect(dto.hasLinkedEntry).toBe(false);
    });

    it("RecoveryStats has total and remaining", () => {
      const dto: RecoveryStats = { total: 10, remaining: 7 };
      expect(dto.total).toBe(10);
      expect(dto.remaining).toBe(7);
    });
  });
});
