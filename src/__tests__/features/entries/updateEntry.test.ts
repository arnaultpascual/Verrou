import { describe, expect, it, beforeEach } from "vitest";
import {
  updateEntry,
  getEntry,
  _resetMockStore,
} from "../../../features/entries/ipc";

const TOTP_ENTRY_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";

beforeEach(() => {
  _resetMockStore();
});

describe("updateEntry", () => {
  it("updates entry name", async () => {
    const result = await updateEntry({ id: TOTP_ENTRY_ID, name: "GitHub Renamed" });
    expect(result.name).toBe("GitHub Renamed");
  });

  it("updates entry issuer", async () => {
    const result = await updateEntry({ id: TOTP_ENTRY_ID, issuer: "gh.example.com" });
    expect(result.issuer).toBe("gh.example.com");
  });

  it("clears issuer when set to null", async () => {
    const result = await updateEntry({ id: TOTP_ENTRY_ID, issuer: null });
    expect(result.issuer).toBeUndefined();
  });

  it("preserves issuer when issuer is not in request", async () => {
    const result = await updateEntry({ id: TOTP_ENTRY_ID, name: "GitHub New" });
    expect(result.issuer).toBe("github.com");
  });

  it("updates algorithm", async () => {
    await updateEntry({ id: TOTP_ENTRY_ID, algorithm: "SHA256" });
    const detail = await getEntry(TOTP_ENTRY_ID);
    expect(detail.algorithm).toBe("SHA256");
  });

  it("updates digits", async () => {
    await updateEntry({ id: TOTP_ENTRY_ID, digits: 8 });
    const detail = await getEntry(TOTP_ENTRY_ID);
    expect(detail.digits).toBe(8);
  });

  it("updates period", async () => {
    await updateEntry({ id: TOTP_ENTRY_ID, period: 60 });
    const detail = await getEntry(TOTP_ENTRY_ID);
    expect(detail.period).toBe(60);
  });

  it("supports partial update (only name)", async () => {
    const before = await getEntry(TOTP_ENTRY_ID);
    const result = await updateEntry({ id: TOTP_ENTRY_ID, name: "Just Name" });
    expect(result.name).toBe("Just Name");
    expect(result.algorithm).toBe(before.algorithm);
    expect(result.digits).toBe(before.digits);
    expect(result.period).toBe(before.period);
  });

  it("throws for nonexistent entry", async () => {
    await expect(
      updateEntry({ id: "nonexistent-id", name: "Nope" }),
    ).rejects.toBe("Entry not found. It may have been deleted.");
  });

  it("updates the updatedAt timestamp", async () => {
    const before = await getEntry(TOTP_ENTRY_ID);
    // Small delay to ensure timestamp differs
    await new Promise((r) => setTimeout(r, 10));
    await updateEntry({ id: TOTP_ENTRY_ID, name: "Timestamp Test" });
    const after = await getEntry(TOTP_ENTRY_ID);
    expect(new Date(after.updatedAt).getTime()).toBeGreaterThan(
      new Date(before.updatedAt).getTime(),
    );
  });

  it("returns metadata without secret", async () => {
    const result = await updateEntry({ id: TOTP_ENTRY_ID, name: "No Secret" });
    expect(result).not.toHaveProperty("secret");
    expect(result).not.toHaveProperty("counter");
  });

  it("updates pinned status", async () => {
    const result = await updateEntry({ id: TOTP_ENTRY_ID, pinned: false });
    expect(result.pinned).toBe(false);
  });
});
