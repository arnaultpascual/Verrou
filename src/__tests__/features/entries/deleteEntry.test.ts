import { describe, expect, it, beforeEach } from "vitest";
import { deleteEntry, listEntries, getEntry, _resetMockStore } from "../../../features/entries/ipc";

beforeEach(() => {
  _resetMockStore();
});

// Known mock store entry IDs
const TOTP_ENTRY_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"; // GitHub

describe("deleteEntry", () => {
  it("deletes an existing entry without throwing", async () => {
    await expect(deleteEntry(TOTP_ENTRY_ID)).resolves.toBeUndefined();
  });

  it("throws when deleting a nonexistent entry", async () => {
    await expect(deleteEntry("nonexistent-id")).rejects.toBe(
      "Entry not found. It may have been deleted.",
    );
  });

  it("removes entry from list after deletion", async () => {
    const beforeList = await listEntries();
    const beforeCount = beforeList.length;

    await deleteEntry(TOTP_ENTRY_ID);

    const afterList = await listEntries();
    expect(afterList.length).toBe(beforeCount - 1);
    expect(afterList.find((e) => e.id === TOTP_ENTRY_ID)).toBeUndefined();
  });

  it("makes deleted entry inaccessible via getEntry", async () => {
    await deleteEntry(TOTP_ENTRY_ID);

    await expect(getEntry(TOTP_ENTRY_ID)).rejects.toBe(
      "Entry not found. It may have been deleted.",
    );
  });

  it("deletion is permanent — double delete throws", async () => {
    await deleteEntry(TOTP_ENTRY_ID);

    await expect(deleteEntry(TOTP_ENTRY_ID)).rejects.toBe(
      "Entry not found. It may have been deleted.",
    );
  });

  it("does not affect other entries when one is deleted", async () => {
    const beforeList = await listEntries();
    const otherEntry = beforeList.find((e) => e.id !== TOTP_ENTRY_ID)!;

    await deleteEntry(TOTP_ENTRY_ID);

    const afterEntry = await getEntry(otherEntry.id);
    expect(afterEntry.id).toBe(otherEntry.id);
    expect(afterEntry.name).toBe(otherEntry.name);
  });
});
