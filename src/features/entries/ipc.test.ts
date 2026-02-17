import { describe, it, expect, beforeEach } from "vitest";
import {
  listEntries,
  addEntry,
  getEntry,
  updateEntry,
  deleteEntry,
  _resetMockStore,
  type EntryMetadataDto,
  type AddEntryRequest,
} from "./ipc";

beforeEach(() => {
  _resetMockStore();
});

describe("listEntries", () => {
  it("returns metadata without secret field", async () => {
    const entries = await listEntries();
    expect(entries.length).toBeGreaterThan(0);

    for (const entry of entries) {
      expect(entry).not.toHaveProperty("secret");
      expect(entry).not.toHaveProperty("counter");
      expect(entry).toHaveProperty("id");
      expect(entry).toHaveProperty("entryType");
      expect(entry).toHaveProperty("name");
      expect(entry).toHaveProperty("algorithm");
      expect(entry).toHaveProperty("digits");
      expect(entry).toHaveProperty("period");
      expect(entry).toHaveProperty("pinned");
      expect(entry).toHaveProperty("createdAt");
      expect(entry).toHaveProperty("updatedAt");
    }
  });

  it("sorts pinned entries first, then by name", async () => {
    const entries = await listEntries();
    const pinnedEntries = entries.filter((e) => e.pinned);
    const unpinnedEntries = entries.filter((e) => !e.pinned);

    // Pinned come first.
    if (pinnedEntries.length > 0 && unpinnedEntries.length > 0) {
      const lastPinnedIdx = entries.findIndex(
        (e) => e.id === pinnedEntries[pinnedEntries.length - 1].id,
      );
      const firstUnpinnedIdx = entries.findIndex(
        (e) => e.id === unpinnedEntries[0].id,
      );
      expect(lastPinnedIdx).toBeLessThan(firstUnpinnedIdx);
    }

    // Unpinned sorted by name.
    for (let i = 1; i < unpinnedEntries.length; i++) {
      expect(
        unpinnedEntries[i - 1].name.localeCompare(unpinnedEntries[i].name),
      ).toBeLessThanOrEqual(0);
    }
  });
});

describe("addEntry", () => {
  it("returns metadata for new entry", async () => {
    const request: AddEntryRequest = {
      entryType: "totp",
      name: "New Service",
      issuer: "new.example.com",
      secret: "NEWSECRET123",
    };
    const entry = await addEntry(request);

    expect(entry.name).toBe("New Service");
    expect(entry.entryType).toBe("totp");
    expect(entry.issuer).toBe("new.example.com");
    expect(entry).not.toHaveProperty("secret");
  });

  it("applies defaults for optional fields", async () => {
    const request: AddEntryRequest = {
      entryType: "totp",
      name: "Defaults",
      secret: "SECRET",
    };
    const entry = await addEntry(request);

    expect(entry.algorithm).toBe("SHA1");
    expect(entry.digits).toBe(6);
    expect(entry.period).toBe(30);
    expect(entry.pinned).toBe(false);
  });

  it("increases list count", async () => {
    const before = await listEntries();
    await addEntry({
      entryType: "totp",
      name: "Extra",
      secret: "S",
    });
    const after = await listEntries();
    expect(after.length).toBe(before.length + 1);
  });
});

describe("getEntry", () => {
  it("returns full detail with secret", async () => {
    const entries = await listEntries();
    const detail = await getEntry(entries[0].id);

    expect(detail).toHaveProperty("secret");
    expect(detail.secret).toBeTruthy();
    expect(detail.id).toBe(entries[0].id);
  });

  it("throws for nonexistent entry", async () => {
    await expect(getEntry("nonexistent-id")).rejects.toThrow();
  });
});

describe("updateEntry", () => {
  it("updates name and returns metadata", async () => {
    const entries = await listEntries();
    const updated = await updateEntry({
      id: entries[0].id,
      name: "Updated Name",
    });

    expect(updated.name).toBe("Updated Name");
    expect(updated).not.toHaveProperty("secret");
  });

  it("persists changes", async () => {
    const entries = await listEntries();
    await updateEntry({
      id: entries[0].id,
      pinned: true,
    });

    const detail = await getEntry(entries[0].id);
    expect(detail.pinned).toBe(true);
  });

  it("throws for nonexistent entry", async () => {
    await expect(
      updateEntry({ id: "nonexistent-id", name: "X" }),
    ).rejects.toThrow();
  });
});

describe("deleteEntry", () => {
  it("removes the entry", async () => {
    const entries = await listEntries();
    const id = entries[0].id;
    await deleteEntry(id);

    const remaining = await listEntries();
    expect(remaining.find((e) => e.id === id)).toBeUndefined();
  });

  it("throws for nonexistent entry", async () => {
    await expect(deleteEntry("nonexistent-id")).rejects.toThrow();
  });

  it("double delete throws", async () => {
    const entries = await listEntries();
    const id = entries[0].id;
    await deleteEntry(id);
    await expect(deleteEntry(id)).rejects.toThrow();
  });
});
