import { describe, it, expect, beforeEach } from "vitest";
import { searchEntries, _resetMockStore } from "../../../features/entries/ipc";

beforeEach(() => {
  _resetMockStore();
});

describe("searchEntries", () => {
  it("returns filtered results for a query", async () => {
    const results = await searchEntries("github");
    expect(results.length).toBe(2);
    expect(results[0].name).toBe("GitHub");
    expect(results[1].name).toBe("GitHub Login");
  });

  it("returns all entries for empty query", async () => {
    const results = await searchEntries("");
    expect(results.length).toBeGreaterThan(0);
  });

  it("returns empty array for unmatched query", async () => {
    const results = await searchEntries("zzzzzznothing");
    expect(results).toHaveLength(0);
  });

  it("returns metadata without secret field", async () => {
    const results = await searchEntries("github");
    expect(results[0]).not.toHaveProperty("secret");
    expect(results[0]).not.toHaveProperty("counter");
  });

  it("matches by issuer", async () => {
    const results = await searchEntries("amazon");
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("AWS Console");
  });

  it("matches credential entries by username", async () => {
    const results = await searchEntries("admin@github");
    expect(results.length).toBe(1);
    expect(results[0].name).toBe("GitHub Login");
    expect(results[0].entryType).toBe("credential");
  });

  it("returns credential entry for username prefix match", async () => {
    const results = await searchEntries("admin");
    expect(results.some((r) => r.name === "GitHub Login")).toBe(true);
  });
});
