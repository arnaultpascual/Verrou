import { describe, it, expect, beforeEach } from "vitest";
import { searchQuery, setSearchQuery, clearSearch } from "../../stores/searchStore";

beforeEach(() => {
  clearSearch();
});

describe("searchStore", () => {
  it("initial state is empty string", () => {
    expect(searchQuery()).toBe("");
  });

  it("setSearchQuery updates the query", () => {
    setSearchQuery("github");
    expect(searchQuery()).toBe("github");
  });

  it("clearSearch resets query to empty string", () => {
    setSearchQuery("test");
    expect(searchQuery()).toBe("test");
    clearSearch();
    expect(searchQuery()).toBe("");
  });

  it("setSearchQuery handles whitespace-only input", () => {
    setSearchQuery("   ");
    expect(searchQuery()).toBe("   ");
  });

  it("setSearchQuery handles empty string", () => {
    setSearchQuery("something");
    setSearchQuery("");
    expect(searchQuery()).toBe("");
  });

  it("multiple sequential updates reflect latest value", () => {
    setSearchQuery("a");
    setSearchQuery("ab");
    setSearchQuery("abc");
    expect(searchQuery()).toBe("abc");
  });
});
