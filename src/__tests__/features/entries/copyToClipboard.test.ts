import { describe, it, expect, vi, beforeEach } from "vitest";
import { copyToClipboard, clearClipboard } from "../../../features/entries/ipc";

describe("copyToClipboard", () => {
  let writeTextMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock, readText: vi.fn() },
    });
  });

  it("writes text to the clipboard", async () => {
    await copyToClipboard("483291");
    expect(writeTextMock).toHaveBeenCalledWith("483291");
  });

  it("resolves on success", async () => {
    await expect(copyToClipboard("123456")).resolves.toBeUndefined();
  });

  it("rejects when clipboard write fails", async () => {
    writeTextMock.mockRejectedValueOnce(new Error("Permission denied"));
    await expect(copyToClipboard("123456")).rejects.toThrow("Permission denied");
  });

  it("handles empty string", async () => {
    await copyToClipboard("");
    expect(writeTextMock).toHaveBeenCalledWith("");
  });
});

describe("clearClipboard", () => {
  let writeTextMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: { writeText: writeTextMock, readText: vi.fn() },
    });
  });

  it("writes empty string to clipboard", async () => {
    await clearClipboard();
    expect(writeTextMock).toHaveBeenCalledWith("");
  });

  it("resolves on success", async () => {
    await expect(clearClipboard()).resolves.toBeUndefined();
  });
});
