import { describe, expect, it, vi, beforeEach } from "vitest";
import {
  prepareQrTransfer,
  receiveQrTransfer,
  setScreenCaptureProtection,
  saveTransferFile,
  loadTransferFile,
} from "../../../features/export/qrTransferIpc";

// Remove __TAURI_INTERNALS__ to force mock fallbacks
beforeEach(() => {
  if ("__TAURI_INTERNALS__" in window) {
    delete (window as Record<string, unknown>).__TAURI_INTERNALS__;
  }
});

describe("qrTransferIpc (mock/browser mode)", () => {
  it("prepareQrTransfer returns mock chunks and verification code", async () => {
    const result = await prepareQrTransfer({
      entryIds: ["e1", "e2"],
    });

    expect(result.chunks).toHaveLength(5);
    expect(result.verificationCode).toBe("alpha bravo charlie delta");
    expect(result.totalEntries).toBe(2);
    expect(result.hasSensitive).toBe(false);
  });

  it("receiveQrTransfer returns mock imported count", async () => {
    const result = await receiveQrTransfer({
      chunks: ["c1", "c2", "c3"],
      verificationCode: "alpha bravo charlie delta",
    });

    expect(result.importedCount).toBe(3);
  });

  it("setScreenCaptureProtection returns false in browser mode", async () => {
    const result = await setScreenCaptureProtection(true);
    expect(result).toBe(false);
  });

  it("prepareQrTransfer accepts optional password", async () => {
    const result = await prepareQrTransfer({
      entryIds: ["e1"],
      password: "testpass",
    });

    expect(result.chunks.length).toBeGreaterThan(0);
  });

  it("saveTransferFile returns mock path in browser mode", async () => {
    const result = await saveTransferFile(["chunk1", "chunk2"]);
    expect(result).toBe("/mock/transfer.verrou-transfer");
  });

  it("loadTransferFile returns mock chunks in browser mode", async () => {
    const result = await loadTransferFile();
    expect(result).toHaveLength(3);
    expect(result![0]).toBe("bW9ja19jaHVua18x");
  });
});
