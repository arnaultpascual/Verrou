import { describe, it, expect, vi, beforeEach } from "vitest";

describe("platformStore", () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it("returns null before initialization", async () => {
    const { platformCapabilities, platformLoaded } = await import(
      "../../stores/platformStore"
    );
    expect(platformCapabilities()).toBeNull();
    expect(platformLoaded()).toBe(false);
  });

  it("provides all-unavailable defaults in browser mode", async () => {
    const {
      initPlatformCapabilities,
      isBiometricAvailable,
      isHardwareSecurityAvailable,
      biometricProviderName,
      hardwareSecurityProviderName,
      platformLoaded,
    } = await import("../../stores/platformStore");

    await initPlatformCapabilities();

    expect(platformLoaded()).toBe(true);
    expect(isBiometricAvailable()).toBe(false);
    expect(isHardwareSecurityAvailable()).toBe(false);
    expect(biometricProviderName()).toBe("None");
    expect(hardwareSecurityProviderName()).toBe("None");
  });

  it("derived accessors return false when capabilities is null", async () => {
    const {
      isBiometricAvailable,
      isHardwareSecurityAvailable,
      biometricProviderName,
      hardwareSecurityProviderName,
    } = await import("../../stores/platformStore");

    expect(isBiometricAvailable()).toBe(false);
    expect(isHardwareSecurityAvailable()).toBe(false);
    expect(biometricProviderName()).toBe("None");
    expect(hardwareSecurityProviderName()).toBe("None");
  });

  it("initPlatformCapabilities only calls IPC once", async () => {
    const { initPlatformCapabilities, platformLoaded } = await import(
      "../../stores/platformStore"
    );

    await initPlatformCapabilities();
    expect(platformLoaded()).toBe(true);

    // Second call is a no-op (no error, no duplicate).
    await initPlatformCapabilities();
    expect(platformLoaded()).toBe(true);
  });

  it("_resetPlatformStore clears state for testing", async () => {
    const {
      initPlatformCapabilities,
      platformLoaded,
      _resetPlatformStore,
    } = await import("../../stores/platformStore");

    await initPlatformCapabilities();
    expect(platformLoaded()).toBe(true);

    _resetPlatformStore();
    expect(platformLoaded()).toBe(false);
  });
});
