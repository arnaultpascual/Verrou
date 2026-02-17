import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock platformStore
vi.mock("../../../stores/platformStore", () => ({
  platformCapabilities: () => ({ osType: "macos" }),
  isBiometricAvailable: () => false,
  biometricProviderName: () => "None",
  isHardwareSecurityAvailable: () => false,
  hardwareSecurityProviderName: () => "None",
  platformLoaded: () => true,
  initPlatformCapabilities: vi.fn(),
}));

// Mock preferencesIpc — capture openOsNetworkSettings calls
const mockOpenOsNetworkSettings = vi.fn(() => Promise.resolve());

vi.mock("../../../features/settings/preferencesIpc", () => ({
  openOsNetworkSettings: () => mockOpenOsNetworkSettings(),
  getAppInfo: vi.fn(() =>
    Promise.resolve({
      version: "0.1.0",
      commitHash: "abc1234",
      buildDate: "2026-02-16",
      repository: "https://github.com/cyanodroid/verrou",
      license: "GPL-3.0-or-later",
    }),
  ),
}));

import { Footer } from "../../../features/layout/Footer";

describe("Footer", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders footer element", () => {
    const { container } = render(() => <Footer />);
    const footer = container.querySelector("footer");
    expect(footer).not.toBeNull();
  });

  it("renders offline badge with shield-check icon", () => {
    const { getByTestId } = render(() => <Footer />);
    const badge = getByTestId("offline-badge");
    expect(badge).toBeDefined();
    expect(badge.textContent).toContain("Offline by design");
  });

  it("offline badge has correct aria-label", () => {
    const { getByTestId } = render(() => <Footer />);
    const badge = getByTestId("offline-badge");
    expect(badge.getAttribute("aria-label")).toBe("Offline by design");
    expect(badge.getAttribute("aria-expanded")).toBe("false");
  });

  it("renders shield-check icon in badge", () => {
    const { getByTestId } = render(() => <Footer />);
    const badge = getByTestId("offline-badge");
    const svg = badge.querySelector("svg");
    expect(svg).not.toBeNull();
  });

  it("renders entry count", () => {
    const { getByText } = render(() => <Footer />);
    expect(getByText("0 entries")).toBeDefined();
  });

  it("clicking badge opens popover with explanation text", async () => {
    const { getByTestId, queryByTestId } = render(() => <Footer />);

    // Popover should not be visible initially
    expect(queryByTestId("offline-popover")).toBeNull();

    // Click badge to open popover
    fireEvent.click(getByTestId("offline-badge"));

    const popover = getByTestId("offline-popover");
    expect(popover).toBeDefined();
    expect(popover.getAttribute("role")).toBe("dialog");
    expect(popover.textContent).toContain("Offline by design");
    expect(popover.textContent).toContain("zero network permissions");
  });

  it("badge aria-expanded updates when popover opens", async () => {
    const { getByTestId } = render(() => <Footer />);
    const badge = getByTestId("offline-badge");

    expect(badge.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(badge);
    expect(badge.getAttribute("aria-expanded")).toBe("true");
  });

  it("popover shows platform-specific instruction for macOS", () => {
    const { getByTestId } = render(() => <Footer />);
    fireEvent.click(getByTestId("offline-badge"));

    const popover = getByTestId("offline-popover");
    expect(popover.textContent).toContain("macOS");
    expect(popover.textContent).toContain("Privacy & Security");
  });

  it("popover verify button calls openOsNetworkSettings", async () => {
    const { getByTestId } = render(() => <Footer />);
    fireEvent.click(getByTestId("offline-badge"));

    const verifyBtn = getByTestId("verify-os-settings");
    expect(verifyBtn).toBeDefined();
    expect(verifyBtn.textContent).toContain("Verify in OS settings");

    fireEvent.click(verifyBtn);
    expect(mockOpenOsNetworkSettings).toHaveBeenCalledOnce();
  });

  it("clicking badge again closes popover", () => {
    const { getByTestId, queryByTestId } = render(() => <Footer />);

    fireEvent.click(getByTestId("offline-badge"));
    expect(queryByTestId("offline-popover")).not.toBeNull();

    fireEvent.click(getByTestId("offline-badge"));
    expect(queryByTestId("offline-popover")).toBeNull();
  });
});
