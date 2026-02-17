import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock platform store — controls hardware availability
let mockHwAvailable = false;
let mockHwProvider = "None";

vi.mock("../../../stores/platformStore", () => ({
  isBiometricAvailable: () => false,
  biometricProviderName: () => "None",
  isHardwareSecurityAvailable: () => mockHwAvailable,
  hardwareSecurityProviderName: () => mockHwProvider,
  platformLoaded: () => true,
  initPlatformCapabilities: vi.fn(),
}));

// Mock hardwareKeyIpc module with controllable function
const mockCheckHardwareSecurity = vi.fn();

vi.mock("../../../features/vault/hardwareKeyIpc", () => ({
  checkHardwareSecurity: (...args: unknown[]) =>
    mockCheckHardwareSecurity(...args),
}));

import { render, waitFor } from "@solidjs/testing-library";
import { HardwareSecurityStatus } from "../../../features/settings/HardwareSecurityStatus";

describe("HardwareSecurityStatus", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockHwAvailable = false;
    mockHwProvider = "None";
  });

  it("shows loading state during availability check", async () => {
    // Never resolve to keep loading state visible
    mockCheckHardwareSecurity.mockReturnValue(new Promise(() => {}));

    const { getByTestId } = render(() => <HardwareSecurityStatus />);

    const section = getByTestId("hardware-security-status");
    expect(section.textContent).toContain("Checking hardware security...");
  });

  it("shows unavailable message when hardware security not available", async () => {
    mockHwAvailable = false;
    mockHwProvider = "None";

    mockCheckHardwareSecurity.mockResolvedValue({
      available: false,
      providerName: "None",
      enabled: false,
    });

    const { findByTestId } = render(() => <HardwareSecurityStatus />);

    const msg = await findByTestId("hw-unavailable");
    expect(msg.textContent).toContain(
      "Hardware security (Secure Enclave/TPM) is not available"
    );
    expect(msg.textContent).toContain(
      "Your vault key is protected by software encryption only"
    );
  });

  it("shows provider name and active status when enabled", async () => {
    mockHwAvailable = true;
    mockHwProvider = "Secure Enclave";

    mockCheckHardwareSecurity.mockResolvedValue({
      available: true,
      providerName: "Secure Enclave",
      enabled: true,
    });

    const { findByTestId } = render(() => <HardwareSecurityStatus />);

    const status = await findByTestId("hw-status");
    expect(status.textContent).toBe("Secure Enclave active");
  });

  it("shows provider name with 'available' when not enabled", async () => {
    mockHwAvailable = true;
    mockHwProvider = "TPM 2.0";

    mockCheckHardwareSecurity.mockResolvedValue({
      available: true,
      providerName: "TPM 2.0",
      enabled: false,
    });

    const { findByTestId } = render(() => <HardwareSecurityStatus />);

    const status = await findByTestId("hw-status");
    expect(status.textContent).toBe("TPM 2.0 available");
  });
});
