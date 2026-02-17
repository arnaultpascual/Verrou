import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock platform store — controls hardware availability
let mockBiometricAvailable = true;
let mockBiometricProvider = "Touch ID";

vi.mock("../../../stores/platformStore", () => ({
  isBiometricAvailable: () => mockBiometricAvailable,
  biometricProviderName: () => mockBiometricProvider,
  isHardwareSecurityAvailable: () => false,
  hardwareSecurityProviderName: () => "None",
  platformLoaded: () => true,
  initPlatformCapabilities: vi.fn(),
}));

// Mock biometricIpc module with controllable functions
const mockCheckAvailability = vi.fn();
const mockEnroll = vi.fn();
const mockRevoke = vi.fn();

vi.mock("../../../features/vault/biometricIpc", () => ({
  checkBiometricAvailability: (...args: unknown[]) => mockCheckAvailability(...args),
  enrollBiometric: (...args: unknown[]) => mockEnroll(...args),
  revokeBiometric: (...args: unknown[]) => mockRevoke(...args),
}));

vi.mock("../../../features/vault/ipc", () => ({
  parseUnlockError: vi.fn((errorStr: string) => {
    try {
      return JSON.parse(errorStr);
    } catch {
      return { code: "UNKNOWN", message: errorStr || "An unexpected error occurred." };
    }
  }),
  getVaultDir: vi.fn(() => "/mock/vault"),
}));

// Mock useToast
const mockToastSuccess = vi.fn();
const mockToastError = vi.fn();
vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => ({
      success: mockToastSuccess,
      error: mockToastError,
      info: vi.fn(),
      dismiss: vi.fn(),
      clear: vi.fn(),
    }),
  };
});

// Mock Kobalte Switch as a simple functional component
vi.mock("@kobalte/core/switch", () => {
  function SwitchRoot(props: {
    checked?: boolean;
    disabled?: boolean;
    onChange?: (checked: boolean) => void;
    class?: string;
    children?: unknown;
    "data-testid"?: string;
  }) {
    return (
      <div data-testid={props["data-testid"] || "biometric-toggle"} class={props.class}>
        <button
          data-testid="switch-trigger"
          disabled={props.disabled}
          onClick={() => {
            if (!props.disabled && props.onChange) {
              props.onChange(!props.checked);
            }
          }}
        >
          {props.checked ? "ON" : "OFF"}
        </button>
      </div>
    );
  }
  SwitchRoot.Input = () => null;
  SwitchRoot.Control = (props: { children?: unknown }) => <>{props.children}</>;
  SwitchRoot.Thumb = () => null;
  return { Switch: SwitchRoot };
});

import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { BiometricSettings } from "../../../features/settings/BiometricSettings";

describe("BiometricSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBiometricAvailable = true;
    mockBiometricProvider = "Touch ID";
  });

  // -- shows "not available" when hardware unavailable --

  it("shows unavailable message when biometric hardware is not detected", async () => {
    mockBiometricAvailable = false;
    mockBiometricProvider = "None";

    mockCheckAvailability.mockResolvedValue({
      available: false,
      providerName: "None",
      enrolled: false,
    });

    const { findByText, getByTestId } = render(() => <BiometricSettings />);

    await findByText("Biometric Unlock");
    const msg = await findByText(/not available on this device/);
    expect(msg).toBeDefined();

    // Toggle should be disabled
    const trigger = getByTestId("switch-trigger") as HTMLButtonElement;
    expect(trigger.disabled).toBe(true);
  });

  // -- shows provider name and enrollment status --

  it("shows provider name and enrolled status when available and enrolled", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: true,
    });

    const { findByTestId } = render(() => <BiometricSettings />);

    const status = await findByTestId("biometric-status");
    expect(status.textContent).toBe("Touch ID enabled");
  });

  it("shows 'Not enrolled' when available but not enrolled", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: false,
    });

    const { findByTestId } = render(() => <BiometricSettings />);

    const status = await findByTestId("biometric-status");
    expect(status.textContent).toBe("Not enrolled");
  });

  // -- enrollment flow calls enrollBiometric --

  it("enrollment flow: toggle on shows re-auth, submitting calls enrollBiometric", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: false,
    });
    mockEnroll.mockResolvedValue(undefined);

    const { findByTestId, getByTestId } = render(() => <BiometricSettings />);

    // Wait for enrollment to load
    await findByTestId("biometric-status");

    // Toggle ON
    fireEvent.click(getByTestId("switch-trigger"));

    // Re-auth form should appear — check password input renders
    await waitFor(() => {
      expect(document.getElementById("biometric-enroll-password")).not.toBeNull();
    });

    // Enter password
    const pwInput = document.getElementById("biometric-enroll-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "my-password" } });

    // Submit
    fireEvent.click(getByTestId("biometric-enroll-btn"));

    // Should call enrollBiometric with password
    await waitFor(() => {
      expect(mockEnroll).toHaveBeenCalledWith("my-password");
    });

    // Should show success toast
    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith("Biometric unlock enabled");
    });
  });

  // -- revocation flow calls revokeBiometric --

  it("revocation flow: toggle off shows re-auth, submitting calls revokeBiometric", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: true,
    });
    mockRevoke.mockResolvedValue(undefined);

    const { findByTestId, getByTestId } = render(() => <BiometricSettings />);

    // Wait for enrollment to load
    await findByTestId("biometric-status");

    // Toggle OFF
    fireEvent.click(getByTestId("switch-trigger"));

    // Re-auth form should appear
    await waitFor(() => {
      expect(document.getElementById("biometric-revoke-password")).not.toBeNull();
    });

    // Enter password
    const pwInput = document.getElementById("biometric-revoke-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "my-password" } });

    // Submit
    fireEvent.click(getByTestId("biometric-revoke-btn"));

    // Should call revokeBiometric with password
    await waitFor(() => {
      expect(mockRevoke).toHaveBeenCalledWith("my-password");
    });

    // Should show success toast
    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith("Biometric unlock has been disabled");
    });
  });

  // -- error handling (INVALID_PASSWORD shows inline error) --

  it("shows inline error on INVALID_PASSWORD during enrollment", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: false,
    });
    mockEnroll.mockRejectedValue(
      JSON.stringify({
        code: "INVALID_PASSWORD",
        message: "Incorrect password. Please try again.",
      }),
    );

    const { findByTestId, getByTestId } = render(() => <BiometricSettings />);

    await findByTestId("biometric-status");

    // Toggle ON
    fireEvent.click(getByTestId("switch-trigger"));

    // Enter wrong password
    const pwInput = document.getElementById("biometric-enroll-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "wrong" } });

    // Submit
    fireEvent.click(getByTestId("biometric-enroll-btn"));

    // Error should appear inline
    const errorEl = await findByTestId("biometric-error");
    expect(errorEl.textContent).toBe("Incorrect password. Please try again.");

    // Re-auth form should still be visible (not dismissed)
    expect(document.getElementById("biometric-enroll-password")).not.toBeNull();
  });

  // -- error handling during revocation --

  it("shows inline error on INVALID_PASSWORD during revocation", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: true,
    });
    mockRevoke.mockRejectedValue(
      JSON.stringify({
        code: "INVALID_PASSWORD",
        message: "Incorrect password. Please try again.",
      }),
    );

    const { findByTestId, getByTestId } = render(() => <BiometricSettings />);

    await findByTestId("biometric-status");

    // Toggle OFF
    fireEvent.click(getByTestId("switch-trigger"));

    // Enter wrong password
    await waitFor(() => {
      expect(document.getElementById("biometric-revoke-password")).not.toBeNull();
    });
    const pwInput = document.getElementById("biometric-revoke-password") as HTMLInputElement;
    fireEvent.input(pwInput, { target: { value: "wrong" } });

    // Submit
    fireEvent.click(getByTestId("biometric-revoke-btn"));

    // Error should appear inline
    const errorEl = await findByTestId("biometric-error");
    expect(errorEl.textContent).toBe("Incorrect password. Please try again.");

    // Re-auth form should still be visible
    expect(document.getElementById("biometric-revoke-password")).not.toBeNull();
  });

  // -- toggle disabled when hardware not available --

  it("toggle is disabled when biometric hardware not available", async () => {
    mockBiometricAvailable = false;
    mockBiometricProvider = "None";

    mockCheckAvailability.mockResolvedValue({
      available: false,
      providerName: "None",
      enrolled: false,
    });

    const { findByText, getByTestId } = render(() => <BiometricSettings />);

    await findByText(/not available/);

    const trigger = getByTestId("switch-trigger") as HTMLButtonElement;
    expect(trigger.disabled).toBe(true);
  });

  // -- cancel reverts to idle --

  it("cancel button reverts to idle state", async () => {
    mockCheckAvailability.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: false,
    });

    const { findByTestId, getByText, getByTestId } = render(() => <BiometricSettings />);

    await findByTestId("biometric-status");

    // Toggle ON
    fireEvent.click(getByTestId("switch-trigger"));

    // Re-auth form appears
    await waitFor(() => {
      expect(document.getElementById("biometric-enroll-password")).not.toBeNull();
    });

    // Click cancel
    fireEvent.click(getByText("Cancel"));

    // Re-auth form should disappear
    await waitFor(() => {
      expect(document.getElementById("biometric-enroll-password")).toBeNull();
    });
  });
});
