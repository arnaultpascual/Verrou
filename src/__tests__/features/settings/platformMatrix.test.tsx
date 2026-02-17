import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, waitFor } from "@solidjs/testing-library";

// ---------------------------------------------------------------------------
// Platform store mock — controls capabilities per test
// ---------------------------------------------------------------------------
let mockBiometricAvailable = false;
let mockBiometricProvider = "None";
let mockHwSecurityAvailable = false;
let mockHwSecurityProvider = "None";

vi.mock("../../../stores/platformStore", () => ({
  isBiometricAvailable: () => mockBiometricAvailable,
  biometricProviderName: () => mockBiometricProvider,
  isHardwareSecurityAvailable: () => mockHwSecurityAvailable,
  hardwareSecurityProviderName: () => mockHwSecurityProvider,
  platformLoaded: () => true,
  platformCapabilities: () => ({
    osType: "unknown",
    biometricAvailable: mockBiometricAvailable,
    biometricProviderName: mockBiometricProvider,
    hardwareSecurityAvailable: mockHwSecurityAvailable,
    hardwareSecurityProviderName: mockHwSecurityProvider,
  }),
  initPlatformCapabilities: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Biometric IPC mock (enrollment status only)
// ---------------------------------------------------------------------------
const mockCheckBiometric = vi.fn();
vi.mock("../../../features/vault/biometricIpc", () => ({
  checkBiometricAvailability: (...args: unknown[]) =>
    mockCheckBiometric(...args),
  enrollBiometric: vi.fn(),
  revokeBiometric: vi.fn(),
}));

vi.mock("../../../features/vault/ipc", () => ({
  parseUnlockError: vi.fn((errorStr: string) => {
    try {
      return JSON.parse(errorStr);
    } catch {
      return { code: "UNKNOWN", message: errorStr };
    }
  }),
  getVaultDir: vi.fn(() => "/mock/vault"),
}));

// ---------------------------------------------------------------------------
// Hardware key IPC mock (enabled status only)
// ---------------------------------------------------------------------------
const mockCheckHwSecurity = vi.fn();
vi.mock("../../../features/vault/hardwareKeyIpc", () => ({
  checkHardwareSecurity: (...args: unknown[]) =>
    mockCheckHwSecurity(...args),
}));

// Mock useToast
vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => ({
      success: vi.fn(),
      error: vi.fn(),
      info: vi.fn(),
      dismiss: vi.fn(),
      clear: vi.fn(),
    }),
  };
});

// Mock Kobalte Switch
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

import { BiometricSettings } from "../../../features/settings/BiometricSettings";
import { HardwareSecurityStatus } from "../../../features/settings/HardwareSecurityStatus";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Platform capability matrix", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockBiometricAvailable = false;
    mockBiometricProvider = "None";
    mockHwSecurityAvailable = false;
    mockHwSecurityProvider = "None";
  });

  // -- Matrix: both available --

  it("both available — biometric shows toggle, hardware shows active", async () => {
    mockBiometricAvailable = true;
    mockBiometricProvider = "Touch ID";
    mockHwSecurityAvailable = true;
    mockHwSecurityProvider = "Secure Enclave";

    mockCheckBiometric.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: true,
    });
    mockCheckHwSecurity.mockResolvedValue({
      available: true,
      providerName: "Secure Enclave",
      enabled: true,
    });

    const { findByTestId: findBio } = render(() => <BiometricSettings />);
    const bioStatus = await findBio("biometric-status");
    expect(bioStatus.textContent).toBe("Touch ID enabled");

    const { findByTestId: findHw } = render(() => <HardwareSecurityStatus />);
    const hwStatus = await findHw("hw-status");
    expect(hwStatus.textContent).toBe("Secure Enclave active");
  });

  // -- Matrix: biometric only --

  it("biometric only — toggle enabled, hardware shows unavailable", async () => {
    mockBiometricAvailable = true;
    mockBiometricProvider = "Touch ID";
    mockHwSecurityAvailable = false;
    mockHwSecurityProvider = "None";

    mockCheckBiometric.mockResolvedValue({
      available: true,
      providerName: "Touch ID",
      enrolled: false,
    });
    mockCheckHwSecurity.mockResolvedValue({
      available: false,
      providerName: "None",
      enabled: false,
    });

    const { findByTestId: findBio } = render(() => <BiometricSettings />);
    const bioStatus = await findBio("biometric-status");
    expect(bioStatus.textContent).toBe("Not enrolled");

    const { findByTestId: findHw } = render(() => <HardwareSecurityStatus />);
    const hwMsg = await findHw("hw-unavailable");
    expect(hwMsg.textContent).toContain("not available");
  });

  // -- Matrix: hardware only --

  it("hardware only — biometric unavailable, hardware shows active", async () => {
    mockBiometricAvailable = false;
    mockBiometricProvider = "None";
    mockHwSecurityAvailable = true;
    mockHwSecurityProvider = "TPM 2.0";

    mockCheckBiometric.mockResolvedValue({
      available: false,
      providerName: "None",
      enrolled: false,
    });
    mockCheckHwSecurity.mockResolvedValue({
      available: true,
      providerName: "TPM 2.0",
      enabled: true,
    });

    const { findByText } = render(() => <BiometricSettings />);
    const unavailMsg = await findByText(/not available on this device/);
    expect(unavailMsg).toBeDefined();

    const { findByTestId: findHw } = render(() => <HardwareSecurityStatus />);
    const hwStatus = await findHw("hw-status");
    expect(hwStatus.textContent).toBe("TPM 2.0 active");
  });

  // -- Matrix: neither available --

  it("neither available — both show unavailable, no errors", async () => {
    mockBiometricAvailable = false;
    mockBiometricProvider = "None";
    mockHwSecurityAvailable = false;
    mockHwSecurityProvider = "None";

    mockCheckBiometric.mockResolvedValue({
      available: false,
      providerName: "None",
      enrolled: false,
    });
    mockCheckHwSecurity.mockResolvedValue({
      available: false,
      providerName: "None",
      enabled: false,
    });

    const { findByText } = render(() => <BiometricSettings />);
    const bioMsg = await findByText(/not available on this device/);
    expect(bioMsg).toBeDefined();

    const { findByTestId: findHw } = render(() => <HardwareSecurityStatus />);
    const hwMsg = await findHw("hw-unavailable");
    expect(hwMsg.textContent).toContain("not available");
  });

  // -- VM scenario --

  it("VM scenario — all false, clean UI, no errors", async () => {
    mockBiometricAvailable = false;
    mockBiometricProvider = "None";
    mockHwSecurityAvailable = false;
    mockHwSecurityProvider = "None";

    mockCheckBiometric.mockResolvedValue({
      available: false,
      providerName: "None",
      enrolled: false,
    });
    mockCheckHwSecurity.mockResolvedValue({
      available: false,
      providerName: "None",
      enabled: false,
    });

    const { getByTestId, findByText } = render(() => <BiometricSettings />);
    await findByText(/not available on this device/);

    // Toggle should be disabled
    const trigger = getByTestId("switch-trigger") as HTMLButtonElement;
    expect(trigger.disabled).toBe(true);

    const { findByTestId: findHw } = render(() => <HardwareSecurityStatus />);
    const hwMsg = await findHw("hw-unavailable");
    expect(hwMsg.textContent).toContain("software encryption only");
  });
});
