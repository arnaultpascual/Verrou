import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Tauri window mock — expose onFocusChanged callback so tests can fire it
// ---------------------------------------------------------------------------
let focusChangedCallback: ((event: { payload: boolean }) => void) | undefined;
const mockUnlisten = vi.fn();
const mockHide = vi.fn().mockResolvedValue(undefined);

vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    onFocusChanged: vi.fn().mockImplementation((cb: (e: { payload: boolean }) => void) => {
      focusChangedCallback = cb;
      return Promise.resolve(mockUnlisten);
    }),
    hide: mockHide,
  }),
}));

// ---------------------------------------------------------------------------
// useToast mock
// ---------------------------------------------------------------------------
const mockToast = { success: vi.fn(), error: vi.fn(), info: vi.fn(), dismiss: vi.fn(), clear: vi.fn() };
vi.mock("../../../components/useToast", () => ({
  useToast: () => mockToast,
}));

// ---------------------------------------------------------------------------
// Kobalte toast mock
// ---------------------------------------------------------------------------
vi.mock("@kobalte/core/toast", () => ({
  Region: (props: { children: unknown }) => props.children,
  List: () => null,
  Root: (props: { children: unknown }) => props.children,
  Description: (props: { children: unknown }) => props.children,
  CloseButton: () => null,
  toaster: { show: vi.fn(), dismiss: vi.fn(), clear: vi.fn() },
}));

// ---------------------------------------------------------------------------
// entries/ipc mock — spy-able module
// ---------------------------------------------------------------------------
vi.mock("../../../features/entries/ipc", async (importOriginal) => {
  const orig = await importOriginal<Record<string, unknown>>();
  return { ...orig };
});

import * as ipc from "../../../features/entries/ipc";
import type { EntryMetadataDto } from "../../../features/entries/ipc";
import { EntryDetailView } from "../../../features/quick-access/EntryDetailView";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const CREDENTIAL_ENTRY: EntryMetadataDto = {
  id: "cred-1",
  entryType: "credential",
  name: "Test Login",
  issuer: "example.com",
  username: "user@example.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

const HOTP_ENTRY: EntryMetadataDto = {
  id: "hotp-1",
  entryType: "hotp",
  name: "HOTP Account",
  issuer: "hotp-provider.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Simulates the Tauri window losing focus. */
const simulateFocusLoss = () => {
  focusChangedCallback?.({ payload: false });
};

// ---------------------------------------------------------------------------
// CredentialDetail tests
// ---------------------------------------------------------------------------

describe("EntryDetailView — CredentialDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    focusChangedCallback = undefined;
    vi.spyOn(ipc, "revealPassword").mockResolvedValue({
      password: "s3cr3t-p@ssw0rd",
      username: "user@example.com",
      urls: [],
      notes: "",
      customFields: [],
      passwordHistory: [],
    });
    vi.spyOn(ipc, "copyToClipboard").mockResolvedValue(undefined);
  });

  it("shows masked password initially (no secret in DOM)", async () => {
    const { container } = render(() => (
      <EntryDetailView entry={CREDENTIAL_ENTRY} onBack={vi.fn()} />
    ));

    // Bullet masks should be visible, actual secret must not be
    await waitFor(() => {
      expect(container.textContent).toContain("••••••••");
      expect(container.textContent).not.toContain("s3cr3t-p@ssw0rd");
    });
  });

  it("reveals password only after re-auth (calls revealPassword with provided password)", async () => {
    const { container, getByPlaceholderText } = render(() => (
      <EntryDetailView entry={CREDENTIAL_ENTRY} onBack={vi.fn()} />
    ));

    // Click Reveal to open the re-auth form
    await waitFor(() => {
      const revealBtn = container.querySelector("button[class*='revealBtn']") as HTMLButtonElement | null;
      expect(revealBtn).not.toBeNull();
      fireEvent.click(revealBtn!);
    });

    // Type master password and submit
    await waitFor(() => {
      const input = getByPlaceholderText("Enter master password") as HTMLInputElement;
      fireEvent.input(input, { target: { value: "master123" } });
    });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(ipc.revealPassword).toHaveBeenCalledWith("cred-1", "master123");
    });

    // Secret should appear in DOM
    await waitFor(() => {
      expect(container.textContent).toContain("s3cr3t-p@ssw0rd");
    });
  });

  it("clears revealed password when focus is lost", async () => {
    const { container, getByPlaceholderText } = render(() => (
      <EntryDetailView entry={CREDENTIAL_ENTRY} onBack={vi.fn()} />
    ));

    // Reveal the password
    await waitFor(() => {
      const revealBtn = container.querySelector("button[class*='revealBtn']") as HTMLButtonElement | null;
      expect(revealBtn).not.toBeNull();
      fireEvent.click(revealBtn!);
    });

    await waitFor(() => {
      const input = getByPlaceholderText("Enter master password") as HTMLInputElement;
      fireEvent.input(input, { target: { value: "master123" } });
    });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    // Wait for password to appear
    await waitFor(() => {
      expect(container.textContent).toContain("s3cr3t-p@ssw0rd");
    });

    // Simulate window losing focus
    simulateFocusLoss();

    // Secret must be cleared from DOM
    await waitFor(() => {
      expect(container.textContent).not.toContain("s3cr3t-p@ssw0rd");
    });
  });

  it("clears revealed password when manual hide button is clicked", async () => {
    const { container, getByPlaceholderText } = render(() => (
      <EntryDetailView entry={CREDENTIAL_ENTRY} onBack={vi.fn()} />
    ));

    // Reveal
    await waitFor(() => {
      const revealBtn = container.querySelector("button[class*='revealBtn']") as HTMLButtonElement | null;
      expect(revealBtn).not.toBeNull();
      fireEvent.click(revealBtn!);
    });

    await waitFor(() => {
      const input = getByPlaceholderText("Enter master password") as HTMLInputElement;
      fireEvent.input(input, { target: { value: "master123" } });
    });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(container.textContent).toContain("s3cr3t-p@ssw0rd");
    });

    // Click the hide button
    const hideBtn = container.querySelector("button[class*='hideBtn']") as HTMLButtonElement | null;
    expect(hideBtn).not.toBeNull();
    fireEvent.click(hideBtn!);

    await waitFor(() => {
      expect(container.textContent).not.toContain("s3cr3t-p@ssw0rd");
    });
  });

  it("clears revealed password when the 30s auto-hide timer expires", async () => {
    vi.useFakeTimers();

    const { container, getByPlaceholderText } = render(() => (
      <EntryDetailView entry={CREDENTIAL_ENTRY} onBack={vi.fn()} />
    ));

    // Reveal
    await waitFor(() => {
      const revealBtn = container.querySelector("button[class*='revealBtn']") as HTMLButtonElement | null;
      expect(revealBtn).not.toBeNull();
      fireEvent.click(revealBtn!);
    });

    await waitFor(() => {
      const input = getByPlaceholderText("Enter master password") as HTMLInputElement;
      fireEvent.input(input, { target: { value: "master123" } });
    });

    const form = container.querySelector("form") as HTMLFormElement;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(container.textContent).toContain("s3cr3t-p@ssw0rd");
    });

    // Advance fake timers by 31 seconds to trigger auto-hide
    vi.advanceTimersByTime(31_000);

    await waitFor(() => {
      expect(container.textContent).not.toContain("s3cr3t-p@ssw0rd");
    });

    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// HotpDetail tests
// ---------------------------------------------------------------------------

describe("EntryDetailView — HotpDetail", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    focusChangedCallback = undefined;
    vi.spyOn(ipc, "generateTotpCode").mockResolvedValue({
      code: "987654",
      remainingSeconds: 0,
    });
    vi.spyOn(ipc, "copyToClipboard").mockResolvedValue(undefined);
  });

  it("displays the HOTP code fetched on mount", async () => {
    const { container } = render(() => (
      <EntryDetailView entry={HOTP_ENTRY} onBack={vi.fn()} />
    ));

    await waitFor(() => {
      expect(container.textContent).toContain("987");
    });
  });

  it("clears the HOTP code when focus is lost", async () => {
    const { container } = render(() => (
      <EntryDetailView entry={HOTP_ENTRY} onBack={vi.fn()} />
    ));

    // Wait for code to appear
    await waitFor(() => {
      expect(container.textContent).toContain("987");
    });

    // Simulate window blur
    simulateFocusLoss();

    // Code must be cleared (empty string renders as nothing meaningful)
    await waitFor(() => {
      expect(container.textContent).not.toContain("987654");
    });
  });

  it("clears the HOTP code on cleanup (component unmount)", async () => {
    let codeInDom = false;

    const { container, unmount } = render(() => (
      <EntryDetailView entry={HOTP_ENTRY} onBack={vi.fn()} />
    ));

    await waitFor(() => {
      codeInDom = container.textContent?.includes("987") ?? false;
      expect(codeInDom).toBe(true);
    });

    unmount();

    // After unmount, the DOM should be empty
    expect(container.textContent).not.toContain("987654");
  });
});
