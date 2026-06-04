import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock Tauri APIs — a shared `hide` spy so tests can assert the popup dismisses.
const hideMock = vi.fn().mockResolvedValue(undefined);
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    hide: hideMock,
    onFocusChanged: vi.fn().mockResolvedValue(() => {}),
  }),
}));

// Mock useToast
vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    success: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    dismiss: vi.fn(),
    clear: vi.fn(),
  }),
}));

// Mock Kobalte toast
vi.mock("@kobalte/core/toast", () => ({
  Region: (props: { children: unknown }) => props.children,
  List: () => null,
  Root: (props: { children: unknown }) => props.children,
  Description: (props: { children: unknown }) => props.children,
  CloseButton: () => null,
  toaster: { show: vi.fn(), dismiss: vi.fn(), clear: vi.fn() },
}));

import { QuickSearch } from "../../../features/quick-access/QuickSearch";
import * as ipc from "../../../features/entries/ipc";
import type { EntryMetadataDto } from "../../../features/entries/ipc";

const MOCK_ENTRIES: EntryMetadataDto[] = [
  {
    id: "entry-1",
    entryType: "totp",
    name: "GitHub",
    issuer: "github.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: true,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "entry-2",
    entryType: "totp",
    name: "Google",
    issuer: "google.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "entry-3",
    entryType: "seed_phrase",
    name: "Bitcoin Wallet",
    issuer: "ledger.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
  {
    id: "entry-4",
    entryType: "credential",
    name: "GitLab Login",
    issuer: "gitlab.com",
    username: "dev@gitlab.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    pinned: false,
    createdAt: "2026-01-01T00:00:00Z",
    updatedAt: "2026-01-01T00:00:00Z",
  },
];

const HOTP_ENTRY: EntryMetadataDto = {
  id: "entry-hotp",
  entryType: "hotp",
  name: "Legacy VPN",
  issuer: "vpn.corp.example.com",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

describe("QuickSearch", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(ipc, "listEntries").mockResolvedValue(MOCK_ENTRIES);
    vi.spyOn(ipc, "generateTotpCode").mockResolvedValue({
      code: "123456",
      remainingSeconds: 15,
    });
    vi.spyOn(ipc, "copyToClipboard").mockResolvedValue(undefined);
  });

  it("renders search input with combobox role", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const input = container.querySelector("input[role='combobox']");
      expect(input).not.toBeNull();
    });
  });

  it("loads and displays entries on mount", async () => {
    const { getByText } = render(() => <QuickSearch />);

    await waitFor(() => {
      expect(getByText("GitHub")).toBeDefined();
      expect(getByText("Google")).toBeDefined();
      expect(getByText("Bitcoin Wallet")).toBeDefined();
      expect(getByText("GitLab Login")).toBeDefined();
    });
  });

  it("shows pinned entries first", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
      // GitHub is pinned, should be first
      expect(items[0].textContent).toContain("GitHub");
    });
  });

  it("filters entries on search input", async () => {
    const { container, queryByText } = render(() => <QuickSearch />);

    await waitFor(() => {
      expect(queryByText("GitHub")).not.toBeNull();
    });

    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "goo" } });

    await waitFor(() => {
      expect(queryByText("Google")).not.toBeNull();
      expect(queryByText("Bitcoin Wallet")).toBeNull();
    });
  });

  it("auto-selects first result", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items[0].getAttribute("aria-selected")).toBe("true");
    });
  });

  it("navigates with arrow keys", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    const wrapper = container.firstElementChild as HTMLElement;

    // Arrow down
    fireEvent.keyDown(wrapper, { key: "ArrowDown" });
    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items[1].getAttribute("aria-selected")).toBe("true");
    });

    // Arrow up wraps around
    fireEvent.keyDown(wrapper, { key: "ArrowUp" });
    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items[0].getAttribute("aria-selected")).toBe("true");
    });
  });

  it("shows empty state when no entries match", async () => {
    const { container, getByText } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "zzzzz" } });

    await waitFor(() => {
      expect(getByText("No matching entries")).toBeDefined();
    });
  });

  it("shows keyboard hints consistent with Enter = copy", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      expect(container.textContent).toContain("navigate");
      // Enter copies the primary value — the hint must say "copy", not "open".
      expect(container.textContent).toContain("copy");
      expect(container.textContent).not.toContain("open");
      expect(container.textContent).toContain("close");
    });
  });

  it("shows result count with aria-live", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const liveRegion = container.querySelector("[aria-live='polite']");
      expect(liveRegion).not.toBeNull();
      expect(liveRegion!.textContent).toContain("4");
    });
  });

  it("copies the live code and hides the popup on Enter for a TOTP entry", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    // Narrow to a single TOTP entry so the selected (index 0) result is GitHub.
    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "github" } });

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(1);
    });

    const wrapper = container.firstElementChild as HTMLElement;
    fireEvent.keyDown(wrapper, { key: "Enter" });

    // Enter copies the live code via the concealed-clipboard path…
    await waitFor(() => {
      expect(ipc.copyToClipboard).toHaveBeenCalledWith("123456");
    });
    // …and hides the popup instead of opening a detail screen.
    await waitFor(() => {
      expect(hideMock).toHaveBeenCalled();
    });
    expect(container.querySelector("input[role='combobox']")).not.toBeNull();
  });

  it("copies the live code on click for a TOTP entry without navigating", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      expect(container.querySelectorAll("[role='option']").length).toBe(4);
    });

    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "github" } });

    await waitFor(() => {
      expect(container.querySelectorAll("[role='option']").length).toBe(1);
    });

    const row = container.querySelector("[role='option']") as HTMLElement;
    fireEvent.click(row);

    await waitFor(() => {
      expect(ipc.copyToClipboard).toHaveBeenCalledWith("123456");
    });
    // Click behaves identically to Enter: copy + dismiss, no detail screen.
    expect(container.querySelector("input[role='combobox']")).not.toBeNull();
  });

  it("copies the username (not the password) on Enter for a credential with a username", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    // GitLab Login is a credential with username "dev@gitlab.com".
    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "gitlab" } });

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(1);
    });

    const wrapper = container.firstElementChild as HTMLElement;
    fireEvent.keyDown(wrapper, { key: "Enter" });

    // The username is display-safe and copied directly; the password is never
    // revealed from the list, so generateTotpCode is irrelevant here too.
    await waitFor(() => {
      expect(ipc.copyToClipboard).toHaveBeenCalledWith("dev@gitlab.com");
    });
    expect(ipc.generateTotpCode).not.toHaveBeenCalled();
    // Copy + dismiss — no detail navigation for the username fast-path.
    await waitFor(() => {
      expect(hideMock).toHaveBeenCalled();
    });
    expect(container.querySelector("input[role='combobox']")).not.toBeNull();
  });

  it("opens the detail view on Enter for a non-copyable entry (seed phrase)", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    // Bitcoin Wallet is a seed phrase — its secret needs reveal, so Enter must
    // open the detail view rather than copy anything from the list.
    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "bitcoin" } });

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(1);
    });

    const wrapper = container.firstElementChild as HTMLElement;
    fireEvent.keyDown(wrapper, { key: "Enter" });

    await waitFor(() => {
      expect(container.querySelector("input[role='combobox']")).toBeNull();
    });
    // Non-copyable rows never touch the clipboard.
    expect(ipc.copyToClipboard).not.toHaveBeenCalled();
  });

  it("resets selectedIndex when query changes", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    const wrapper = container.firstElementChild as HTMLElement;

    // Move selection down
    fireEvent.keyDown(wrapper, { key: "ArrowDown" });
    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items[1].getAttribute("aria-selected")).toBe("true");
    });

    // Type new query — should reset to 0
    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "g" } });

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      if (items.length > 0) {
        expect(items[0].getAttribute("aria-selected")).toBe("true");
      }
    });
  });

  describe("HOTP fast-path (Enter/click generates the next code)", () => {
    beforeEach(() => {
      // A single HOTP entry so the selected (index 0) result is the HOTP one.
      vi.spyOn(ipc, "listEntries").mockResolvedValue([HOTP_ENTRY]);
      vi.spyOn(ipc, "generateHotpCode").mockResolvedValue({
        code: "654321",
        counter: 42,
      });
    });

    it("generates + copies the next HOTP code and hides the popup on Enter", async () => {
      const { container } = render(() => <QuickSearch />);

      await waitFor(() => {
        expect(container.querySelectorAll("[role='option']").length).toBe(1);
      });

      const wrapper = container.firstElementChild as HTMLElement;
      fireEvent.keyDown(wrapper, { key: "Enter" });

      // Counter-based generation (not the time-based TOTP path).
      await waitFor(() => {
        expect(ipc.generateHotpCode).toHaveBeenCalledWith("entry-hotp");
        expect(ipc.copyToClipboard).toHaveBeenCalledWith("654321");
      });
      expect(ipc.generateTotpCode).not.toHaveBeenCalled();
      await waitFor(() => {
        expect(hideMock).toHaveBeenCalled();
      });
      // Stays on the search screen (no detail navigation for the copy fast-path).
      expect(container.querySelector("input[role='combobox']")).not.toBeNull();
    });

    it("generates + copies the next HOTP code on click", async () => {
      const { container } = render(() => <QuickSearch />);

      await waitFor(() => {
        expect(container.querySelectorAll("[role='option']").length).toBe(1);
      });

      const row = container.querySelector("[role='option']") as HTMLElement;
      fireEvent.click(row);

      await waitFor(() => {
        expect(ipc.generateHotpCode).toHaveBeenCalledWith("entry-hotp");
        expect(ipc.copyToClipboard).toHaveBeenCalledWith("654321");
      });
      expect(container.querySelector("input[role='combobox']")).not.toBeNull();
    });
  });
});
