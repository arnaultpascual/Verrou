import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock Tauri APIs
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({
    hide: vi.fn().mockResolvedValue(undefined),
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

  it("shows keyboard hints", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      expect(container.textContent).toContain("navigate");
      expect(container.textContent).toContain("copy");
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

  it("copies username on Enter for credential entry", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    // Type query to filter to credential entry
    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "gitlab" } });

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(1);
    });

    const wrapper = container.firstElementChild as HTMLElement;
    fireEvent.keyDown(wrapper, { key: "Enter" });

    await waitFor(() => {
      expect(ipc.copyToClipboard).toHaveBeenCalledWith("dev@gitlab.com");
    });
  });

  it("does not call generateTotpCode for credential Enter", async () => {
    const { container } = render(() => <QuickSearch />);

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(4);
    });

    const input = container.querySelector("input[role='combobox']") as HTMLInputElement;
    fireEvent.input(input, { target: { value: "gitlab" } });

    await waitFor(() => {
      const items = container.querySelectorAll("[role='option']");
      expect(items.length).toBe(1);
    });

    // Record call count before Enter press
    const callCountBefore = (ipc.generateTotpCode as ReturnType<typeof vi.fn>).mock.calls.length;

    const wrapper = container.firstElementChild as HTMLElement;
    fireEvent.keyDown(wrapper, { key: "Enter" });

    await waitFor(() => {
      expect(ipc.copyToClipboard).toHaveBeenCalledWith("dev@gitlab.com");
    });

    // No new generateTotpCode calls after Enter
    const callCountAfter = (ipc.generateTotpCode as ReturnType<typeof vi.fn>).mock.calls.length;
    expect(callCountAfter).toBe(callCountBefore);
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
});
