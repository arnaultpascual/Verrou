import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { ImportStep } from "../../../features/onboarding/ImportStep";
import { vaultState, setVaultState } from "../../../stores/vaultStore";

// Mock useToast
const mockToast = {
  success: vi.fn(),
  error: vi.fn(),
  info: vi.fn(),
  dismiss: vi.fn(),
  clear: vi.fn(),
};

vi.mock("../../../components", async (importOriginal) => {
  const original = await importOriginal<Record<string, unknown>>();
  return {
    ...original,
    useToast: () => mockToast,
  };
});

// Mock ImportWizard to isolate ImportStep tests
const mockImportWizard = vi.fn();
let capturedOnComplete: ((count?: number) => void) | null = null;
vi.mock("../../../features/import/ImportWizard", () => ({
  ImportWizard: (props: { onComplete: (count?: number) => void; onCancel: () => void; embedded?: boolean }) => {
    mockImportWizard(props);
    capturedOnComplete = props.onComplete;
    return (
      <div data-testid="import-wizard">
        <button onClick={() => props.onComplete(5)}>Complete Import</button>
        <button onClick={() => props.onComplete(1)}>Complete Import Single</button>
        <button onClick={() => props.onComplete(0)}>Complete Import Zero</button>
        <button onClick={() => props.onCancel()}>Cancel Import</button>
      </div>
    );
  },
}));

function renderImportStep() {
  return render(() => (
    <MemoryRouter
      root={(props) => <>{props.children}</>}
    >
      <Route path="/*" component={() => <ImportStep />} />
    </MemoryRouter>
  ));
}

describe("ImportStep", () => {
  beforeEach(() => {
    setVaultState("no-vault");
    mockToast.success.mockClear();
    mockToast.error.mockClear();
    mockImportWizard.mockClear();
    capturedOnComplete = null;
  });

  it("renders heading and description", () => {
    const { getByText } = renderImportStep();
    expect(getByText("Import Existing Entries")).toBeDefined();
    expect(getByText(/import 2FA codes from other apps/)).toBeDefined();
  });

  it("renders import option (enabled)", () => {
    const { getByText } = renderImportStep();
    expect(getByText("Import from another app")).toBeDefined();
    expect(getByText("Google Authenticator, Aegis, 2FAS")).toBeDefined();
  });

  it("import button is enabled", () => {
    const { container } = renderImportStep();
    const buttons = container.querySelectorAll("button");
    const importBtn = Array.from(buttons).find(
      (b) => b.textContent?.includes("Import from another app")
    );
    expect(importBtn).toBeDefined();
    expect(importBtn!.disabled).toBe(false);
  });

  it("renders start empty option", () => {
    const { getByText } = renderImportStep();
    expect(getByText("Start with empty vault")).toBeDefined();
    expect(getByText("You can always add entries later.")).toBeDefined();
  });

  it("sets vault state to unlocked when starting empty", () => {
    const { container } = renderImportStep();
    const buttons = container.querySelectorAll("button");
    const startBtn = Array.from(buttons).find(
      (b) => b.textContent?.includes("Start with empty vault")
    );
    expect(startBtn).toBeDefined();
    fireEvent.click(startBtn!);
    expect(vaultState()).toBe("unlocked");
  });

  it("shows success toast when starting empty", () => {
    const { container } = renderImportStep();
    const buttons = container.querySelectorAll("button");
    const startBtn = Array.from(buttons).find(
      (b) => b.textContent?.includes("Start with empty vault")
    );
    fireEvent.click(startBtn!);
    expect(mockToast.success).toHaveBeenCalledWith("Vault created successfully");
  });

  it("renders icon SVGs", () => {
    const { container } = renderImportStep();
    const svgs = container.querySelectorAll("svg");
    expect(svgs.length).toBeGreaterThanOrEqual(2);
  });

  describe("import wizard integration", () => {
    it("shows ImportWizard when import option is clicked", async () => {
      const { container } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(container.querySelector("[data-testid='import-wizard']")).toBeTruthy();
      });
    });

    it("hides heading, description, and option cards when ImportWizard is shown", async () => {
      const { container, queryByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(queryByText("Import Existing Entries")).toBeNull();
        expect(queryByText(/import 2FA codes from other apps/)).toBeNull();
        expect(queryByText("Start with empty vault")).toBeNull();
      });
    });

    it("passes embedded prop to ImportWizard", async () => {
      const { container } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(mockImportWizard).toHaveBeenCalledWith(
          expect.objectContaining({ embedded: true }),
        );
      });
    });

    it("returns to option cards when ImportWizard cancel is triggered", async () => {
      const { container, getByText, queryByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(container.querySelector("[data-testid='import-wizard']")).toBeTruthy();
      });

      fireEvent.click(getByText("Cancel Import"));

      await waitFor(() => {
        expect(queryByText("Start with empty vault")).toBeDefined();
        expect(container.querySelector("[data-testid='import-wizard']")).toBeNull();
      });
    });

    it("sets vault state to unlocked on import complete", async () => {
      const { container, getByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(container.querySelector("[data-testid='import-wizard']")).toBeTruthy();
      });

      fireEvent.click(getByText("Complete Import"));
      expect(vaultState()).toBe("unlocked");
    });

    it("shows welcoming toast with import count on completion", async () => {
      const { container, getByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(container.querySelector("[data-testid='import-wizard']")).toBeTruthy();
      });

      fireEvent.click(getByText("Complete Import"));
      expect(mockToast.success).toHaveBeenCalledWith(
        "Entries imported successfully",
      );
    });

    it("shows same toast when import count is 1", async () => {
      const { container, getByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(container.querySelector("[data-testid='import-wizard']")).toBeTruthy();
      });

      fireEvent.click(getByText("Complete Import Single"));
      expect(mockToast.success).toHaveBeenCalledWith(
        "Entries imported successfully",
      );
    });

    it("shows fallback toast when import count is 0", async () => {
      const { container, getByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(container.querySelector("[data-testid='import-wizard']")).toBeTruthy();
      });

      fireEvent.click(getByText("Complete Import Zero"));
      expect(mockToast.success).toHaveBeenCalledWith(
        "Your vault is ready",
      );
    });

    it("shows fallback toast when import count is undefined", async () => {
      const { container, getByText } = renderImportStep();
      const buttons = container.querySelectorAll("button");
      const importBtn = Array.from(buttons).find(
        (b) => b.textContent?.includes("Import from another app")
      );
      fireEvent.click(importBtn!);

      await waitFor(() => {
        expect(capturedOnComplete).not.toBeNull();
      });

      // Call onComplete with no arguments (undefined count)
      capturedOnComplete!();
      expect(mockToast.success).toHaveBeenCalledWith(
        "Your vault is ready",
      );
    });
  });
});
