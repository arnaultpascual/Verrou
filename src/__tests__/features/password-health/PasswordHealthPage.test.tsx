import { render, fireEvent, waitFor } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { PasswordHealthPage } from "../../../features/password-health/PasswordHealthPage";
import type { PasswordHealthReport } from "../../../features/password-health/ipc";

// Mock useToast
vi.mock("../../../components/useToast", () => ({
  useToast: () => ({
    info: vi.fn(),
    success: vi.fn(),
    error: vi.fn(),
    warning: vi.fn(),
  }),
}));

// Stub EditCredentialModal — we only assert the page wires it (open + entryId).
// It always renders so the test can read its data attributes; `open` reflects state.
vi.mock("../../../features/credentials/EditCredentialModal", () => ({
  EditCredentialModal: (props: { open: boolean; entryId: string }) => (
    <div
      data-testid="edit-credential-modal"
      data-open={String(props.open)}
      data-entry-id={props.entryId}
    />
  ),
}));

// Mock the IPC module. 5 credentials: 2 reused + 1 weak + 1 old = 4 password
// issues across 5×3 = 15 checks → score 74. 2FA is separate (3 without).
vi.mock("../../../features/password-health/ipc", () => {
  return {
    getPasswordHealth: vi.fn(async () => {
      return {
        overallScore: 74,
        totalCredentials: 5,
        reusedCount: 2,
        reusedGroups: [
          {
            credentials: [
              { id: "1", name: "GitHub" },
              { id: "2", name: "GitLab" },
            ],
          },
        ],
        weakCount: 1,
        weakCredentials: [{ id: "3", name: "Old Forum", strength: "weak" }],
        oldCount: 1,
        oldCredentials: [
          {
            id: "4",
            name: "Legacy Service",
            daysSinceChange: 400,
            severity: "danger",
          },
        ],
        noTotpCount: 3,
        noTotpCredentials: [
          { id: "3", name: "Old Forum" },
          { id: "4", name: "Legacy Service" },
          { id: "5", name: "Personal Blog" },
        ],
      } satisfies PasswordHealthReport;
    }),
  };
});

function renderPage() {
  return render(() => (
    <MemoryRouter root={(props) => <>{props.children}</>}>
      <Route path="/" component={PasswordHealthPage} />
    </MemoryRouter>
  ));
}

beforeEach(() => {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("PasswordHealthPage", () => {
  it("renders the page title", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Password Health")).toBeTruthy();
    });
  });

  it("renders the overall score", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("74")).toBeTruthy();
    });
  });

  it("shows the Good score label for the 70+ range", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Good")).toBeTruthy();
    });
  });

  it("renders the three SCORED password categories", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Reused Passwords")).toBeTruthy();
      expect(getByText("Weak Passwords")).toBeTruthy();
      expect(getByText("Old Passwords")).toBeTruthy();
    });
  });

  it("counts only password issues in the summary (2FA excluded)", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      // 2 reused + 1 weak + 1 old = 4 (NOT 7 — the 3 missing-2FA are excluded).
      expect(getByText(/4 issues found across 5 credentials/)).toBeTruthy();
    });
  });

  it("shows 2FA coverage as a SEPARATE, non-scored section", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Two-factor coverage")).toBeTruthy();
      expect(getByText(/3 of 5 have no 2FA/)).toBeTruthy();
    });
  });

  it("explains how the score is computed", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("How is this scored?")).toBeTruthy();
    });
    fireEvent.click(getByText("How is this scored?"));
    await waitFor(() => {
      expect(
        getByText(/Two-factor coverage is tracked separately/),
      ).toBeTruthy();
    });
  });

  it("expands the reused category to reveal names + a 'shared with' chip", async () => {
    // GitHub/GitLab are reused-only (they have 2FA), so their names are unique
    // to the scored card — not duplicated in the coverage section below.
    const { getByText, getAllByText, queryByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Reused Passwords")).toBeTruthy();
    });

    expect(queryByText("GitHub")).toBeFalsy();
    fireEvent.click(getByText("Reused Passwords"));

    await waitFor(() => {
      expect(getByText("GitHub")).toBeTruthy();
      expect(getByText("GitLab")).toBeTruthy();
      // Both reused rows carry the chip → two matches.
      expect(getAllByText("shared with 1 more").length).toBe(2);
    });
  });

  it("humanizes a stale password's age into a chip", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Old Passwords")).toBeTruthy();
    });

    fireEvent.click(getByText("Old Passwords"));
    await waitFor(() => {
      // "400d" → a calm relative phrase (unique to the chip).
      expect(getByText("over a year ago")).toBeTruthy();
    });
  });

  it("opens the remediation modal for the right entry when Fix is clicked", async () => {
    const { getByText, getAllByTestId, queryAllByTestId, getByTestId } = renderPage();
    await waitFor(() => {
      expect(getByText("Weak Passwords")).toBeTruthy();
    });

    // Closed initially.
    expect(getByTestId("edit-credential-modal").getAttribute("data-open")).toBe(
      "false",
    );

    fireEvent.click(getByText("Weak Passwords")); // expand the weak card
    await waitFor(() => {
      expect(queryAllByTestId("health-fix-btn").length).toBeGreaterThan(0);
    });

    fireEvent.click(getAllByTestId("health-fix-btn")[0]);

    await waitFor(() => {
      const modal = getByTestId("edit-credential-modal");
      expect(modal.getAttribute("data-open")).toBe("true");
      expect(modal.getAttribute("data-entry-id")).toBe("3"); // Old Forum's id
    });
  });

  it("renders refresh button", async () => {
    const { getByLabelText } = renderPage();
    await waitFor(() => {
      expect(getByLabelText("Refresh analysis")).toBeTruthy();
    });
  });
});
