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

// Mock the IPC module.
vi.mock("../../../features/password-health/ipc", () => {
  return {
    getPasswordHealth: vi.fn(async () => {
      return {
        overallScore: 65,
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
      expect(getByText("65")).toBeTruthy();
    });
  });

  it("renders four category cards", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Reused Passwords")).toBeTruthy();
      expect(getByText("Weak Passwords")).toBeTruthy();
      expect(getByText("Old Passwords")).toBeTruthy();
      expect(getByText("No 2FA Linked")).toBeTruthy();
    });
  });

  it("shows correct counts in category cards", async () => {
    const { getByText, getAllByText } = renderPage();
    await waitFor(() => {
      expect(getByText("2")).toBeTruthy(); // reused
      expect(getAllByText("1").length).toBe(2); // weak and old both = 1
      expect(getByText("3")).toBeTruthy(); // no totp
    });
  });

  it("shows score label for needs attention range", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Needs attention")).toBeTruthy();
    });
  });

  it("shows issue summary", async () => {
    const { getByText } = renderPage();
    await waitFor(() => {
      expect(getByText(/7 issues found across 5 credentials/)).toBeTruthy();
    });
  });

  it("expands category card to show credential names on click", async () => {
    const { getByText, queryByText } = renderPage();
    await waitFor(() => {
      expect(getByText("Reused Passwords")).toBeTruthy();
    });

    // Credential names should not be visible before expanding.
    expect(queryByText("GitHub")).toBeFalsy();

    // Click "Reused Passwords" header to expand.
    fireEvent.click(getByText("Reused Passwords"));

    await waitFor(() => {
      expect(getByText("GitHub")).toBeTruthy();
      expect(getByText("GitLab")).toBeTruthy();
    });
  });

  it("renders refresh button", async () => {
    const { getByLabelText } = renderPage();
    await waitFor(() => {
      expect(getByLabelText("Refresh analysis")).toBeTruthy();
    });
  });
});
