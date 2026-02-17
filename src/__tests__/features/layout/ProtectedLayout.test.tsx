import { render } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { ProtectedLayout } from "../../../features/layout/ProtectedLayout";
import { setVaultState } from "../../../stores/vaultStore";

function mockMatchMedia(matches: boolean) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
}

function renderProtected(content = "Protected Content") {
  return render(() => (
    <MemoryRouter
      root={(props) => (
        <ProtectedLayout>{props.children}</ProtectedLayout>
      )}
    >
      <Route path="/*" component={() => <p>{content}</p>} />
    </MemoryRouter>
  ));
}

describe("ProtectedLayout", () => {
  beforeEach(() => {
    localStorage.clear();
    mockMatchMedia(false);
  });

  it("renders children when vault is unlocked", () => {
    setVaultState("unlocked");
    const { getByText } = renderProtected();
    expect(getByText("Protected Content")).toBeDefined();
  });

  it("does not render children when vault is locked", () => {
    setVaultState("locked");
    const { queryByText } = renderProtected();
    expect(queryByText("Protected Content")).toBeNull();
  });

  it("does not render children when vault state is no-vault", () => {
    setVaultState("no-vault");
    const { queryByText } = renderProtected();
    expect(queryByText("Protected Content")).toBeNull();
  });

  it("renders AppLayout shell when unlocked", () => {
    setVaultState("unlocked");
    const { container } = renderProtected();
    expect(container.querySelector("header")).not.toBeNull();
    expect(container.querySelector("nav")).not.toBeNull();
    expect(container.querySelector("main")).not.toBeNull();
    expect(container.querySelector("footer")).not.toBeNull();
  });

  it("hides AppLayout shell when locked", () => {
    setVaultState("locked");
    const { container } = renderProtected();
    expect(container.querySelector("header")).toBeNull();
    expect(container.querySelector("nav")).toBeNull();
    expect(container.querySelector("main")).toBeNull();
    expect(container.querySelector("footer")).toBeNull();
  });
});
