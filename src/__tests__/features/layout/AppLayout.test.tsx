import { render } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { AppLayout } from "../../../features/layout/AppLayout";

function mockMatchMedia(matches: boolean) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
}

function renderAppLayout(content?: string) {
  return render(() => (
    <MemoryRouter root={(props) => (
      <AppLayout>{props.children}</AppLayout>
    )}>
      <Route path="/" component={() => <p>{content ?? "Test Content"}</p>} />
    </MemoryRouter>
  ));
}

describe("AppLayout", () => {
  beforeEach(() => {
    localStorage.clear();
    mockMatchMedia(false);
  });

  it("renders the shell container", () => {
    const { container } = renderAppLayout();
    const shell = container.querySelector('[class*="shell"]');
    expect(shell).not.toBeNull();
  });

  it("renders header region", () => {
    const { container } = renderAppLayout();
    const header = container.querySelector("header");
    expect(header).not.toBeNull();
  });

  it("renders sidebar navigation", () => {
    const { container } = renderAppLayout();
    const nav = container.querySelector('nav[aria-label="Navigation"]');
    expect(nav).not.toBeNull();
  });

  it("renders footer region", () => {
    const { container } = renderAppLayout();
    const footer = container.querySelector("footer");
    expect(footer).not.toBeNull();
  });

  it("renders main content area", () => {
    const { container } = renderAppLayout();
    const main = container.querySelector("main");
    expect(main).not.toBeNull();
  });

  it("renders children in main content", () => {
    const { getByText } = renderAppLayout("Hello World");
    expect(getByText("Hello World")).toBeDefined();
  });

  it("renders all four layout regions (header, nav, main, footer)", () => {
    const { container } = renderAppLayout();
    expect(container.querySelector("header")).not.toBeNull();
    expect(container.querySelector("nav")).not.toBeNull();
    expect(container.querySelector("main")).not.toBeNull();
    expect(container.querySelector("footer")).not.toBeNull();
  });
});
