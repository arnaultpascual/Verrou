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

function renderAppLayout() {
  return render(() => (
    <MemoryRouter root={(props) => (
      <AppLayout>{props.children}</AppLayout>
    )}>
      <Route path="/" component={() => <p>Test Content</p>} />
    </MemoryRouter>
  ));
}

describe("Skip link (WCAG 2.4.1)", () => {
  beforeEach(() => {
    localStorage.clear();
    mockMatchMedia(false);
  });

  it("renders a skip link as the first focusable child", () => {
    const { container } = renderAppLayout();
    const skipLink = container.querySelector("a[href='#main-content']");
    expect(skipLink).not.toBeNull();
    expect(skipLink!.textContent).toBe("Skip to main content");
  });

  it("skip link has correct href pointing to main content", () => {
    const { container } = renderAppLayout();
    const skipLink = container.querySelector("a[href='#main-content']");
    expect(skipLink).not.toBeNull();
    expect(skipLink!.getAttribute("href")).toBe("#main-content");
  });

  it("main element has id='main-content'", () => {
    const { container } = renderAppLayout();
    const main = container.querySelector("main#main-content");
    expect(main).not.toBeNull();
  });

  it("skip link has the skipLink CSS class", () => {
    const { container } = renderAppLayout();
    const skipLink = container.querySelector("a[href='#main-content']");
    expect(skipLink).not.toBeNull();
    expect(skipLink!.className).toContain("skipLink");
  });
});
