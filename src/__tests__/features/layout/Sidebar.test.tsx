import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { MemoryRouter, Route } from "@solidjs/router";
import { Sidebar } from "../../../features/layout/Sidebar";

function renderSidebar(collapsed = false, onToggle = vi.fn()) {
  return render(() => (
    <MemoryRouter root={(props) => (
      <>
        <Sidebar collapsed={collapsed} onToggle={onToggle} />
        {props.children}
      </>
    )}>
      <Route path="/" component={() => null} />
      <Route path="/entries" component={() => null} />
    </MemoryRouter>
  ));
}

describe("Sidebar", () => {
  it("renders nav element with label", () => {
    const { container } = renderSidebar();
    const nav = container.querySelector('nav[aria-label="Navigation"]');
    expect(nav).not.toBeNull();
  });

  it("renders all navigation items when expanded", () => {
    const { getByText } = renderSidebar(false);
    expect(getByText("All")).toBeDefined();
    expect(getByText("TOTP")).toBeDefined();
    expect(getByText("Seeds")).toBeDefined();
    expect(getByText("Recovery")).toBeDefined();
    expect(getByText("Notes")).toBeDefined();
    expect(getByText("Passwords")).toBeDefined();
    expect(getByText("Health")).toBeDefined();
    expect(getByText("Import")).toBeDefined();
  });

  it("hides nav labels when collapsed", () => {
    const { queryByText } = renderSidebar(true);
    expect(queryByText("All")).toBeNull();
    expect(queryByText("TOTP")).toBeNull();
    expect(queryByText("Seeds")).toBeNull();
    expect(queryByText("Recovery")).toBeNull();
    expect(queryByText("Notes")).toBeNull();
    expect(queryByText("Passwords")).toBeNull();
    expect(queryByText("Health")).toBeNull();
    expect(queryByText("Import")).toBeNull();
  });

  it("renders collapse toggle button", () => {
    const { getByLabelText } = renderSidebar(false);
    expect(getByLabelText("Collapse sidebar")).toBeDefined();
  });

  it("renders expand toggle button when collapsed", () => {
    const { getByLabelText } = renderSidebar(true);
    expect(getByLabelText("Expand sidebar")).toBeDefined();
  });

  it("calls onToggle when collapse button is clicked", async () => {
    const onToggle = vi.fn();
    const { getByLabelText } = renderSidebar(false, onToggle);
    await fireEvent.click(getByLabelText("Collapse sidebar"));
    expect(onToggle).toHaveBeenCalledOnce();
  });

  it("renders navigation links as anchor elements", () => {
    const { container } = renderSidebar();
    const links = container.querySelectorAll("a");
    expect(links.length).toBe(8);
  });

  it("shows folders section with folder UI when expanded", () => {
    const { getByText } = renderSidebar(false);
    expect(getByText("Folders")).toBeDefined();
    expect(getByText("All Entries")).toBeDefined();
    expect(getByText("New Folder")).toBeDefined();
  });

  it("hides folders section labels when collapsed", () => {
    const { queryByText } = renderSidebar(true);
    expect(queryByText("Folders")).toBeNull();
    expect(queryByText("New Folder")).toBeNull();
  });

  it("sets data-collapsed attribute when collapsed", () => {
    const { container } = renderSidebar(true);
    const nav = container.querySelector("nav");
    expect(nav?.getAttribute("data-collapsed")).toBe("true");
  });

  it("does not set data-collapsed when expanded", () => {
    const { container } = renderSidebar(false);
    const nav = container.querySelector("nav");
    expect(nav?.getAttribute("data-collapsed")).toBeNull();
  });

  it("renders SVG icons for each nav item", () => {
    const { container } = renderSidebar();
    const svgs = container.querySelectorAll("svg");
    // 6 nav items + 1 collapse toggle = 7 minimum
    expect(svgs.length).toBeGreaterThanOrEqual(7);
  });

  it("shows tooltip titles when collapsed", () => {
    const { container } = renderSidebar(true);
    const links = container.querySelectorAll("a[title]");
    expect(links.length).toBe(8);
  });

  it("does not show tooltip titles when expanded", () => {
    const { container } = renderSidebar(false);
    const links = container.querySelectorAll("a[title]");
    expect(links.length).toBe(0);
  });
});
