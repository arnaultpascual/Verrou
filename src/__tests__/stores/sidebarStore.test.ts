import { describe, expect, it, beforeEach, vi } from "vitest";

// We need to re-import the module fresh for each test to avoid shared state
// SolidJS module-level signals persist, so we mock localStorage and test behavior

describe("sidebarStore", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.resetModules();
  });

  it("defaults to collapsed=false when localStorage is empty", async () => {
    const { sidebarCollapsed } = await import("../../stores/sidebarStore");
    expect(sidebarCollapsed()).toBe(false);
  });

  it("reads persisted collapsed=true from localStorage", async () => {
    localStorage.setItem("verrou:sidebar-collapsed", "true");
    const { sidebarCollapsed } = await import("../../stores/sidebarStore");
    expect(sidebarCollapsed()).toBe(true);
  });

  it("toggleSidebar switches collapsed state", async () => {
    const { sidebarCollapsed, toggleSidebar } = await import("../../stores/sidebarStore");
    expect(sidebarCollapsed()).toBe(false);
    toggleSidebar();
    expect(sidebarCollapsed()).toBe(true);
    toggleSidebar();
    expect(sidebarCollapsed()).toBe(false);
  });

  it("setSidebarCollapsed sets specific value", async () => {
    const { sidebarCollapsed, setSidebarCollapsed } = await import("../../stores/sidebarStore");
    setSidebarCollapsed(true);
    expect(sidebarCollapsed()).toBe(true);
    setSidebarCollapsed(false);
    expect(sidebarCollapsed()).toBe(false);
  });

  it("persists state to localStorage on change", async () => {
    const { setSidebarCollapsed } = await import("../../stores/sidebarStore");
    setSidebarCollapsed(true);
    expect(localStorage.getItem("verrou:sidebar-collapsed")).toBe("true");
    setSidebarCollapsed(false);
    expect(localStorage.getItem("verrou:sidebar-collapsed")).toBe("false");
  });

  it("toggleSidebar persists state", async () => {
    const { toggleSidebar } = await import("../../stores/sidebarStore");
    toggleSidebar();
    expect(localStorage.getItem("verrou:sidebar-collapsed")).toBe("true");
  });
});
