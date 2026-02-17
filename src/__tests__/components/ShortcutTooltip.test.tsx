import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi } from "vitest";
import { ShortcutTooltip } from "../../components/ShortcutTooltip";

describe("ShortcutTooltip", () => {
  it("renders children", () => {
    const { getByText } = render(() => (
      <ShortcutTooltip shortcut="Ctrl+B">
        <button>Toggle</button>
      </ShortcutTooltip>
    ));
    expect(getByText("Toggle")).toBeDefined();
  });

  it("children are interactive (click works)", () => {
    const onClick = vi.fn();
    const { getByText } = render(() => (
      <ShortcutTooltip shortcut="Ctrl+B">
        <button onClick={onClick}>Toggle</button>
      </ShortcutTooltip>
    ));
    fireEvent.click(getByText("Toggle"));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("does not show tooltip content by default", () => {
    const { queryByText } = render(() => (
      <ShortcutTooltip shortcut="Ctrl+B">
        <button>Toggle</button>
      </ShortcutTooltip>
    ));
    // Tooltip content is not rendered until triggered
    expect(queryByText("Ctrl+B")).toBeNull();
  });

  it("renders tooltip trigger wrapper as span (not button)", () => {
    const { container } = render(() => (
      <ShortcutTooltip shortcut="Ctrl+B">
        <button>Toggle</button>
      </ShortcutTooltip>
    ));
    // Trigger should be a span to avoid nested buttons
    const trigger = container.querySelector("span");
    expect(trigger).not.toBeNull();
    const button = trigger!.querySelector("button");
    expect(button).not.toBeNull();
    expect(button!.textContent).toBe("Toggle");
  });

  it("shows tooltip content with correct shortcut text on pointer enter", async () => {
    const { container } = render(() => (
      <ShortcutTooltip shortcut="Ctrl+Shift+L">
        <button>Lock</button>
      </ShortcutTooltip>
    ));
    const trigger = container.querySelector("span")!;
    // Kobalte tooltip opens on pointer enter (with delay)
    fireEvent.pointerEnter(trigger);
    // Wait for tooltip open delay + portal render
    await vi.waitFor(() => {
      const tooltipEl = document.body.querySelector("[role='tooltip']");
      expect(tooltipEl).not.toBeNull();
      expect(tooltipEl!.textContent).toContain("Ctrl+Shift+L");
    }, { timeout: 2000 });
  });
});
