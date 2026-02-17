import { render, fireEvent } from "@solidjs/testing-library";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { ConfirmDeleteModal } from "../../../features/entries/ConfirmDeleteModal";

describe("ConfirmDeleteModal", () => {
  const defaultProps = {
    open: true,
    entryName: "GitHub",
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
  };

  beforeEach(() => {
    defaultProps.onConfirm = vi.fn();
    defaultProps.onCancel = vi.fn();
  });

  function renderModal(overrides: Partial<typeof defaultProps> = {}) {
    const props = { ...defaultProps, ...overrides };
    return render(() => (
      <ConfirmDeleteModal
        open={props.open}
        entryName={props.entryName}
        onConfirm={props.onConfirm}
        onCancel={props.onCancel}
      />
    ));
  }

  function getDialog() {
    return document.querySelector("[role='dialog']");
  }

  describe("rendering (AC #2)", () => {
    it("renders dialog when open", () => {
      renderModal();
      expect(getDialog()).toBeTruthy();
    });

    it("does not render dialog when closed", () => {
      renderModal({ open: false });
      expect(getDialog()).toBeNull();
    });

    it("shows 'Delete Entry' title", () => {
      renderModal();
      expect(document.body.textContent).toContain("Delete Entry");
    });

    it("shows entry name in confirmation text", () => {
      renderModal({ entryName: "AWS Console" });
      expect(document.body.textContent).toContain("Delete 'AWS Console'?");
    });

    it("shows 'This action cannot be undone.' warning", () => {
      renderModal();
      expect(document.body.textContent).toContain("This action cannot be undone.");
    });

    it("shows Cancel and Delete buttons", () => {
      renderModal();
      const buttons = Array.from(document.querySelectorAll("button"));
      expect(buttons.some((b) => b.textContent === "Cancel")).toBe(true);
      expect(buttons.some((b) => b.textContent === "Delete")).toBe(true);
    });
  });

  describe("cancel flow (AC #4)", () => {
    it("calls onCancel when Cancel button is clicked", () => {
      renderModal();
      const cancelBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Cancel",
      );
      expect(cancelBtn).toBeTruthy();
      fireEvent.click(cancelBtn!);
      expect(defaultProps.onCancel).toHaveBeenCalled();
      expect(defaultProps.onConfirm).not.toHaveBeenCalled();
    });
  });

  describe("confirm flow (AC #3)", () => {
    it("calls onConfirm when Delete button is clicked", () => {
      renderModal();
      const deleteBtn = Array.from(document.querySelectorAll("button")).find(
        (b) => b.textContent === "Delete",
      );
      expect(deleteBtn).toBeTruthy();
      fireEvent.click(deleteBtn!);
      expect(defaultProps.onConfirm).toHaveBeenCalled();
      expect(defaultProps.onCancel).not.toHaveBeenCalled();
    });
  });

  describe("accessibility (AC #5)", () => {
    it("renders as a dialog", () => {
      renderModal();
      expect(getDialog()).toBeTruthy();
    });

    it("has dialog title 'Delete Entry'", () => {
      renderModal();
      const dialog = getDialog();
      expect(dialog).toBeTruthy();
      // Kobalte renders h2 with Dialog.Title
      const heading = dialog!.querySelector("h2");
      expect(heading?.textContent).toContain("Delete Entry");
    });

    it("calls onCancel when Escape key is pressed", () => {
      renderModal();
      const dialog = getDialog();
      expect(dialog).toBeTruthy();
      fireEvent.keyDown(dialog!, { key: "Escape" });
      expect(defaultProps.onCancel).toHaveBeenCalled();
    });
  });
});
