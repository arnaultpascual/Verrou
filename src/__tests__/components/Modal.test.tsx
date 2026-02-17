import { render, fireEvent } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { Modal } from "../../components/Modal";

describe("Modal", () => {
  it("renders nothing when closed", () => {
    const { container } = render(() => (
      <Modal open={false} onClose={() => {}} title="Test">
        <p>Body</p>
      </Modal>
    ));
    expect(container.querySelector("[role='dialog']")).toBeNull();
  });

  it("renders dialog when open", () => {
    const { container } = render(() => (
      <Modal open={true} onClose={() => {}} title="Test Modal">
        <p>Content here</p>
      </Modal>
    ));
    const dialog = document.querySelector("[role='dialog']");
    expect(dialog).toBeTruthy();
  });

  it("displays title", () => {
    render(() => (
      <Modal open={true} onClose={() => {}} title="My Title">
        <p>Body</p>
      </Modal>
    ));
    expect(document.body.textContent).toContain("My Title");
  });

  it("displays children content", () => {
    render(() => (
      <Modal open={true} onClose={() => {}} title="T">
        <p>Modal body text</p>
      </Modal>
    ));
    expect(document.body.textContent).toContain("Modal body text");
  });

  it("displays actions", () => {
    render(() => (
      <Modal
        open={true}
        onClose={() => {}}
        title="T"
        actions={<button>Confirm</button>}
      >
        <p>Body</p>
      </Modal>
    ));
    expect(document.body.textContent).toContain("Confirm");
  });

  it("calls onClose when close button is clicked", () => {
    const onClose = vi.fn();
    render(() => (
      <Modal open={true} onClose={onClose} title="T">
        <p>Body</p>
      </Modal>
    ));
    const closeBtn = document.querySelector("[aria-label='Close']") as HTMLElement;
    expect(closeBtn).toBeTruthy();
    fireEvent.click(closeBtn);
    expect(onClose).toHaveBeenCalled();
  });

  it("has close button with aria-label", () => {
    render(() => (
      <Modal open={true} onClose={() => {}} title="T">
        <p>Body</p>
      </Modal>
    ));
    const closeBtn = document.querySelector("[aria-label='Close']");
    expect(closeBtn).toBeTruthy();
  });

  it("calls onClose on Escape key", () => {
    const onClose = vi.fn();
    render(() => (
      <Modal open={true} onClose={onClose} title="T">
        <p>Body</p>
      </Modal>
    ));
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });
});
