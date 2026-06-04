import { render, fireEvent } from "@solidjs/testing-library";
import { createSignal } from "solid-js";
import { Modal } from "../../components/Modal";
import styles from "../../components/Modal.module.css";

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

  describe("size", () => {
    it("defaults to md size when size prop is omitted", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T">
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      expect(panel.classList.contains(styles.sizeMd)).toBe(true);
      expect(panel.classList.contains(styles.sizeSm)).toBe(false);
      expect(panel.classList.contains(styles.sizeLg)).toBe(false);
    });

    it("applies sm size class", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T" size="sm">
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      expect(panel.classList.contains(styles.sizeSm)).toBe(true);
      expect(panel.classList.contains(styles.sizeMd)).toBe(false);
    });

    it("applies md size class", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T" size="md">
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      expect(panel.classList.contains(styles.sizeMd)).toBe(true);
    });

    it("applies lg size class", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T" size="lg">
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      expect(panel.classList.contains(styles.sizeLg)).toBe(true);
      expect(panel.classList.contains(styles.sizeMd)).toBe(false);
    });

    it("preserves a caller-supplied class alongside the size class", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T" size="lg" class="custom-panel">
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      expect(panel.classList.contains(styles.content)).toBe(true);
      expect(panel.classList.contains(styles.sizeLg)).toBe(true);
      expect(panel.classList.contains("custom-panel")).toBe(true);
    });
  });

  describe("sticky layout", () => {
    it("places the scrollable body between the pinned header and footer", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T" actions={<button>OK</button>}>
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      const header = panel.querySelector(`.${styles.header}`) as HTMLElement;
      const body = panel.querySelector(`.${styles.body}`) as HTMLElement;
      const actions = panel.querySelector(`.${styles.actions}`) as HTMLElement;

      expect(header).toBeTruthy();
      expect(body).toBeTruthy();
      expect(actions).toBeTruthy();

      // header → body → actions, in document order, as direct children of the panel.
      const order = Array.from(panel.children);
      expect(order.indexOf(header)).toBeLessThan(order.indexOf(body));
      expect(order.indexOf(body)).toBeLessThan(order.indexOf(actions));
    });

    it("keeps the title inside the header and content inside the body", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="My Title">
          <p>Modal body text</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      const header = panel.querySelector(`.${styles.header}`) as HTMLElement;
      const body = panel.querySelector(`.${styles.body}`) as HTMLElement;

      expect(header.textContent).toContain("My Title");
      expect(body.textContent).toContain("Modal body text");
    });

    it("omits the actions footer when no actions are provided", () => {
      render(() => (
        <Modal open={true} onClose={() => {}} title="T">
          <p>Body</p>
        </Modal>
      ));
      const panel = document.querySelector("[role='dialog']") as HTMLElement;
      expect(panel.querySelector(`.${styles.actions}`)).toBeNull();
    });
  });
});
