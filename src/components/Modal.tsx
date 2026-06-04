import type { Component, JSX } from "solid-js";
import { Show, splitProps } from "solid-js";
import { Dialog } from "@kobalte/core/dialog";
import { Icon } from "./Icon";
import { t } from "../stores/i18nStore";
import styles from "./Modal.module.css";

export interface ModalProps {
  /** Controlled open state */
  open: boolean;
  /** Called when dialog should close */
  onClose: () => void;
  /** Dialog title (required for accessibility) */
  title: string;
  /** Panel max-width: sm 400px / md 480px / lg 640px (default "md") */
  size?: "sm" | "md" | "lg";
  /** Whether clicking the overlay closes the dialog (default true) */
  closeOnOverlayClick?: boolean;
  /** Dialog body content */
  children?: JSX.Element;
  /** Action buttons at the bottom */
  actions?: JSX.Element;
  /** Additional CSS class for the content panel */
  class?: string;
}

const SIZE_CLASS: Record<NonNullable<ModalProps["size"]>, string> = {
  sm: styles.sizeSm,
  md: styles.sizeMd,
  lg: styles.sizeLg,
};

export const Modal: Component<ModalProps> = (props) => {
  const [local] = splitProps(props, [
    "open", "onClose", "title", "size", "closeOnOverlayClick", "children", "actions", "class",
  ]);

  const closeOnOverlay = () => local.closeOnOverlayClick ?? true;
  const sizeClass = () => SIZE_CLASS[local.size ?? "md"];

  const handleInteractOutside = (e: Event) => {
    if (!closeOnOverlay()) {
      e.preventDefault();
    }
  };

  return (
    <Dialog open={local.open} onOpenChange={(open) => { if (!open) local.onClose(); }} modal>
      <Dialog.Portal>
        <Dialog.Overlay class={styles.overlay} />
        <Dialog.Content
          class={`${styles.content} ${sizeClass()} ${local.class ?? ""}`.trim()}
          onInteractOutside={handleInteractOutside}
        >
          <div class={styles.header}>
            <Dialog.Title class={styles.title}>{local.title}</Dialog.Title>
            <Dialog.CloseButton class={styles.closeBtn} aria-label={t("components.modal.close")}>
              <Icon name="x" size={18} />
            </Dialog.CloseButton>
          </div>

          <div class={styles.body}>
            {local.children}
          </div>

          <Show when={local.actions}>
            <div class={styles.actions}>
              {local.actions}
            </div>
          </Show>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog>
  );
};
