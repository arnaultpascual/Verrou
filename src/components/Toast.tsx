import type { Component } from "solid-js";
import { Show } from "solid-js";
import { Root, Description, CloseButton } from "@kobalte/core/toast";
import { Icon, type IconName } from "./Icon";
import { t } from "../stores/i18nStore";
import styles from "./Toast.module.css";

export type ToastVariant = "success" | "error" | "info";

export interface ToastData {
  variant: ToastVariant;
  message: string;
}

const VARIANT_ICONS: Record<ToastVariant, IconName> = {
  success: "check",
  error: "alert",
  info: "info",
};

/** Duration overrides per variant (ms) */
const VARIANT_DURATIONS: Record<ToastVariant, number | undefined> = {
  success: 1000,
  info: 3000,
  error: undefined, // persistent — handled via persistent prop
};

/** Individual toast content — rendered inside Kobalte's Toast region */
export const ToastContent: Component<{
  toastId: number;
  variant: ToastVariant;
  message: string;
}> = (props) => {
  const persistent = () => props.variant === "error";
  const duration = () => VARIANT_DURATIONS[props.variant];

  return (
    <Root
      toastId={props.toastId}
      class={`${styles.toast} ${styles[props.variant]}`}
      persistent={persistent()}
      duration={duration()}
    >
      <div class={styles.content}>
        <Icon name={VARIANT_ICONS[props.variant]} size={16} />
        <Description class={styles.message}>
          {props.message}
        </Description>
      </div>
      <Show when={persistent()}>
        <CloseButton class={styles.closeBtn} aria-label={t("components.toast.dismiss")}>
          <Icon name="x" size={14} />
        </CloseButton>
      </Show>
    </Root>
  );
};
