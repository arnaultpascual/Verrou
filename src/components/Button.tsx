import type { Component, JSX } from "solid-js";
import { Show, splitProps } from "solid-js";
import { Spinner } from "./Spinner";
import { t } from "../stores/i18nStore";
import styles from "./Button.module.css";

export interface ButtonProps {
  /** Visual variant */
  variant?: "primary" | "ghost" | "danger";
  /** Button type attribute */
  type?: "button" | "submit" | "reset";
  /** Disabled state — uses aria-disabled for screen reader focus */
  disabled?: boolean;
  /** Loading state — shows spinner + "Saving..." */
  loading?: boolean;
  /** Click handler */
  onClick?: (e: MouseEvent) => void;
  /** Additional CSS class */
  class?: string;
  /** Button contents */
  children?: JSX.Element;
}

export const Button: Component<ButtonProps> = (props) => {
  const [local, rest] = splitProps(props, [
    "variant", "type", "disabled", "loading", "onClick", "class", "children",
  ]);

  const variant = () => local.variant ?? "primary";
  const isDisabled = () => local.disabled || local.loading;

  const handleClick = (e: MouseEvent) => {
    if (isDisabled()) {
      e.preventDefault();
      return;
    }
    local.onClick?.(e);
  };

  return (
    <button
      class={`${styles.button} ${styles[variant()]} ${local.class ?? ""}`.trim()}
      type={local.type ?? "button"}
      aria-disabled={isDisabled() || undefined}
      aria-busy={local.loading || undefined}
      onClick={handleClick}
      {...rest}
    >
      <Show when={local.loading} fallback={local.children}>
        <span class={styles.loadingContent}>
          <Spinner size={14} />
          <span>{t("components.button.saving")}</span>
        </span>
      </Show>
    </button>
  );
};
