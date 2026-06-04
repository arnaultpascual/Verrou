import type { Component, JSX } from "solid-js";
import { Show, splitProps } from "solid-js";
import { Spinner } from "./Spinner";
import styles from "./Button.module.css";

export interface ButtonProps {
  /** Visual variant */
  variant?: "primary" | "secondary" | "ghost" | "danger";
  /** Size — controls height, padding, and font-size (default "md") */
  size?: "sm" | "md" | "lg";
  /** Square button sized for a single centered icon child */
  iconOnly?: boolean;
  /** Stretch to fill the available width */
  fullWidth?: boolean;
  /** Button type attribute */
  type?: "button" | "submit" | "reset";
  /** Disabled state — uses aria-disabled for screen reader focus */
  disabled?: boolean;
  /** Loading state — shows spinner (+ loadingText if provided) */
  loading?: boolean;
  /** Optional label shown next to the spinner while loading. Spinner-only if omitted. */
  loadingText?: string;
  /** Click handler */
  onClick?: (e: MouseEvent) => void;
  /** Additional CSS class */
  class?: string;
  /** Button contents */
  children?: JSX.Element;
}

export const Button: Component<ButtonProps> = (props) => {
  const [local, rest] = splitProps(props, [
    "variant",
    "size",
    "iconOnly",
    "fullWidth",
    "type",
    "disabled",
    "loading",
    "loadingText",
    "onClick",
    "class",
    "children",
  ]);

  const variant = () => local.variant ?? "primary";
  const size = () => local.size ?? "md";
  const isDisabled = () => local.disabled || local.loading;

  const handleClick = (e: MouseEvent) => {
    if (isDisabled()) {
      e.preventDefault();
      return;
    }
    local.onClick?.(e);
  };

  const classes = () =>
    [
      styles.button,
      styles[variant()],
      styles[size()],
      local.iconOnly ? styles.iconOnly : "",
      local.fullWidth ? styles.fullWidth : "",
      local.class ?? "",
    ]
      .filter(Boolean)
      .join(" ");

  return (
    <button
      class={classes()}
      type={local.type ?? "button"}
      aria-disabled={isDisabled() || undefined}
      aria-busy={local.loading || undefined}
      onClick={handleClick}
      {...rest}
    >
      <Show when={local.loading} fallback={local.children}>
        <span class={styles.loadingContent}>
          <Spinner size={14} />
          <Show when={local.loadingText}>
            <span>{local.loadingText}</span>
          </Show>
        </span>
      </Show>
    </button>
  );
};
