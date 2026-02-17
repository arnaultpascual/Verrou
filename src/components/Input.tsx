import type { Component, JSX } from "solid-js";
import { Show, splitProps, createUniqueId } from "solid-js";
import styles from "./Input.module.css";

export interface InputProps {
  /** Visible label (required — never placeholder-only) */
  label: string;
  /** Current value */
  value?: string;
  /** Input handler */
  onInput?: (value: string) => void;
  /** Error message — displays below input in danger color */
  error?: string;
  /** Input type */
  type?: "text" | "password" | "email" | "url" | "number";
  /** Placeholder text */
  placeholder?: string;
  /** Disabled state */
  disabled?: boolean;
  /** Additional CSS class on wrapper */
  class?: string;
  /** Custom id (auto-generated if omitted) */
  id?: string;
  /** Autocomplete attribute */
  autocomplete?: string;
}

export const Input: Component<InputProps> = (props) => {
  const [local, rest] = splitProps(props, [
    "label", "value", "onInput", "error", "type", "placeholder",
    "disabled", "class", "id", "autocomplete",
  ]);

  const inputId = local.id ?? createUniqueId();
  const errorId = `${inputId}-error`;

  const handleInput: JSX.EventHandler<HTMLInputElement, InputEvent> = (e) => {
    local.onInput?.(e.currentTarget.value);
  };

  return (
    <div class={`${styles.wrapper} ${local.class ?? ""}`.trim()}>
      <label class={styles.label} for={inputId}>
        {local.label}
      </label>
      <input
        class={`${styles.input} ${local.error ? styles.inputError : ""}`.trim()}
        id={inputId}
        type={local.type ?? "text"}
        value={local.value ?? ""}
        placeholder={local.placeholder}
        disabled={local.disabled}
        autocomplete={local.autocomplete}
        aria-invalid={local.error ? "true" : undefined}
        aria-describedby={local.error ? errorId : undefined}
        onInput={handleInput}
      />
      <Show when={local.error}>
        <p class={styles.error} id={errorId} role="alert">
          {local.error}
        </p>
      </Show>
    </div>
  );
};
