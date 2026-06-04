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
  /** Helper text shown under the field (announced via aria-describedby) */
  hint?: string;
  /** Marks the field required — shows an indicator on the label */
  required?: boolean;
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
    "label", "value", "onInput", "error", "hint", "required", "type",
    "placeholder", "disabled", "class", "id", "autocomplete",
  ]);

  const inputId = local.id ?? createUniqueId();
  const errorId = `${inputId}-error`;
  const hintId = `${inputId}-hint`;

  // Wire both error and hint into aria-describedby when present.
  const describedBy = () =>
    [local.error ? errorId : "", local.hint ? hintId : ""]
      .filter(Boolean)
      .join(" ") || undefined;

  const handleInput: JSX.EventHandler<HTMLInputElement, InputEvent> = (e) => {
    local.onInput?.(e.currentTarget.value);
  };

  return (
    <div class={`${styles.wrapper} ${local.class ?? ""}`.trim()}>
      <label class={styles.label} for={inputId}>
        {local.label}
        <Show when={local.required}>
          <span class={styles.required} aria-hidden="true">*</span>
        </Show>
      </label>
      <input
        class={`${styles.input} ${local.error ? styles.inputError : ""}`.trim()}
        id={inputId}
        type={local.type ?? "text"}
        value={local.value ?? ""}
        placeholder={local.placeholder}
        disabled={local.disabled}
        required={local.required}
        autocomplete={local.autocomplete}
        aria-invalid={local.error ? "true" : undefined}
        aria-describedby={describedBy()}
        onInput={handleInput}
      />
      <Show when={local.hint}>
        <p class={styles.hint} id={hintId}>
          {local.hint}
        </p>
      </Show>
      <Show when={local.error}>
        <p class={styles.error} id={errorId} role="alert">
          {local.error}
        </p>
      </Show>
    </div>
  );
};
