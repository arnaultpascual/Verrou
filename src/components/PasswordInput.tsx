import type { Component } from "solid-js";
import { Show, createSignal, createMemo, splitProps, createUniqueId } from "solid-js";
import { Icon } from "./Icon";
import { t } from "../stores/i18nStore";
import styles from "./PasswordInput.module.css";

export type PasswordStrength = "weak" | "fair" | "good" | "excellent";

export interface PasswordInputProps {
  /** Label text */
  label: string;
  /** create = strength meter + guidance; unlock = plain masked field */
  mode: "create" | "unlock";
  /** Current value */
  value?: string;
  /** Input handler */
  onInput?: (value: string) => void;
  /** Error message */
  error?: string;
  /** Disabled state */
  disabled?: boolean;
  /** Additional CSS class */
  class?: string;
  /** Placeholder text */
  placeholder?: string;
  /** Custom id */
  id?: string;
}

/** Basic password strength estimation */
export function evaluateStrength(password: string): PasswordStrength {
  if (!password || password.length < 4) return "weak";

  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  // Bonus for passphrase-like input (spaces between words)
  if (/\w+\s+\w+\s+\w+/.test(password)) score += 2;

  if (score <= 2) return "weak";
  if (score <= 4) return "fair";
  if (score <= 5) return "good";
  return "excellent";
}

const STRENGTH_KEYS: Record<PasswordStrength, string> = {
  weak: "components.passwordInput.strengthWeak",
  fair: "components.passwordInput.strengthFair",
  good: "components.passwordInput.strengthGood",
  excellent: "components.passwordInput.strengthExcellent",
};

const STRENGTH_WIDTHS: Record<PasswordStrength, number> = {
  weak: 25,
  fair: 50,
  good: 75,
  excellent: 100,
};

export const PasswordInput: Component<PasswordInputProps> = (props) => {
  const [local] = splitProps(props, [
    "label", "mode", "value", "onInput", "error", "disabled",
    "class", "placeholder", "id",
  ]);

  const [visible, setVisible] = createSignal(false);
  const inputId = local.id ?? createUniqueId();
  const errorId = `${inputId}-error`;
  const strengthId = `${inputId}-strength`;

  const strength = createMemo(() => {
    if (local.mode !== "create") return "weak";
    return evaluateStrength(local.value ?? "");
  });

  const toggleVisibility = () => setVisible((v) => !v);

  const handleInput = (e: InputEvent) => {
    const target = e.currentTarget as HTMLInputElement;
    local.onInput?.(target.value);
  };

  return (
    <div class={`${styles.wrapper} ${local.class ?? ""}`.trim()}>
      <label class={styles.label} for={inputId}>
        {local.label}
      </label>

      <div class={styles.inputRow}>
        <input
          class={`${styles.input} ${local.error ? styles.inputError : ""}`.trim()}
          id={inputId}
          type={visible() ? "text" : "password"}
          value={local.value ?? ""}
          placeholder={local.placeholder}
          disabled={local.disabled}
          autocomplete={local.mode === "create" ? "new-password" : "current-password"}
          aria-invalid={local.error ? "true" : undefined}
          aria-describedby={
            [
              local.error ? errorId : "",
              local.mode === "create" ? strengthId : "",
            ].filter(Boolean).join(" ") || undefined
          }
          onInput={handleInput}
        />
        <button
          type="button"
          class={styles.toggleBtn}
          onClick={toggleVisibility}
          aria-label={visible() ? t("components.passwordInput.hidePassword") : t("components.passwordInput.showPassword")}
          tabindex={-1}
        >
          <Icon name={visible() ? "eye-off" : "eye"} size={18} />
        </button>
      </div>

      <Show when={local.error}>
        <p class={styles.error} id={errorId} role="alert">
          {local.error}
        </p>
      </Show>

      <Show when={local.mode === "create"}>
        <div class={styles.strengthSection} id={strengthId}>
          <div class={styles.meterTrack}>
            <div
              class={`${styles.meterFill} ${styles[strength()]}`}
              style={{ width: `${STRENGTH_WIDTHS[strength()]}%` }}
              role="progressbar"
              aria-valuenow={STRENGTH_WIDTHS[strength()]}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={t("components.passwordInput.strengthAria", { level: t(STRENGTH_KEYS[strength()]) })}
            />
          </div>
          <span class={styles.strengthLabel}>
            {t(STRENGTH_KEYS[strength()])}
          </span>
        </div>
        <Show when={strength() === "weak" || strength() === "fair"}>
          <p class={styles.guidance}>
            {t("components.passwordInput.guidance")}
          </p>
        </Show>
      </Show>
    </div>
  );
};
