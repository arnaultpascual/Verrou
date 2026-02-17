/**
 * BIP39WordInput — single word input with autocomplete suggestions.
 *
 * Calls Rust backend via IPC for prefix matching and validation.
 * Never receives the full BIP39 wordlist (NFR22).
 */

import {
  type Component,
  type JSX,
  createSignal,
  createUniqueId,
  Show,
  For,
  onCleanup,
} from "solid-js";
import { Icon } from "../../components/Icon";
import { suggestWords, validateWord } from "./ipc";
import styles from "./BIP39WordInput.module.css";

export interface BIP39WordInputProps {
  /** Word position (0-based) */
  index: number;
  /** Total word count for accessibility label */
  total: number;
  /** Current word value */
  value: string;
  /** BIP39 language (e.g. "english") */
  language: string;
  /** Called when the input value changes */
  onChange: (value: string) => void;
  /** Called when validation completes */
  onValidated: (index: number, valid: boolean) => void;
  /** Disabled state */
  disabled?: boolean;
  /** External ref setter for focusing */
  ref?: (el: HTMLInputElement) => void;
}

export const BIP39WordInput: Component<BIP39WordInputProps> = (props) => {
  const inputId = createUniqueId();
  const errorId = `${inputId}-error`;
  const listboxId = `${inputId}-listbox`;

  const [suggestions, setSuggestions] = createSignal<string[]>([]);
  const [showDropdown, setShowDropdown] = createSignal(false);
  const [activeIndex, setActiveIndex] = createSignal(-1);
  const [validationState, setValidationState] = createSignal<
    "idle" | "valid" | "invalid"
  >("idle");

  let debounceTimer: ReturnType<typeof setTimeout> | undefined;
  let inputRef: HTMLInputElement | undefined;

  onCleanup(() => {
    if (debounceTimer) clearTimeout(debounceTimer);
  });

  const fetchSuggestions = (prefix: string) => {
    if (debounceTimer) clearTimeout(debounceTimer);

    if (prefix.length < 1) {
      setSuggestions([]);
      setShowDropdown(false);
      return;
    }

    debounceTimer = setTimeout(async () => {
      const results = await suggestWords(prefix, props.language, 5);
      setSuggestions(results);
      setShowDropdown(results.length > 0);
      setActiveIndex(-1);
    }, 150);
  };

  const selectSuggestion = async (word: string) => {
    props.onChange(word);
    setSuggestions([]);
    setShowDropdown(false);
    setActiveIndex(-1);

    const result = await validateWord(word, props.language);
    setValidationState(result.valid ? "valid" : "invalid");
    props.onValidated(props.index, result.valid);
  };

  const handleInput: JSX.EventHandler<HTMLInputElement, InputEvent> = (e) => {
    const value = e.currentTarget.value.toLowerCase().trim();
    props.onChange(value);
    setValidationState("idle");
    fetchSuggestions(value);
  };

  const handleBlur = async () => {
    // Delay to allow suggestion click to fire first
    setTimeout(async () => {
      setShowDropdown(false);
      setActiveIndex(-1);

      if (props.value.length > 0) {
        const result = await validateWord(props.value, props.language);
        setValidationState(result.valid ? "valid" : "invalid");
        props.onValidated(props.index, result.valid);
      } else {
        setValidationState("idle");
      }
    }, 150);
  };

  const handleKeyDown: JSX.EventHandler<HTMLInputElement, KeyboardEvent> = (
    e,
  ) => {
    const items = suggestions();
    if (!showDropdown() || items.length === 0) {
      return;
    }

    switch (e.key) {
      case "ArrowDown": {
        e.preventDefault();
        setActiveIndex((prev) => Math.min(prev + 1, items.length - 1));
        break;
      }
      case "ArrowUp": {
        e.preventDefault();
        setActiveIndex((prev) => Math.max(prev - 1, 0));
        break;
      }
      case "Enter": {
        e.preventDefault();
        const idx = activeIndex();
        if (idx >= 0 && idx < items.length) {
          selectSuggestion(items[idx]);
        }
        break;
      }
      case "Escape": {
        e.preventDefault();
        setShowDropdown(false);
        setActiveIndex(-1);
        break;
      }
    }
  };

  const inputClass = () => {
    const base = styles.input;
    const state = validationState();
    if (state === "valid") return `${base} ${styles.inputValid}`;
    if (state === "invalid") return `${base} ${styles.inputInvalid}`;
    return base;
  };

  const activeDescendant = () => {
    const idx = activeIndex();
    if (idx >= 0) return `${listboxId}-option-${idx}`;
    return undefined;
  };

  return (
    <div class={styles.wrapper}>
      <label class={styles.label} for={inputId}>
        Word {props.index + 1}
      </label>
      <input
        ref={(el) => {
          inputRef = el;
          props.ref?.(el);
        }}
        class={inputClass()}
        id={inputId}
        type="text"
        value={props.value}
        disabled={props.disabled}
        autocomplete="off"
        spellcheck={false}
        role="combobox"
        aria-expanded={showDropdown()}
        aria-controls={listboxId}
        aria-activedescendant={activeDescendant()}
        aria-label={`Word ${props.index + 1} of ${props.total}`}
        aria-invalid={validationState() === "invalid" ? "true" : undefined}
        aria-describedby={
          validationState() === "invalid" ? errorId : undefined
        }
        onInput={handleInput}
        onBlur={handleBlur}
        onKeyDown={handleKeyDown}
      />

      {/* Status icon */}
      <Show when={validationState() !== "idle"}>
        <span
          class={`${styles.statusIcon} ${
            validationState() === "valid"
              ? styles.statusIconValid
              : styles.statusIconInvalid
          }`}
        >
          <Icon
            name={validationState() === "valid" ? "check" : "alert"}
            size={14}
          />
        </span>
      </Show>

      {/* Suggestions dropdown */}
      <Show when={showDropdown() && suggestions().length > 0}>
        <ul class={styles.dropdown} id={listboxId} role="listbox">
          <For each={suggestions()}>
            {(word, i) => (
              <li
                id={`${listboxId}-option-${i()}`}
                class={`${styles.suggestion} ${
                  i() === activeIndex() ? styles.suggestionActive : ""
                }`.trim()}
                role="option"
                aria-selected={i() === activeIndex()}
                onMouseDown={(e) => {
                  e.preventDefault();
                  selectSuggestion(word);
                }}
              >
                {word}
              </li>
            )}
          </For>
        </ul>
      </Show>

      {/* Error message */}
      <Show when={validationState() === "invalid"}>
        <p class={styles.error} id={errorId} role="alert">
          Not a valid BIP39 word.
        </p>
      </Show>
    </div>
  );
};
