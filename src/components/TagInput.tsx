/**
 * TagInput — chip-style tag input.
 *
 * Type a tag, press Enter or comma to add. Backspace removes the last tag.
 * Click the × on a chip to remove it.
 */

import type { Component } from "solid-js";
import { For, createSignal } from "solid-js";
import { Icon } from "./Icon";
import { t } from "../stores/i18nStore";
import styles from "./TagInput.module.css";

export interface TagInputProps {
  tags: string[];
  onChange: (tags: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
}

export const TagInput: Component<TagInputProps> = (props) => {
  const [inputValue, setInputValue] = createSignal("");

  const addTag = (raw: string) => {
    const tag = raw.trim().toLowerCase();
    if (!tag) return;
    if (props.tags.includes(tag)) return;
    props.onChange([...props.tags, tag]);
  };

  const removeTag = (index: number) => {
    props.onChange(props.tags.filter((_, i) => i !== index));
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    const value = inputValue();

    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      if (value.trim()) {
        addTag(value);
        setInputValue("");
      }
    } else if (e.key === "Backspace" && !value && props.tags.length > 0) {
      removeTag(props.tags.length - 1);
    }
  };

  const handleInput = (value: string) => {
    // If user pastes text with commas, split into multiple tags
    if (value.includes(",")) {
      const parts = value.split(",");
      // Add all complete parts as tags, keep the last part in input
      for (let i = 0; i < parts.length - 1; i++) {
        addTag(parts[i]);
      }
      setInputValue(parts[parts.length - 1]);
    } else {
      setInputValue(value);
    }
  };

  return (
    <div class={styles.wrapper}>
      <div class={styles.container}>
        <For each={props.tags}>
          {(tag, index) => (
            <span class={styles.chip}>
              <span class={styles.chipText}>{tag}</span>
              <button
                class={styles.chipRemove}
                type="button"
                onClick={() => removeTag(index())}
                aria-label={t("components.tagInput.removeTag", { tag })}
                disabled={props.disabled}
              >
                <Icon name="x" size={12} />
              </button>
            </span>
          )}
        </For>
        <input
          class={styles.input}
          type="text"
          value={inputValue()}
          onInput={(e) => handleInput(e.currentTarget.value)}
          onKeyDown={handleKeyDown}
          placeholder={props.tags.length === 0 ? (props.placeholder ?? t("components.tagInput.addTags")) : ""}
          disabled={props.disabled}
        />
      </div>
    </div>
  );
};
