/**
 * SeedPhraseGrid — renders a grid of BIP39WordInput components.
 *
 * Supports 12/15/18/21/24 word counts in a 4-column layout.
 * Auto-focuses the first empty word input when wordCount changes.
 */

import { type Component, createEffect, For } from "solid-js";
import { BIP39WordInput } from "./BIP39WordInput";
import styles from "./SeedPhraseGrid.module.css";

export interface SeedPhraseGridProps {
  /** Number of words (12, 15, 18, 21, or 24) */
  wordCount: number;
  /** BIP39 language (e.g. "english") */
  language: string;
  /** Current word values */
  words: string[];
  /** Called when any word changes */
  onWordsChange: (words: string[]) => void;
  /** Per-word validation state */
  validationStates: boolean[];
  /** Called when a word's validation completes */
  onWordValidated: (index: number, valid: boolean) => void;
  /** Disabled state */
  disabled?: boolean;
}

export const SeedPhraseGrid: Component<SeedPhraseGridProps> = (props) => {
  const inputRefs: HTMLInputElement[] = [];

  const enteredCount = () =>
    props.words.filter((w) => w.length > 0).length;

  // Auto-focus first empty word input when wordCount changes
  createEffect(() => {
    const count = props.wordCount;
    // Wait for DOM to update
    requestAnimationFrame(() => {
      const firstEmpty = inputRefs.findIndex(
        (_, i) => i < count && (!props.words[i] || props.words[i].length === 0),
      );
      if (firstEmpty >= 0 && inputRefs[firstEmpty]) {
        inputRefs[firstEmpty].focus();
      }
    });
  });

  const handleWordChange = (index: number, value: string) => {
    const updated = [...props.words];
    updated[index] = value;
    props.onWordsChange(updated);
  };

  // Generate indices array for <For>
  const indices = () => Array.from({ length: props.wordCount }, (_, i) => i);

  return (
    <div>
      <div class={styles.grid}>
        <For each={indices()}>
          {(index) => (
            <BIP39WordInput
              index={index}
              total={props.wordCount}
              value={props.words[index] ?? ""}
              language={props.language}
              onChange={(value) => handleWordChange(index, value)}
              onValidated={props.onWordValidated}
              disabled={props.disabled}
              ref={(el) => {
                inputRefs[index] = el;
              }}
            />
          )}
        </For>
      </div>
      <p class={styles.completion}>
        {enteredCount()} of {props.wordCount} words entered
      </p>
    </div>
  );
};
