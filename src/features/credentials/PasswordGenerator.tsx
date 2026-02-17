import type { Component } from "solid-js";
import { Show, createSignal, createEffect, on } from "solid-js";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { evaluateStrength, type PasswordStrength } from "../../components/PasswordInput";
import { copyToClipboard } from "../entries/ipc";
import { generatePassword, type PasswordMode, type SeparatorType } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./PasswordGenerator.module.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STRENGTH_LABEL_KEYS: Record<PasswordStrength, string> = {
  weak: "credentials.generator.strengthWeak",
  fair: "credentials.generator.strengthFair",
  good: "credentials.generator.strengthGood",
  excellent: "credentials.generator.strengthExcellent",
};

const STRENGTH_WIDTHS: Record<PasswordStrength, number> = {
  weak: 25,
  fair: 50,
  good: 75,
  excellent: 100,
};

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface PasswordGeneratorProps {
  /** Called when the user clicks "Use this password". */
  onUse: (password: string) => void;
  /** Whether the panel starts expanded (default: false). */
  defaultExpanded?: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Count how many charset options are currently enabled. */
function enabledCharsetCount(u: boolean, l: boolean, d: boolean, s: boolean): number {
  return Number(u) + Number(l) + Number(d) + Number(s);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const PasswordGenerator: Component<PasswordGeneratorProps> = (props) => {
  const toast = useToast();

  // ── Panel state ──
  const [expanded, setExpanded] = createSignal(props.defaultExpanded ?? false);

  // ── Mode ──
  const [mode, setMode] = createSignal<PasswordMode>("random");

  // ── Random options ──
  const [length, setLength] = createSignal(20);
  const [uppercase, setUppercase] = createSignal(true);
  const [lowercase, setLowercase] = createSignal(true);
  const [digits, setDigits] = createSignal(true);
  const [symbols, setSymbols] = createSignal(true);

  // ── Passphrase options ──
  const [wordCount, setWordCount] = createSignal(5);
  const [separator, setSeparator] = createSignal<SeparatorType>("hyphen");
  const [capitalize, setCapitalize] = createSignal(false);
  const [appendDigit, setAppendDigit] = createSignal(false);

  // ── Output ──
  const [generated, setGenerated] = createSignal("");

  // ── Committed slider values (H1 fix: only fire IPC on slider release) ──
  const [committedLength, setCommittedLength] = createSignal(20);
  const [committedWordCount, setCommittedWordCount] = createSignal(5);

  // ── Generate function ──
  async function doGenerate() {
    try {
      const result = await generatePassword(
        mode() === "random"
          ? {
              mode: "random",
              length: committedLength(),
              uppercase: uppercase(),
              lowercase: lowercase(),
              digits: digits(),
              symbols: symbols(),
            }
          : {
              mode: "passphrase",
              wordCount: committedWordCount(),
              separator: separator(),
              capitalize: capitalize(),
              appendDigit: appendDigit(),
            },
      );
      setGenerated(result.value);
    } catch (err) {
      toast.error(t("credentials.generator.generationFailed", { error: String(err) }));
    }
  }

  // ── Auto-generate on expand or option change ──
  // Uses committedLength/committedWordCount (updated on slider release)
  // so dragging doesn't flood IPC.
  createEffect(
    on(
      () => [
        expanded(),
        mode(),
        committedLength(),
        uppercase(),
        lowercase(),
        digits(),
        symbols(),
        committedWordCount(),
        separator(),
        capitalize(),
        appendDigit(),
      ],
      () => {
        if (expanded()) {
          void doGenerate();
        }
      },
    ),
  );

  // ── Strength ──
  const strength = () => evaluateStrength(generated());

  // ── H3 fix: prevent unchecking the last enabled charset ──
  function isLastCharset(current: boolean, ...others: boolean[]): boolean {
    return current && others.every((o) => !o);
  }

  // ── Handlers ──
  async function handleCopy() {
    const val = generated();
    if (!val) return;
    try {
      await copyToClipboard(val);
      toast.success(t("credentials.generator.copied"));
    } catch {
      toast.error(t("credentials.generator.copyFailed"));
    }
  }

  function handleUse() {
    const val = generated();
    if (val) props.onUse(val);
  }

  return (
    <div class={styles.container}>
      {/* ── Header toggle ── */}
      <button
        type="button"
        class={styles.header}
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded()}
      >
        <span class={styles.headerLeft}>
          <Icon name="settings" size={14} />
          {t("credentials.generator.title")}
        </span>
        <Icon
          name="chevron-down"
          size={14}
          class={`${styles.chevron} ${expanded() ? styles.chevronOpen : ""}`.trim()}
        />
      </button>

      {/* ── Body ── */}
      <Show when={expanded()}>
        <div class={styles.body}>
          {/* Mode toggle */}
          <div class={styles.modeToggle} role="radiogroup" aria-label={t("credentials.generator.modeAria")}>
            <button
              type="button"
              class={`${styles.modeBtn} ${mode() === "random" ? styles.modeBtnActive : ""}`.trim()}
              onClick={() => setMode("random")}
              role="radio"
              aria-checked={mode() === "random"}
            >
              {t("credentials.generator.random")}
            </button>
            <button
              type="button"
              class={`${styles.modeBtn} ${mode() === "passphrase" ? styles.modeBtnActive : ""}`.trim()}
              onClick={() => setMode("passphrase")}
              role="radio"
              aria-checked={mode() === "passphrase"}
            >
              {t("credentials.generator.passphrase")}
            </button>
          </div>

          {/* Generated value + actions */}
          <div class={styles.outputRow}>
            <div class={styles.outputValue}>{generated()}</div>
            <div class={styles.outputActions}>
              <button
                type="button"
                class={styles.iconBtn}
                onClick={() => void doGenerate()}
                aria-label={t("credentials.generator.regenerate")}
                title={t("credentials.generator.regenerate")}
              >
                <Icon name="refresh" size={16} />
              </button>
              <button
                type="button"
                class={styles.iconBtn}
                onClick={() => void handleCopy()}
                aria-label={t("credentials.generator.copyAria")}
                title={t("credentials.generator.copy")}
              >
                <Icon name="copy" size={16} />
              </button>
            </div>
          </div>

          {/* Strength meter */}
          <div class={styles.strengthRow}>
            <div class={styles.meterTrack}>
              <div
                class={`${styles.meterFill} ${styles[strength()]}`}
                style={{ width: `${STRENGTH_WIDTHS[strength()]}%` }}
                role="progressbar"
                aria-valuenow={STRENGTH_WIDTHS[strength()]}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label={t("credentials.generator.strengthAria", { level: t(STRENGTH_LABEL_KEYS[strength()]) })}
              />
            </div>
            <span class={styles.strengthLabel}>
              {t(STRENGTH_LABEL_KEYS[strength()])}
            </span>
          </div>

          {/* ── Random mode options ── */}
          <Show when={mode() === "random"}>
            <div class={styles.options}>
              <div class={styles.sliderRow}>
                <label class={styles.sliderLabel} for="pw-length">{t("credentials.generator.length")}</label>
                <input
                  id="pw-length"
                  type="range"
                  class={styles.slider}
                  min={8}
                  max={128}
                  value={length()}
                  onInput={(e) => setLength(Number(e.currentTarget.value))}
                  onChange={(e) => setCommittedLength(Number(e.currentTarget.value))}
                />
                <span class={styles.sliderValue}>{length()}</span>
              </div>
              <div class={styles.checkboxGrid}>
                <label class={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={uppercase()}
                    disabled={isLastCharset(uppercase(), lowercase(), digits(), symbols())}
                    onChange={(e) => setUppercase(e.currentTarget.checked)}
                  />
                  A-Z
                </label>
                <label class={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={lowercase()}
                    disabled={isLastCharset(lowercase(), uppercase(), digits(), symbols())}
                    onChange={(e) => setLowercase(e.currentTarget.checked)}
                  />
                  a-z
                </label>
                <label class={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={digits()}
                    disabled={isLastCharset(digits(), uppercase(), lowercase(), symbols())}
                    onChange={(e) => setDigits(e.currentTarget.checked)}
                  />
                  0-9
                </label>
                <label class={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={symbols()}
                    disabled={isLastCharset(symbols(), uppercase(), lowercase(), digits())}
                    onChange={(e) => setSymbols(e.currentTarget.checked)}
                  />
                  !@#$
                </label>
              </div>
            </div>
          </Show>

          {/* ── Passphrase mode options ── */}
          <Show when={mode() === "passphrase"}>
            <div class={styles.options}>
              <div class={styles.sliderRow}>
                <label class={styles.sliderLabel} for="pw-words">{t("credentials.generator.words")}</label>
                <input
                  id="pw-words"
                  type="range"
                  class={styles.slider}
                  min={3}
                  max={10}
                  value={wordCount()}
                  onInput={(e) => setWordCount(Number(e.currentTarget.value))}
                  onChange={(e) => setCommittedWordCount(Number(e.currentTarget.value))}
                />
                <span class={styles.sliderValue}>{wordCount()}</span>
              </div>
              <div class={styles.selectRow}>
                <label class={styles.sliderLabel} for="pw-separator">{t("credentials.generator.separator")}</label>
                <select
                  id="pw-separator"
                  class={styles.select}
                  value={separator()}
                  onChange={(e) => setSeparator(e.currentTarget.value as SeparatorType)}
                >
                  <option value="hyphen">{t("credentials.generator.separatorHyphen")}</option>
                  <option value="space">{t("credentials.generator.separatorSpace")}</option>
                  <option value="dot">{t("credentials.generator.separatorDot")}</option>
                  <option value="underscore">{t("credentials.generator.separatorUnderscore")}</option>
                  <option value="none">{t("credentials.generator.separatorNone")}</option>
                </select>
              </div>
              <div class={styles.checkboxGrid}>
                <label class={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={capitalize()}
                    onChange={(e) => setCapitalize(e.currentTarget.checked)}
                  />
                  {t("credentials.generator.capitalize")}
                </label>
                <label class={styles.checkboxLabel}>
                  <input
                    type="checkbox"
                    checked={appendDigit()}
                    onChange={(e) => setAppendDigit(e.currentTarget.checked)}
                  />
                  {t("credentials.generator.appendDigit")}
                </label>
              </div>
            </div>
          </Show>

          {/* Use button */}
          <button
            type="button"
            class={styles.useBtn}
            onClick={handleUse}
          >
            {t("credentials.generator.usePassword")}
          </button>
        </div>
      </Show>
    </div>
  );
};
