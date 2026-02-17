/**
 * AddSeedPhraseForm — modal form for adding a seed phrase entry.
 *
 * Includes word count selector, language selector, BIP39 word grid,
 * checksum validation, metadata fields, and optional passphrase.
 */

import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, createResource, on } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { PasswordInput } from "../../components/PasswordInput";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { addEntry } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { validatePhrase } from "./ipc";
import { SeedPhraseGrid } from "./SeedPhraseGrid";
import { t } from "../../stores/i18nStore";
import styles from "./AddSeedPhraseForm.module.css";

export interface AddSeedPhraseFormProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

interface FormState {
  wordCount: number;
  language: string;
  words: string[];
  name: string;
  issuer: string;
  folderId: string;
  passphrase: string;
  showPassphrase: boolean;
  validationStates: boolean[];
  isSubmitting: boolean;
  phraseValid: boolean | null;
  phraseError: string | null;
  errors: Record<string, string>;
}

const WORD_COUNTS = [12, 15, 18, 21, 24] as const;

const LANGUAGES = [
  { value: "english", label: "English" },
  { value: "japanese", label: "Japanese" },
  { value: "korean", label: "Korean" },
  { value: "spanish", label: "Spanish" },
  { value: "chinese_simplified", label: "Chinese (Simplified)" },
  { value: "chinese_traditional", label: "Chinese (Traditional)" },
  { value: "french", label: "French" },
  { value: "italian", label: "Italian" },
  { value: "czech", label: "Czech" },
  { value: "portuguese", label: "Portuguese" },
] as const;

function createInitialState(wordCount = 12): FormState {
  return {
    wordCount,
    language: "english",
    words: Array(wordCount).fill(""),
    name: "",
    issuer: "",
    folderId: "",
    passphrase: "",
    showPassphrase: false,
    validationStates: Array(wordCount).fill(false),
    isSubmitting: false,
    phraseValid: null,
    phraseError: null,
    errors: {},
  };
}

export const AddSeedPhraseForm: Component<AddSeedPhraseFormProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<FormState>(createInitialState());
  const [validatingPhrase, setValidatingPhrase] = createSignal(false);
  const [folders] = createResource(() => props.open ? true : undefined, listFolders);

  // Reset form when modal opens
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          setForm(createInitialState());
        }
      },
    ),
  );

  const handleClose = () => {
    setForm(createInitialState());
    props.onClose();
  };

  const handleWordCountChange = (count: number) => {
    setForm({
      wordCount: count,
      words: Array(count).fill(""),
      validationStates: Array(count).fill(false),
      phraseValid: null,
      phraseError: null,
    });
  };

  const handleLanguageChange = (language: string) => {
    setForm({
      language,
      validationStates: Array(form.wordCount).fill(false),
      phraseValid: null,
      phraseError: null,
    });
  };

  const handleWordsChange = (words: string[]) => {
    setForm("words", words);
    // Reset phrase validation when words change
    setForm("phraseValid", null);
    setForm("phraseError", null);
  };

  const handleWordValidated = (index: number, valid: boolean) => {
    const updated = [...form.validationStates];
    updated[index] = valid;
    setForm("validationStates", updated);

    // Auto-trigger phrase validation when all words are entered and individually valid
    const allEntered = form.words.every((w) => w.length > 0);
    const allValid = updated.slice(0, form.wordCount).every(Boolean);
    if (allEntered && allValid && !validatingPhrase()) {
      triggerPhraseValidation();
    }
  };

  const triggerPhraseValidation = async () => {
    setValidatingPhrase(true);
    try {
      const result = await validatePhrase(form.words, form.language);
      setForm("phraseValid", result.valid);
      setForm("phraseError", result.error ?? null);
    } finally {
      setValidatingPhrase(false);
    }
  };

  const canSave = () =>
    form.name.trim().length > 0 &&
    form.words.every((w) => w.length > 0) &&
    form.phraseValid !== false &&
    (!form.showPassphrase || form.passphrase.length > 0) &&
    !form.isSubmitting;

  const handleSave = async () => {
    if (!canSave()) return;

    // Validate name
    if (!form.name.trim()) {
      setForm("errors", { name: t("seed.add.errors.nameRequired") });
      return;
    }

    setForm("isSubmitting", true);
    try {
      await addEntry({
        entryType: "seed_phrase",
        name: form.name.trim(),
        issuer: form.issuer.trim() || undefined,
        secret: form.words.join(" "),
        passphrase: form.showPassphrase ? form.passphrase : undefined,
        language: form.language,
        folderId: form.folderId || undefined,
      });
      toast.success(t("seed.add.success"));
      setForm(createInitialState());
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(
        typeof err === "string"
          ? err
          : t("seed.add.error"),
      );
    } finally {
      setForm("isSubmitting", false);
    }
  };

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("seed.add.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button variant="ghost" onClick={handleClose}>
            {t("seed.add.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            disabled={!canSave()}
            loading={form.isSubmitting}
          >
            {t("seed.add.save")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        {/* Word Count & Language Selectors */}
        <div class={styles.selectorsRow}>
          <div class={styles.selectWrapper}>
            <label class={styles.selectLabel} for="select-word-count">
              {t("seed.add.wordCount")}
            </label>
            <select
              id="select-word-count"
              class={styles.select}
              value={form.wordCount}
              onChange={(e) =>
                handleWordCountChange(Number(e.currentTarget.value))
              }
            >
              {WORD_COUNTS.map((count) => (
                <option value={count}>{t("seed.add.nWords", { count })}</option>
              ))}
            </select>
          </div>

          <div class={styles.selectWrapper}>
            <label class={styles.selectLabel} for="select-language">
              {t("seed.add.language")}
            </label>
            <select
              id="select-language"
              class={styles.select}
              value={form.language}
              onChange={(e) => handleLanguageChange(e.currentTarget.value)}
            >
              {LANGUAGES.map((lang) => (
                <option value={lang.value}>{lang.label}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Seed Phrase Grid */}
        <SeedPhraseGrid
          wordCount={form.wordCount}
          language={form.language}
          words={form.words}
          onWordsChange={handleWordsChange}
          validationStates={form.validationStates}
          onWordValidated={handleWordValidated}
          disabled={form.isSubmitting}
        />

        {/* Phrase Validation Banner */}
        <Show when={form.phraseValid !== null}>
          <div
            class={`${styles.banner} ${
              form.phraseValid ? styles.bannerValid : styles.bannerInvalid
            }`}
            role="status"
          >
            <Icon
              name={form.phraseValid ? "check" : "alert"}
              size={16}
            />
            <Show
              when={form.phraseValid}
              fallback={
                <span>
                  {t("seed.add.checksumInvalid")}{" "}
                  {form.phraseError ? `(${form.phraseError})` : ""}
                </span>
              }
            >
              <span>{t("seed.add.phraseValid")}</span>
            </Show>
          </div>
        </Show>

        <hr class={styles.separator} />

        {/* Metadata Fields */}
        <div class={styles.fieldGroup}>
          <Input
            label={t("seed.add.walletName")}
            value={form.name}
            onInput={(value) => {
              setForm("name", value);
              if (form.errors.name) {
                const { name: _, ...rest } = form.errors;
                setForm("errors", rest);
              }
            }}
            error={form.errors.name}
            placeholder={t("seed.add.walletNamePlaceholder")}
          />
          <Input
            label={t("seed.add.issuer")}
            value={form.issuer}
            onInput={(value) => setForm("issuer", value)}
            placeholder={t("seed.add.issuerPlaceholder")}
          />
          <div class={styles.selectWrapper}>
            <label class={styles.selectLabel} for="select-folder">
              {t("seed.add.folder")}
            </label>
            <select
              id="select-folder"
              class={styles.select}
              value={form.folderId}
              onChange={(e) => setForm("folderId", e.currentTarget.value)}
            >
              <option value="">{t("seed.add.folderNone")}</option>
              <For each={folders() ?? []}>
                {(f) => <option value={f.id}>{f.name}</option>}
              </For>
            </select>
          </div>
        </div>

        {/* Passphrase Toggle */}
        <div class={styles.passphraseToggle}>
          <input
            type="checkbox"
            id="passphrase-toggle"
            class={styles.checkbox}
            checked={form.showPassphrase}
            onChange={(e) =>
              setForm("showPassphrase", e.currentTarget.checked)
            }
          />
          <label for="passphrase-toggle" class={styles.checkboxLabel}>
            {t("seed.add.bip39Passphrase")}
          </label>
        </div>

        <Show when={form.showPassphrase}>
          <PasswordInput
            label={t("seed.add.passphraseLabel")}
            mode="unlock"
            value={form.passphrase}
            onInput={(value) => setForm("passphrase", value)}
            placeholder={t("seed.add.passphrasePlaceholder")}
          />
        </Show>
      </div>
    </Modal>
  );
};
