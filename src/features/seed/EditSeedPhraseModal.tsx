import type { Component } from "solid-js";
import { Show, createSignal, createResource, createEffect } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { PasswordInput } from "../../components/PasswordInput";
import { useToast } from "../../components/useToast";
import { getEntry, updateEntry } from "../entries/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./EditSeedPhraseModal.module.css";

export interface EditSeedPhraseModalProps {
  open: boolean;
  entryId: string;
  onClose: () => void;
  onSuccess: () => void;
  onDelete?: (entryId: string, entryName: string) => void;
}

interface EditSeedFormState {
  name: string;
  issuer: string;
  pinned: boolean;
  hasPassphrase: boolean;
  passphrase: string;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

const INITIAL_FORM: EditSeedFormState = {
  name: "",
  issuer: "",
  pinned: false,
  hasPassphrase: false,
  passphrase: "",
  isSubmitting: false,
  errors: {},
};

export const EditSeedPhraseModal: Component<EditSeedPhraseModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<EditSeedFormState>({ ...INITIAL_FORM });
  const [wordCount, setWordCount] = createSignal(0);

  // Track original passphrase state for tri-state change detection.
  // NOTE: Always false until the backend exposes `hasPassphrase` in EntryDetailDto.
  // When that's added, convert to: const [originalHasPassphrase, setOriginalHasPassphrase] = createSignal(false);
  let originalHasPassphrase = false;

  // Fetch entry detail when modal opens
  const [entryDetail] = createResource(
    () => (props.open ? props.entryId : undefined),
    (id) => getEntry(id),
  );

  // Pre-populate form when entry detail loads
  createEffect(() => {
    const entry = entryDetail();
    if (entry) {
      // For seed phrases, word count comes from the secret (space-separated words)
      const words = entry.secret ? entry.secret.split(" ") : [];
      setWordCount(words.length);

      // Detect if entry has a passphrase (convention: passphrase stored after a tab separator)
      // In production, the backend would return this metadata; for mock, we don't have it
      originalHasPassphrase = false;

      setForm({
        name: entry.name,
        issuer: entry.issuer ?? "",
        pinned: entry.pinned,
        hasPassphrase: originalHasPassphrase,
        passphrase: "",
        isSubmitting: false,
        errors: {},
      });
    }
  });

  const clearError = (field: string) => {
    if (form.errors[field]) {
      setForm("errors", field, undefined!);
    }
  };

  const handleNameInput = (value: string) => {
    setForm("name", value);
    clearError("name");
  };

  const handleIssuerInput = (value: string) => {
    setForm("issuer", value);
    clearError("issuer");
  };

  const validateForm = (): Record<string, string> => {
    const errors: Record<string, string> = {};
    const trimmedName = form.name.trim();
    if (!trimmedName) {
      errors.name = t("seed.edit.errors.nameRequired");
    } else if (trimmedName.length > 100) {
      errors.name = t("seed.edit.errors.nameTooLong");
    }
    if (form.issuer && form.issuer.length > 100) {
      errors.issuer = t("seed.edit.errors.issuerTooLong");
    }
    return errors;
  };

  /**
   * Compute passphrase tri-state for the update request:
   * - undefined = no change
   * - null = remove passphrase
   * - string = set new passphrase
   */
  const computePassphraseValue = (): string | null | undefined => {
    if (!form.hasPassphrase && originalHasPassphrase) {
      // User unchecked the passphrase box → remove
      return null;
    }
    if (form.hasPassphrase && form.passphrase) {
      // User set or changed passphrase
      return form.passphrase;
    }
    // No change
    return undefined;
  };

  const handleSave = async () => {
    if (form.isSubmitting) return;

    const errors = validateForm();
    if (Object.keys(errors).length > 0) {
      setForm("errors", errors);
      return;
    }

    setForm("isSubmitting", true);
    try {
      const passphraseValue = computePassphraseValue();
      await updateEntry({
        id: props.entryId,
        name: form.name.trim(),
        issuer: form.issuer.trim() || null,
        pinned: form.pinned,
        ...(passphraseValue !== undefined ? { passphrase: passphraseValue } : {}),
      });
      toast.success(t("seed.edit.success", { name: form.name.trim() }));
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("seed.edit.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  const handleClose = () => {
    // Clear passphrase from form state on close
    setForm("passphrase", "");
    props.onClose();
  };

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("seed.edit.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Show when={props.onDelete}>
            <Button
              variant="danger"
              onClick={() => props.onDelete?.(props.entryId, form.name)}
              class={styles.deleteBtn}
              disabled={form.isSubmitting}
              data-testid="edit-seed-delete-btn"
            >
              {t("seed.edit.delete")}
            </Button>
          </Show>
          <Button variant="ghost" onClick={handleClose}>
            {t("seed.edit.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            loading={form.isSubmitting}
            data-testid="edit-seed-save-btn"
          >
            {t("seed.edit.save")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        <div class={styles.fieldGroup}>
          <Input
            label={t("seed.edit.walletName")}
            value={form.name}
            onInput={handleNameInput}
            error={form.errors.name}
            placeholder={t("seed.edit.walletNamePlaceholder")}
            data-testid="edit-seed-name"
          />
          <Input
            label={t("seed.edit.issuer")}
            value={form.issuer}
            onInput={handleIssuerInput}
            error={form.errors.issuer}
            placeholder={t("seed.edit.issuerPlaceholder")}
            data-testid="edit-seed-issuer"
          />

          {/* Read-only word count */}
          <div class={styles.readOnlyRow} data-testid="edit-seed-word-count">
            <span class={styles.readOnlyLabel}>{t("seed.edit.wordCount")}</span>
            <span class={styles.readOnlyValue}>{t("seed.edit.nWords", { count: wordCount() })}</span>
          </div>

          {/* Info banner — seed words are immutable */}
          <div class={styles.infoBanner} role="note" data-testid="edit-seed-info-banner">
            <Icon name="info" size={16} />
            <span>{t("seed.edit.immutableInfo")}</span>
          </div>

          {/* Passphrase section (FR78) */}
          <label class={styles.passphraseCheckbox}>
            <input
              type="checkbox"
              checked={form.hasPassphrase}
              onChange={(e) => {
                setForm("hasPassphrase", e.currentTarget.checked);
                if (!e.currentTarget.checked) {
                  setForm("passphrase", "");
                }
              }}
              data-testid="edit-seed-passphrase-toggle"
            />
            <Icon name="key" size={14} />
            <span>{t("seed.edit.bip39Passphrase")}</span>
          </label>

          <Show when={form.hasPassphrase}>
            <PasswordInput
              label={t("seed.edit.passphraseLabel")}
              mode="unlock"
              value={form.passphrase}
              onInput={(v) => setForm("passphrase", v)}
              placeholder={t("seed.edit.passphrasePlaceholder")}
            />
          </Show>

          {/* Pin as favorite */}
          <label class={styles.pinCheckbox}>
            <input
              type="checkbox"
              checked={form.pinned}
              onChange={(e) => setForm("pinned", e.currentTarget.checked)}
              data-testid="edit-seed-pin-checkbox"
            />
            <Icon name="star" size={14} />
            <span>{t("seed.edit.pinFavorite")}</span>
          </label>
        </div>
      </div>
    </Modal>
  );
};
