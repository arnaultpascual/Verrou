/**
 * AddSecureNoteForm — modal form for adding a secure note entry.
 *
 * Title input + body textarea + optional comma-separated tags.
 * Follows the AddSeedPhraseForm pattern (form rendered inside a Modal).
 */

import type { Component } from "solid-js";
import { Show, For, createResource } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { TagInput } from "../../components/TagInput";
import { useToast } from "../../components/useToast";
import { addEntry } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./AddSecureNoteForm.module.css";

export interface AddSecureNoteFormProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

interface FormState {
  name: string;
  body: string;
  tags: string[];
  folderId: string;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

const INITIAL_FORM: FormState = {
  name: "",
  body: "",
  tags: [],
  folderId: "",
  isSubmitting: false,
  errors: {},
};

export const AddSecureNoteForm: Component<AddSecureNoteFormProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<FormState>({ ...INITIAL_FORM });
  const [folders] = createResource(() => props.open ? true : undefined, listFolders);

  const resetForm = () => {
    setForm({ ...INITIAL_FORM });
  };

  const clearError = (field: string) => {
    if (form.errors[field]) {
      setForm("errors", field, undefined!);
    }
  };

  const validateForm = (): Record<string, string> => {
    const errors: Record<string, string> = {};
    const trimmedName = form.name.trim();
    if (!trimmedName) {
      errors.name = t("notes.add.errors.titleRequired");
    } else if (trimmedName.length > 100) {
      errors.name = t("notes.add.errors.titleTooLong");
    }
    if (!form.body.trim()) {
      errors.body = t("notes.add.errors.bodyRequired");
    }
    return errors;
  };

  const handleSubmit = async () => {
    if (form.isSubmitting) return;

    const errors = validateForm();
    if (Object.keys(errors).length > 0) {
      setForm("errors", errors);
      return;
    }

    setForm("isSubmitting", true);
    try {
      await addEntry({
        entryType: "secure_note",
        name: form.name.trim(),
        secret: form.body,
        tags: form.tags.length > 0 ? form.tags : undefined,
        folderId: form.folderId || undefined,
      });
      toast.success(t("notes.add.success"));
      resetForm();
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("notes.add.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  const handleClose = () => {
    resetForm();
    props.onClose();
  };

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("notes.add.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button variant="ghost" onClick={handleClose}>
            {t("notes.add.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSubmit}
            loading={form.isSubmitting}
          >
            {t("notes.add.save")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        <div class={styles.fieldGroup}>
          <Input
            label={t("notes.add.noteTitle")}
            value={form.name}
            onInput={(v) => { setForm("name", v); clearError("name"); }}
            error={form.errors.name}
            placeholder={t("notes.add.titlePlaceholder")}
          />

          <div class={styles.textareaWrapper}>
            <label class={styles.textareaLabel} for="note-body">
              {t("notes.add.noteBody")}
            </label>
            <textarea
              id="note-body"
              class={styles.textarea}
              value={form.body}
              onInput={(e) => { setForm("body", e.currentTarget.value); clearError("body"); }}
              placeholder={t("notes.add.bodyPlaceholder")}
              rows={8}
            />
            <Show when={form.errors.body}>
              <span class={styles.error}>{form.errors.body}</span>
            </Show>
          </div>

          <div class={styles.selectWrapper}>
            <label class={styles.selectLabel} for="select-folder">
              {t("notes.add.folder")}
            </label>
            <select
              id="select-folder"
              class={styles.select}
              value={form.folderId}
              onChange={(e) => setForm("folderId", e.currentTarget.value)}
            >
              <option value="">{t("notes.add.folderNone")}</option>
              <For each={folders() ?? []}>
                {(f) => <option value={f.id}>{f.name}</option>}
              </For>
            </select>
          </div>

          <div class={styles.tagsWrapper}>
            <label class={styles.tagsLabel}>{t("notes.add.tags")}</label>
            <TagInput
              tags={form.tags}
              onChange={(tags) => setForm("tags", tags)}
              placeholder={t("notes.add.tagsPlaceholder")}
              disabled={form.isSubmitting}
            />
            <span class={styles.tagsHint}>{t("notes.add.tagsHint")}</span>
          </div>
        </div>
      </div>
    </Modal>
  );
};
