import type { Component } from "solid-js";
import { Show, For, createResource, createEffect, on } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { PasswordInput } from "../../components/PasswordInput";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { TagInput } from "../../components/TagInput";
import { useToast } from "../../components/useToast";
import { getEntry, updateEntry } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { PasswordGenerator } from "./PasswordGenerator";
import { getTemplateById } from "./templates";
import { t } from "../../stores/i18nStore";
import styles from "./EditCredentialModal.module.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EditCredentialModalProps {
  open: boolean;
  entryId: string;
  onClose: () => void;
  onSuccess: () => void;
  onDelete?: (entryId: string, entryName: string) => void;
}

interface EditCredentialFormState {
  name: string;
  password: string;
  tags: string[];
  folderId: string;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const INITIAL_FORM: EditCredentialFormState = {
  name: "",
  password: "",
  tags: [],
  folderId: "",
  isSubmitting: false,
  errors: {},
};

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateEditForm(form: EditCredentialFormState): Record<string, string> {
  const errors: Record<string, string> = {};

  const trimmedName = form.name.trim();
  if (!trimmedName) {
    errors.name = t("credentials.edit.errors.nameRequired");
  } else if (trimmedName.length > 100) {
    errors.name = t("credentials.edit.errors.nameTooLong");
  }

  return errors;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Edit a credential's **basics**: display name, master-password rotation,
 * tags, and folder.
 *
 * Username / website URLs / notes / linked TOTP / custom fields are encrypted
 * entry data that `getEntry` does NOT return (they are only available via a
 * re-authenticated reveal, see `CredentialDetailModal`). This form therefore
 * does not edit them: it would otherwise have to render them blank and then
 * overwrite the stored values with empties on save — a silent data-loss bug.
 * Full in-place editing of those fields returns with the reveal-to-load editor
 * (Phase D / D-5). Until then they remain viewable from the credential's detail
 * view and are preserved untouched by this form.
 */
export const EditCredentialModal: Component<EditCredentialModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<EditCredentialFormState>({ ...INITIAL_FORM });

  const [folders] = createResource(() => (props.open ? true : undefined), listFolders);

  // Fetch entry metadata when the modal opens.
  const [entryDetail] = createResource(
    () => (props.open ? props.entryId : undefined),
    (id) => getEntry(id),
  );

  // Pre-populate the form when entry metadata loads.
  createEffect(
    on(
      () => entryDetail(),
      (entry) => {
        if (!entry) return;
        setForm({
          name: entry.name,
          password: "", // Empty = keep current
          tags: entry.tags ?? [],
          folderId: entry.folderId ?? "",
          isSubmitting: false,
          errors: {},
        });
      },
    ),
  );

  // ── Error helpers ──

  const clearError = (field: string) => {
    if (form.errors[field]) {
      const { [field]: _, ...rest } = form.errors;
      setForm("errors", rest);
    }
  };

  // ── Password generator ──

  const handleUsePassword = (password: string) => {
    setForm("password", password);
    clearError("password");
  };

  // ── Close ──

  const handleClose = () => {
    setForm("password", "");
    props.onClose();
  };

  // ── Submit ──

  const handleSave = async () => {
    if (form.isSubmitting) return;

    const errors = validateEditForm(form);
    if (Object.keys(errors).length > 0) {
      setForm("errors", errors);
      return;
    }

    setForm("isSubmitting", true);
    try {
      // Only send the fields this form actually manages. The backend treats an
      // omitted field as "no change", so username / urls / issuer / notes /
      // linkedTotpId / customFields are preserved untouched. (A previous version
      // sent null/[] for these blank-loaded fields, silently WIPING them.)
      await updateEntry({
        id: props.entryId,
        name: form.name.trim(),
        // Only include the secret when a new password was entered (empty = keep).
        ...(form.password ? { secret: form.password } : {}),
        folderId: form.folderId || null,
        tags: form.tags,
      });
      toast.success(t("credentials.edit.success", { name: form.name.trim() }));
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("credentials.edit.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  // ── Render ──

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("credentials.edit.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Show when={props.onDelete}>
            <Button
              variant="danger"
              onClick={() => props.onDelete?.(props.entryId, form.name)}
              class={styles.deleteBtn}
              disabled={form.isSubmitting}
              data-testid="edit-credential-delete-btn"
            >
              {t("credentials.edit.delete")}
            </Button>
          </Show>
          <Button variant="ghost" onClick={handleClose}>
            {t("credentials.edit.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            loading={form.isSubmitting}
            data-testid="edit-credential-save-btn"
          >
            {t("credentials.edit.save")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        {/* ── Template (read-only) ── */}
        <Show when={entryDetail()?.template}>
          {(templateId) => {
            const tmpl = () => getTemplateById(templateId());
            return (
              <Show when={tmpl()}>
                {(tmplData) => (
                  <div class={styles.templateIndicator} data-testid="edit-credential-template">
                    <Icon name={tmplData().icon} size={14} />
                    <span>
                      {t("credentials.edit.templateLabel", {
                        name: t(`credentials.templates.${tmplData().id}.name`),
                      })}
                    </span>
                  </div>
                )}
              </Show>
            );
          }}
        </Show>

        {/* ── Name ── */}
        <Input
          label={t("credentials.edit.name")}
          value={form.name}
          onInput={(v) => {
            setForm("name", v);
            clearError("name");
          }}
          error={form.errors.name}
          placeholder={t("credentials.edit.namePlaceholder")}
        />

        {/* ── Password + Generator ── */}
        <div class={styles.passwordSection}>
          <PasswordInput
            label={t("credentials.edit.newPassword")}
            mode="create"
            value={form.password}
            onInput={(v) => {
              setForm("password", v);
              clearError("password");
            }}
            error={form.errors.password}
            placeholder={t("credentials.edit.newPasswordPlaceholder")}
          />
          <p class={styles.passwordHint}>{t("credentials.edit.passwordHint")}</p>
          <PasswordGenerator onUse={handleUsePassword} />
        </div>

        {/* ── Tags ── */}
        <div>
          <span class={styles.tagLabel}>{t("credentials.edit.tags")}</span>
          <TagInput
            tags={form.tags}
            onChange={(tags) => setForm("tags", tags)}
            placeholder={t("credentials.edit.tagsPlaceholder")}
          />
        </div>

        {/* ── Folder Selector ── */}
        <div class={styles.selectWrapper}>
          <label class={styles.selectLabel} for="edit-credential-folder">
            {t("credentials.edit.folder")}
          </label>
          <select
            id="edit-credential-folder"
            class={styles.select}
            value={form.folderId}
            onChange={(e) => setForm("folderId", e.currentTarget.value)}
          >
            <option value="">{t("credentials.edit.folderNone")}</option>
            <For each={folders() ?? []}>{(f) => <option value={f.id}>{f.name}</option>}</For>
          </select>
        </div>
      </div>
    </Modal>
  );
};
