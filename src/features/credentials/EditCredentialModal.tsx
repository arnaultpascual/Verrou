import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, createResource, on } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { PasswordInput } from "../../components/PasswordInput";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { TagInput } from "../../components/TagInput";
import { useToast } from "../../components/useToast";
import { getEntry, updateEntry, listEntries } from "../entries/ipc";
import type { CustomFieldDto } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { PasswordGenerator } from "./PasswordGenerator";
import { getTemplateById } from "./templates";
import { extractDomain, validateUrl } from "./url-utils";
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
  username: string;
  password: string;
  urls: string[];
  notes: string;
  linkedTotpId: string;
  customFields: CustomFieldDto[];
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
  username: "",
  password: "",
  urls: [""],
  notes: "",
  linkedTotpId: "",
  customFields: [],
  tags: [],
  folderId: "",
  isSubmitting: false,
  errors: {},
};

const FIELD_TYPE_OPTIONS = [
  { value: "text", labelKey: "credentials.edit.fieldType.text" },
  { value: "hidden", labelKey: "credentials.edit.fieldType.hidden" },
  { value: "url", labelKey: "credentials.edit.fieldType.url" },
  { value: "date", labelKey: "credentials.edit.fieldType.date" },
];

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

  // Password is optional in edit mode (empty = keep current)

  for (let i = 0; i < form.urls.length; i++) {
    const url = form.urls[i].trim();
    if (url) {
      const err = validateUrl(url);
      if (err) errors[`url-${i}`] = err;
    }
  }

  for (let i = 0; i < form.customFields.length; i++) {
    if (!form.customFields[i].label.trim()) {
      errors[`cf-label-${i}`] = t("credentials.edit.errors.fieldNameRequired");
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const EditCredentialModal: Component<EditCredentialModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<EditCredentialFormState>({ ...INITIAL_FORM });
  const [hiddenVisible, setHiddenVisible] = createStore<Record<number, boolean>>({});

  const [folders] = createResource(() => (props.open ? true : undefined), listFolders);
  const [totpEntries] = createResource(
    () => (props.open ? true : undefined),
    async () => {
      const all = await listEntries();
      return all.filter((e) => e.entryType === "totp");
    },
  );

  // Fetch entry detail when modal opens
  const [entryDetail] = createResource(
    () => (props.open ? props.entryId : undefined),
    (id) => getEntry(id),
  );

  // Pre-populate form when entry detail loads
  createEffect(
    on(
      () => entryDetail(),
      (entry) => {
        if (!entry) return;
        setForm({
          name: entry.name,
          username: "",       // Not in EntryDetailDto — loaded separately via reveal
          password: "",       // Empty = keep current
          urls: [""],         // Will be populated if credential data is available
          notes: "",
          linkedTotpId: "",
          customFields: [],
          tags: entry.tags ?? [],
          folderId: entry.folderId ?? "",
          isSubmitting: false,
          errors: {},
        });
        setHiddenVisible({});
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

  // ── URL management ──

  const handleUrlInput = (index: number, value: string) => {
    setForm("urls", index, value);
    clearError(`url-${index}`);
  };

  const addUrl = () => {
    setForm("urls", [...form.urls, ""]);
  };

  const removeUrl = (index: number) => {
    const newErrors = { ...form.errors };
    for (let i = 0; i < form.urls.length; i++) {
      delete newErrors[`url-${i}`];
    }
    let newIdx = 0;
    for (let i = 0; i < form.urls.length; i++) {
      if (i === index) continue;
      const oldErr = form.errors[`url-${i}`];
      if (oldErr) newErrors[`url-${newIdx}`] = oldErr;
      newIdx++;
    }
    setForm("urls", form.urls.filter((_, i) => i !== index));
    setForm("errors", newErrors);
  };

  // ── Custom fields ──

  const addCustomField = () => {
    setForm("customFields", [...form.customFields, { label: "", value: "", fieldType: "text" }]);
  };

  const removeCustomField = (index: number) => {
    const newErrors = { ...form.errors };
    const newHidden: Record<number, boolean> = {};
    for (let i = 0; i < form.customFields.length; i++) {
      delete newErrors[`cf-label-${i}`];
    }
    let newIdx = 0;
    for (let i = 0; i < form.customFields.length; i++) {
      if (i === index) continue;
      const oldErr = form.errors[`cf-label-${i}`];
      if (oldErr) newErrors[`cf-label-${newIdx}`] = oldErr;
      if (hiddenVisible[i]) newHidden[newIdx] = true;
      newIdx++;
    }
    setForm("customFields", form.customFields.filter((_, i) => i !== index));
    setForm("errors", newErrors);
    setHiddenVisible(newHidden);
  };

  const updateCustomField = (index: number, key: keyof CustomFieldDto, value: string) => {
    setForm("customFields", index, key, value);
    if (key === "label") clearError(`cf-label-${index}`);
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
      const nonEmptyUrls = form.urls.filter((u) => u.trim());
      const issuer = nonEmptyUrls.length > 0 ? extractDomain(nonEmptyUrls[0]) || null : null;

      await updateEntry({
        id: props.entryId,
        name: form.name.trim(),
        issuer,
        // Only include secret if password was changed (non-empty)
        ...(form.password ? { secret: form.password } : {}),
        username: form.username.trim() || null,
        urls: nonEmptyUrls.length > 0 ? nonEmptyUrls.map((u) => u.trim()) : undefined,
        notes: form.notes.trim() || null,
        linkedTotpId: form.linkedTotpId || null,
        customFields: form.customFields,
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
                    <span>{t("credentials.edit.templateLabel", { name: t(`credentials.templates.${tmplData().id}.name`) })}</span>
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

        {/* ── Username ── */}
        <Input
          label={t("credentials.edit.username")}
          value={form.username}
          onInput={(v) => setForm("username", v)}
          placeholder={t("credentials.edit.usernamePlaceholder")}
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
          <p class={styles.passwordHint}>
            {t("credentials.edit.passwordHint")}
          </p>
          <PasswordGenerator onUse={handleUsePassword} />
        </div>

        <hr class={styles.separator} />

        {/* ── URLs ── */}
        <div class={styles.fieldGroup}>
          <span class={styles.sectionLabel}>{t("credentials.edit.urls")}</span>
          <div class={styles.urlList}>
            <For each={form.urls}>
              {(url, index) => (
                <div class={styles.urlRow}>
                  <Input
                    label={index() === 0 ? t("credentials.edit.primaryUrl") : t("credentials.edit.urlN", { n: index() + 1 })}
                    type="url"
                    value={url}
                    onInput={(v) => handleUrlInput(index(), v)}
                    error={form.errors[`url-${index()}`]}
                    placeholder={t("credentials.edit.urlPlaceholder")}
                  />
                  <Show when={form.urls.length > 1}>
                    <button
                      type="button"
                      class={styles.urlRemoveBtn}
                      onClick={() => removeUrl(index())}
                      aria-label={t("credentials.edit.removeUrlAria", { n: index() + 1 })}
                    >
                      <Icon name="x" size={14} />
                    </button>
                  </Show>
                </div>
              )}
            </For>
          </div>
          <button type="button" class={styles.addBtn} onClick={addUrl} aria-label={t("credentials.edit.addUrlAria")}>
            <Icon name="plus" size={14} /> {t("credentials.edit.addUrl")}
          </button>
        </div>

        <hr class={styles.separator} />

        {/* ── Notes ── */}
        <div class={styles.textareaWrapper}>
          <label class={styles.textareaLabel} for="edit-credential-notes">
            {t("credentials.edit.notes")}
          </label>
          <textarea
            id="edit-credential-notes"
            class={styles.textarea}
            value={form.notes}
            onInput={(e) => setForm("notes", e.currentTarget.value)}
            placeholder={t("credentials.edit.notesPlaceholder")}
            rows={3}
          />
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
            <For each={folders() ?? []}>
              {(f) => <option value={f.id}>{f.name}</option>}
            </For>
          </select>
        </div>

        <hr class={styles.separator} />

        {/* ── Link TOTP ── */}
        <div class={styles.selectWrapper}>
          <label class={styles.selectLabel} for="edit-credential-totp-link">
            {t("credentials.edit.linkTotp")}
          </label>
          <select
            id="edit-credential-totp-link"
            class={styles.select}
            value={form.linkedTotpId}
            onChange={(e) => setForm("linkedTotpId", e.currentTarget.value)}
          >
            <option value="">{t("credentials.edit.folderNone")}</option>
            <For each={totpEntries() ?? []}>
              {(entry) => (
                <option value={entry.id}>
                  {entry.name}
                  {entry.issuer ? ` (${entry.issuer})` : ""}
                </option>
              )}
            </For>
          </select>
        </div>

        {/* ── Custom Fields ── */}
        <div class={styles.fieldGroup}>
          <span class={styles.sectionLabel}>{t("credentials.edit.customFields")}</span>
          <For each={form.customFields}>
            {(field, index) => (
              <div class={styles.customFieldRow}>
                <div class={styles.customFieldLabel}>
                  <Input
                    label={t("credentials.edit.fieldName")}
                    value={field.label}
                    onInput={(v) => updateCustomField(index(), "label", v)}
                    error={form.errors[`cf-label-${index()}`]}
                    placeholder={t("credentials.edit.fieldNamePlaceholder")}
                  />
                </div>

                <Show
                  when={field.fieldType !== "hidden"}
                  fallback={
                    <div class={styles.hiddenFieldRow}>
                      <Input
                        label={t("credentials.edit.fieldValue")}
                        type={hiddenVisible[index()] ? "text" : "password"}
                        value={field.value}
                        onInput={(v) => updateCustomField(index(), "value", v)}
                        placeholder={t("credentials.edit.hiddenValuePlaceholder")}
                      />
                      <button
                        type="button"
                        class={styles.hiddenToggle}
                        onClick={() =>
                          setHiddenVisible(index(), !hiddenVisible[index()])
                        }
                        aria-label={
                          hiddenVisible[index()] ? t("credentials.edit.hideValueAria") : t("credentials.edit.showValueAria")
                        }
                      >
                        <Icon
                          name={hiddenVisible[index()] ? "eye-off" : "eye"}
                          size={16}
                        />
                      </button>
                    </div>
                  }
                >
                  <div class={styles.customFieldValue}>
                    <Input
                      label={t("credentials.edit.fieldValue")}
                      type={field.fieldType === "url" ? "url" : "text"}
                      value={field.value}
                      onInput={(v) => updateCustomField(index(), "value", v)}
                      placeholder={
                        field.fieldType === "date" ? t("credentials.edit.datePlaceholder") : t("credentials.edit.valuePlaceholder")
                      }
                    />
                  </div>
                </Show>

                <div class={styles.selectWrapper}>
                  <label
                    class={styles.selectLabel}
                    for={`edit-cf-type-${index()}`}
                  >
                    {t("credentials.edit.fieldType.label")}
                  </label>
                  <select
                    id={`edit-cf-type-${index()}`}
                    class={`${styles.select} ${styles.customFieldType}`}
                    value={field.fieldType}
                    onChange={(e) =>
                      updateCustomField(index(), "fieldType", e.currentTarget.value)
                    }
                  >
                    <For each={FIELD_TYPE_OPTIONS}>
                      {(opt) => <option value={opt.value}>{t(opt.labelKey)}</option>}
                    </For>
                  </select>
                </div>

                <button
                  type="button"
                  class={styles.customFieldRemove}
                  onClick={() => removeCustomField(index())}
                  aria-label={t("credentials.edit.removeFieldAria", { name: field.label || t("credentials.edit.customField") })}
                >
                  <Icon name="x" size={14} />
                </button>
              </div>
            )}
          </For>
          <button
            type="button"
            class={styles.addBtn}
            onClick={addCustomField}
          >
            <Icon name="plus" size={14} /> {t("credentials.edit.addCustomField")}
          </button>
        </div>
      </div>
    </Modal>
  );
};
