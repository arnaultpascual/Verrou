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
import { addEntry, listEntries } from "../entries/ipc";
import type { CustomFieldDto } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { PasswordGenerator } from "./PasswordGenerator";
import { CREDENTIAL_TEMPLATES, getTemplateById } from "./templates";
import { extractDomain, validateUrl } from "./url-utils";
import { t } from "../../stores/i18nStore";
import styles from "./AddCredentialModal.module.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AddCredentialModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

interface AddCredentialFormState {
  name: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  linkedTotpId: string;
  customFields: CustomFieldDto[];
  tags: string[];
  template: string;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const INITIAL_FORM: AddCredentialFormState = {
  name: "",
  username: "",
  password: "",
  urls: [""],
  notes: "",
  linkedTotpId: "",
  customFields: [],
  tags: [],
  template: "login",
  isSubmitting: false,
  errors: {},
};

const FIELD_TYPE_OPTIONS = [
  { value: "text", labelKey: "credentials.add.fieldType.text" },
  { value: "hidden", labelKey: "credentials.add.fieldType.hidden" },
  { value: "url", labelKey: "credentials.add.fieldType.url" },
  { value: "date", labelKey: "credentials.add.fieldType.date" },
];

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

function validateCredentialForm(form: AddCredentialFormState): Record<string, string> {
  const errors: Record<string, string> = {};

  const trimmedName = form.name.trim();
  if (!trimmedName) {
    errors.name = t("credentials.add.errors.nameRequired");
  } else if (trimmedName.length > 100) {
    errors.name = t("credentials.add.errors.nameTooLong");
  }

  if (!form.password) {
    errors.password = t("credentials.add.errors.passwordRequired");
  }

  // Validate each non-empty URL
  for (let i = 0; i < form.urls.length; i++) {
    const url = form.urls[i].trim();
    if (url) {
      const err = validateUrl(url);
      if (err) {
        errors[`url-${i}`] = err;
      }
    }
  }

  // Validate custom field labels are non-empty
  for (let i = 0; i < form.customFields.length; i++) {
    if (!form.customFields[i].label.trim()) {
      errors[`cf-label-${i}`] = t("credentials.add.errors.fieldNameRequired");
    }
  }

  return errors;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const AddCredentialModal: Component<AddCredentialModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<AddCredentialFormState>({ ...INITIAL_FORM });
  const [folderId, setFolderId] = createSignal("");
  const [folders] = createResource(() => (props.open ? true : undefined), listFolders);
  const [totpEntries] = createResource(
    () => (props.open ? true : undefined),
    async () => {
      const all = await listEntries();
      return all.filter((e) => e.entryType === "totp");
    },
  );

  // Track hidden field visibility per custom field index
  const [hiddenVisible, setHiddenVisible] = createStore<Record<number, boolean>>({});

  // ── Reset ──

  const resetForm = () => {
    setForm({ ...INITIAL_FORM, urls: [""], customFields: [], tags: [], errors: {} });
    setFolderId("");
    setHiddenVisible({});
  };

  // ── Template selection ──

  const handleTemplateChange = (templateId: string) => {
    const tmpl = getTemplateById(templateId);
    setForm("template", templateId);
    // Replace custom fields with template fields (deep copy to avoid mutation)
    setForm("customFields", tmpl?.customFields.map((f) => ({ ...f })) ?? []);
    setHiddenVisible({});
  };

  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) resetForm();
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

  // ── URL auto-detection ──

  const handleUrlInput = (index: number, value: string) => {
    setForm("urls", index, value);
    clearError(`url-${index}`);

    // Auto-suggest name from first URL domain when name is empty
    if (index === 0 && !form.name.trim()) {
      const domain = extractDomain(value);
      if (domain) {
        setForm("name", domain);
      }
    }
  };

  const addUrl = () => {
    setForm("urls", [...form.urls, ""]);
  };

  const removeUrl = (index: number) => {
    // Rebuild url-* error keys to match new indices after removal
    const newErrors = { ...form.errors };
    // Clear all url-* keys and re-key the survivors
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
    // Rebuild cf-label-* error keys and hiddenVisible to match new indices
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

  // ── Password generator callback ──

  const handleUsePassword = (password: string) => {
    setForm("password", password);
    clearError("password");
  };

  // ── Close ──

  const handleClose = () => {
    resetForm();
    props.onClose();
  };

  // ── Submit ──

  const handleSave = async () => {
    if (form.isSubmitting) return;

    const errors = validateCredentialForm(form);
    if (Object.keys(errors).length > 0) {
      setForm("errors", errors);
      return;
    }

    setForm("isSubmitting", true);
    try {
      const nonEmptyUrls = form.urls.filter((u) => u.trim());
      const issuer = extractDomain(form.urls[0]) || undefined;

      const result = await addEntry({
        entryType: "credential",
        name: form.name.trim(),
        issuer,
        secret: form.password,
        username: form.username.trim() || undefined,
        urls: nonEmptyUrls.length > 0 ? nonEmptyUrls.map((u) => u.trim()) : undefined,
        notes: form.notes.trim() || undefined,
        linkedTotpId: form.linkedTotpId || undefined,
        customFields: form.customFields.length > 0 ? form.customFields : undefined,
        folderId: folderId() || undefined,
        tags: form.tags.length > 0 ? form.tags : undefined,
        template: form.template !== "login" ? form.template : undefined,
      });
      toast.success(t("credentials.add.success", { name: result.name }));
      resetForm();
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("credentials.add.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  // ── Render ──

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("credentials.add.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button variant="ghost" onClick={handleClose}>
            {t("credentials.add.cancel")}
          </Button>
          <Button variant="primary" onClick={handleSave} loading={form.isSubmitting}>
            {t("credentials.add.save")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        {/* ── Template ── */}
        <div class={styles.selectWrapper}>
          <label class={styles.selectLabel} for="credential-template">
            {t("credentials.add.template")}
          </label>
          <select
            id="credential-template"
            class={styles.select}
            value={form.template}
            onChange={(e) => { e.stopPropagation(); handleTemplateChange(e.currentTarget.value); }}
            data-testid="credential-template-select"
          >
            <For each={CREDENTIAL_TEMPLATES}>
              {(tmpl) => (
                <option value={tmpl.id}>
                  {t(`credentials.templates.${tmpl.id}.name`)} — {t(`credentials.templates.${tmpl.id}.description`)}
                </option>
              )}
            </For>
          </select>
        </div>

        {/* ── Name ── */}
        <Input
          label={t("credentials.add.name")}
          value={form.name}
          onInput={(v) => {
            setForm("name", v);
            clearError("name");
          }}
          error={form.errors.name}
          placeholder={t("credentials.add.namePlaceholder")}
        />

        {/* ── Username ── */}
        <Input
          label={t("credentials.add.username")}
          value={form.username}
          onInput={(v) => setForm("username", v)}
          placeholder={t("credentials.add.usernamePlaceholder")}
        />

        {/* ── Password + Generator ── */}
        <div class={styles.passwordSection}>
          <PasswordInput
            label={t("credentials.add.password")}
            mode="create"
            value={form.password}
            onInput={(v) => {
              setForm("password", v);
              clearError("password");
            }}
            error={form.errors.password}
            placeholder={t("credentials.add.passwordPlaceholder")}
          />
          <PasswordGenerator onUse={handleUsePassword} />
        </div>

        <hr class={styles.separator} />

        {/* ── URLs ── */}
        <div class={styles.fieldGroup}>
          <span class={styles.sectionLabel}>{t("credentials.add.urls")}</span>
          <div class={styles.urlList}>
            <For each={form.urls}>
              {(url, index) => (
                <div class={styles.urlRow}>
                  <Input
                    label={index() === 0 ? t("credentials.add.primaryUrl") : t("credentials.add.urlN", { number: index() + 1 })}
                    type="url"
                    value={url}
                    onInput={(v) => handleUrlInput(index(), v)}
                    error={form.errors[`url-${index()}`]}
                    placeholder={t("credentials.add.urlPlaceholder")}
                  />
                  <Show when={form.urls.length > 1}>
                    <button
                      type="button"
                      class={styles.urlRemoveBtn}
                      onClick={() => removeUrl(index())}
                      aria-label={t("credentials.add.removeUrlAria", { n: index() + 1 })}
                    >
                      <Icon name="x" size={14} />
                    </button>
                  </Show>
                </div>
              )}
            </For>
          </div>
          <button type="button" class={styles.addBtn} onClick={addUrl} aria-label={t("credentials.add.addUrlAria")}>
            <Icon name="plus" size={14} /> {t("credentials.add.addUrl")}
          </button>
        </div>

        <hr class={styles.separator} />

        {/* ── Notes ── */}
        <div class={styles.textareaWrapper}>
          <label class={styles.textareaLabel} for="credential-notes">
            {t("credentials.add.notes")}
          </label>
          <textarea
            id="credential-notes"
            class={styles.textarea}
            value={form.notes}
            onInput={(e) => setForm("notes", e.currentTarget.value)}
            placeholder={t("credentials.add.notesPlaceholder")}
            rows={3}
          />
        </div>

        {/* ── Tags ── */}
        <div>
          <span class={styles.tagLabel}>{t("credentials.add.tags")}</span>
          <TagInput
            tags={form.tags}
            onChange={(tags) => setForm("tags", tags)}
            placeholder={t("credentials.add.tagsPlaceholder")}
          />
        </div>

        {/* ── Folder Selector ── */}
        <div class={styles.selectWrapper}>
          <label class={styles.selectLabel} for="credential-folder">
            {t("credentials.add.folder")}
          </label>
          <select
            id="credential-folder"
            class={styles.select}
            value={folderId()}
            onChange={(e) => setFolderId(e.currentTarget.value)}
          >
            <option value="">{t("credentials.add.folderNone")}</option>
            <For each={folders() ?? []}>
              {(f) => <option value={f.id}>{f.name}</option>}
            </For>
          </select>
        </div>

        <hr class={styles.separator} />

        {/* ── Link TOTP ── */}
        <div class={styles.selectWrapper}>
          <label class={styles.selectLabel} for="credential-totp-link">
            {t("credentials.add.linkTotp")}
          </label>
          <select
            id="credential-totp-link"
            class={styles.select}
            value={form.linkedTotpId}
            onChange={(e) => setForm("linkedTotpId", e.currentTarget.value)}
          >
            <option value="">{t("credentials.add.folderNone")}</option>
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
          <span class={styles.sectionLabel}>{t("credentials.add.customFields")}</span>
          <For each={form.customFields}>
            {(field, index) => (
              <div class={styles.customFieldRow}>
                <div class={styles.customFieldLabel}>
                  <Input
                    label={t("credentials.add.fieldName")}
                    value={field.label}
                    onInput={(v) => updateCustomField(index(), "label", v)}
                    error={form.errors[`cf-label-${index()}`]}
                    placeholder={t("credentials.add.fieldNamePlaceholder")}
                  />
                </div>

                <Show
                  when={field.fieldType !== "hidden"}
                  fallback={
                    <div class={styles.hiddenFieldRow}>
                      <Input
                        label={t("credentials.add.fieldValue")}
                        type={hiddenVisible[index()] ? "text" : "password"}
                        value={field.value}
                        onInput={(v) => updateCustomField(index(), "value", v)}
                        placeholder={t("credentials.add.hiddenValuePlaceholder")}
                      />
                      <button
                        type="button"
                        class={styles.hiddenToggle}
                        onClick={() =>
                          setHiddenVisible(index(), !hiddenVisible[index()])
                        }
                        aria-label={
                          hiddenVisible[index()] ? t("credentials.add.hideValueAria") : t("credentials.add.showValueAria")
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
                      label={t("credentials.add.fieldValue")}
                      type={field.fieldType === "url" ? "url" : "text"}
                      value={field.value}
                      onInput={(v) => updateCustomField(index(), "value", v)}
                      placeholder={
                        field.fieldType === "date" ? t("credentials.add.datePlaceholder") : t("credentials.add.valuePlaceholder")
                      }
                    />
                  </div>
                </Show>

                <div class={styles.selectWrapper}>
                  <label
                    class={styles.selectLabel}
                    for={`cf-type-${index()}`}
                  >
                    {t("credentials.add.fieldType.label")}
                  </label>
                  <select
                    id={`cf-type-${index()}`}
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
                  aria-label={t("credentials.add.removeFieldAria", { name: field.label || t("credentials.add.customField") })}
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
            <Icon name="plus" size={14} /> {t("credentials.add.addCustomField")}
          </button>
        </div>
      </div>
    </Modal>
  );
};
