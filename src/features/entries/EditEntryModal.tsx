import type { Component } from "solid-js";
import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { getEntry, updateEntry } from "./ipc";
import { listFolders, type FolderWithCountDto } from "../folders/ipc";
import type { OtpAlgorithm, OtpDigits, OtpPeriod } from "./otpauth";
import { t } from "../../stores/i18nStore";
import styles from "./EditEntryModal.module.css";

export interface EditEntryModalProps {
  open: boolean;
  entryId: string;
  onClose: () => void;
  onSuccess: () => void;
  onDelete?: (entryId: string, entryName: string) => void;
  onExport?: (entryId: string, name: string, issuer: string | undefined, entryType: string) => void;
}

interface EditEntryFormState {
  name: string;
  issuer: string;
  folderId: string;
  algorithm: string;
  digits: number;
  period: number;
  pinned: boolean;
  showAdvanced: boolean;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

const INITIAL_FORM: EditEntryFormState = {
  name: "",
  issuer: "",
  folderId: "",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pinned: false,
  showAdvanced: false,
  isSubmitting: false,
  errors: {},
};

export const EditEntryModal: Component<EditEntryModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<EditEntryFormState>({ ...INITIAL_FORM });
  const [entryType, setEntryType] = createSignal("");
  const [folders] = createResource(() => props.open ? true : undefined, listFolders);

  // Track original parameter values for change detection
  let originalAlgorithm = "";
  let originalDigits = 0;
  let originalPeriod = 0;

  // Fetch entry detail when modal opens with a valid entryId
  const [entryDetail] = createResource(
    () => (props.open ? props.entryId : undefined),
    (id) => getEntry(id),
  );

  // Pre-populate form when entry detail loads
  createEffect(() => {
    const entry = entryDetail();
    if (entry) {
      setEntryType(entry.entryType);
      originalAlgorithm = entry.algorithm;
      originalDigits = entry.digits;
      originalPeriod = entry.period;

      setForm({
        name: entry.name,
        issuer: entry.issuer ?? "",
        folderId: entry.folderId ?? "",
        algorithm: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
        pinned: entry.pinned,
        showAdvanced: false,
        isSubmitting: false,
        errors: {},
      });
    }
  });

  const isOtpType = () => {
    const et = entryType();
    return et === "totp" || et === "hotp";
  };

  const hasParameterChanges = () =>
    form.algorithm !== originalAlgorithm ||
    form.digits !== originalDigits ||
    form.period !== originalPeriod;

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

  const handleAdvancedToggle = () => {
    setForm("showAdvanced", !form.showAdvanced);
  };

  const validateForm = (): Record<string, string> => {
    const errors: Record<string, string> = {};
    const trimmedName = form.name.trim();
    if (!trimmedName) {
      errors.name = "Account name is required.";
    } else if (trimmedName.length > 100) {
      errors.name = "Account name too long (max 100 characters).";
    }
    if (form.issuer && form.issuer.length > 100) {
      errors.issuer = "Issuer too long (max 100 characters).";
    }
    return errors;
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
      await updateEntry({
        id: props.entryId,
        name: form.name.trim(),
        issuer: form.issuer.trim() || null,
        folderId: form.folderId || null,
        pinned: form.pinned,
        ...(isOtpType() ? {
          algorithm: form.algorithm,
          digits: form.digits,
          period: form.period,
        } : {}),
      });
      toast.success(t("entries.edit.success"));
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("entries.edit.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  const handleClose = () => {
    props.onClose();
  };

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("entries.edit.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Show when={props.onDelete}>
            <Button
              variant="danger"
              onClick={() => props.onDelete?.(props.entryId, form.name)}
              class={styles.deleteBtn}
              disabled={form.isSubmitting}
            >
              {t("entries.edit.deleteButton")}
            </Button>
          </Show>
          <Show when={isOtpType() && props.onExport}>
            <Button
              variant="ghost"
              onClick={() => props.onExport?.(props.entryId, form.name, form.issuer || undefined, entryType())}
              disabled={form.isSubmitting}
              data-testid="export-uri-btn"
            >
              <Icon name="share" size={16} /> {t("entries.edit.exportUri")}
            </Button>
          </Show>
          <Button variant="ghost" onClick={handleClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            loading={form.isSubmitting}
          >
            {t("entries.edit.saveButton")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        <div class={styles.fieldGroup}>
          <Input
            label={t("entries.edit.accountLabel")}
            value={form.name}
            onInput={handleNameInput}
            error={form.errors.name}
            placeholder={t("entries.edit.accountPlaceholder")}
          />
          <Input
            label={t("entries.edit.issuerLabel")}
            value={form.issuer}
            onInput={handleIssuerInput}
            error={form.errors.issuer}
            placeholder={t("entries.edit.issuerPlaceholder")}
          />

          <div class={styles.selectWrapper}>
            <label class={styles.selectLabel} for="select-folder">
              {t("entries.edit.folderLabel")}
            </label>
            <select
              id="select-folder"
              class={styles.select}
              value={form.folderId}
              onChange={(e) => setForm("folderId", e.currentTarget.value)}
            >
              <option value="">{t("entries.edit.folderNone")}</option>
              <For each={folders() ?? []}>
                {(f) => <option value={f.id}>{f.name}</option>}
              </For>
            </select>
          </div>

          <label class={styles.pinCheckbox}>
            <input
              type="checkbox"
              checked={form.pinned}
              onChange={(e) => setForm("pinned", e.currentTarget.checked)}
              data-testid="pin-checkbox"
            />
            <Icon name="star" size={14} />
            <span>{t("entries.edit.pinFavorite")}</span>
          </label>

          {/* Advanced Settings — TOTP/HOTP only */}
          <Show when={isOtpType()}>
            <button
              class={styles.advancedToggle}
              type="button"
              onClick={handleAdvancedToggle}
              aria-expanded={form.showAdvanced}
            >
              <Icon
                name="chevron-right"
                size={14}
                class={`${styles.chevron} ${form.showAdvanced ? styles.chevronOpen : ""}`}
              />
              {t("entries.edit.advancedSettings")}
            </button>

            <Show when={form.showAdvanced}>
              <div class={styles.advancedFields}>
                {/* Parameter Change Warning */}
                <Show when={hasParameterChanges()}>
                  <div class={styles.warningBanner} role="alert">
                    <Icon name="alert" size={16} />
                    {t("entries.edit.advancedWarning")}
                  </div>
                </Show>

                <div class={styles.selectWrapper}>
                  <label class={styles.selectLabel} for="select-algorithm">
                    {t("entries.edit.algorithmLabel")}
                  </label>
                  <select
                    id="select-algorithm"
                    class={styles.select}
                    value={form.algorithm}
                    onChange={(e) =>
                      setForm("algorithm", e.currentTarget.value as OtpAlgorithm)
                    }
                  >
                    <option value="SHA1">SHA1</option>
                    <option value="SHA256">SHA256</option>
                    <option value="SHA512">SHA512</option>
                  </select>
                </div>

                <div class={styles.selectWrapper}>
                  <label class={styles.selectLabel} for="select-digits">
                    {t("entries.edit.digitsLabel")}
                  </label>
                  <select
                    id="select-digits"
                    class={styles.select}
                    value={form.digits}
                    onChange={(e) =>
                      setForm("digits", Number(e.currentTarget.value) as OtpDigits)
                    }
                  >
                    <option value="6">6</option>
                    <option value="8">8</option>
                  </select>
                </div>

                <div class={styles.selectWrapper}>
                  <label class={styles.selectLabel} for="select-period">
                    {t("entries.edit.periodLabel")}
                  </label>
                  <select
                    id="select-period"
                    class={styles.select}
                    value={form.period}
                    onChange={(e) =>
                      setForm("period", Number(e.currentTarget.value) as OtpPeriod)
                    }
                  >
                    <option value="15">{t("entries.edit.period15")}</option>
                    <option value="30">{t("entries.edit.period30")}</option>
                    <option value="60">{t("entries.edit.period60")}</option>
                  </select>
                </div>
              </div>
            </Show>
          </Show>
        </div>
      </div>
    </Modal>
  );
};
