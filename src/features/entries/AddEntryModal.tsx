import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, createResource, on } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { addEntry } from "./ipc";
import { listFolders } from "../folders/ipc";
import { detectPasteType } from "./paste-detection";
import { isValidBase32, validateEntryForm, type AddEntryFormState } from "./validation";
import type { OtpAlgorithm, OtpDigits, OtpPeriod } from "./otpauth";
import { t } from "../../stores/i18nStore";
import styles from "./AddEntryModal.module.css";

export interface AddEntryModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
  initialData?: { name?: string; issuer?: string };
}

const INITIAL_FORM: AddEntryFormState = {
  secret: "",
  name: "",
  issuer: "",
  algorithm: "SHA1",
  digits: 6,
  period: 30,
  pasteInput: "",
  pasteDetected: null,
  showManualForm: false,
  showAdvanced: false,
  isSubmitting: false,
  errors: {},
};

export const AddEntryModal: Component<AddEntryModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<AddEntryFormState>({ ...INITIAL_FORM });
  const [pasteFeedback, setPasteFeedback] = createSignal<string>("");
  const [pasteFeedbackType, setPasteFeedbackType] = createSignal<"success" | "error" | "">("");
  const [folderId, setFolderId] = createSignal("");
  const [folders] = createResource(() => props.open ? true : undefined, listFolders);

  const resetForm = () => {
    const initial = props.initialData
      ? {
          ...INITIAL_FORM,
          name: props.initialData.name ?? "",
          issuer: props.initialData.issuer ?? "",
          showManualForm: true,
          pasteDetected: "manual" as const,
        }
      : { ...INITIAL_FORM };
    setForm(initial);
    setFolderId("");
    setPasteFeedback("");
    setPasteFeedbackType("");
  };

  // When modal opens with initialData, start in manual mode with pre-populated fields
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          resetForm();
        }
      },
    ),
  );

  const handleClose = () => {
    resetForm();
    props.onClose();
  };

  const handlePasteInput = (value: string) => {
    setForm("pasteInput", value);
    setForm("errors", {});

    if (!value.trim()) {
      setPasteFeedback("");
      setPasteFeedbackType("");
      setForm("pasteDetected", null);
      return;
    }

    const result = detectPasteType(value);

    if (result.type === "uri") {
      const p = result.parsed;
      setForm({
        secret: p.secret,
        name: p.name,
        issuer: p.issuer,
        algorithm: p.algorithm,
        digits: p.digits,
        period: p.period,
        pasteDetected: "uri",
        showManualForm: true,
      });
      setPasteFeedback(t("entries.add.pasteDetectedUri"));
      setPasteFeedbackType("success");
    } else if (result.type === "base32") {
      setForm({
        secret: result.secret,
        pasteDetected: "base32",
        showManualForm: true,
      });
      setPasteFeedback(t("entries.add.pasteDetectedBase32"));
      setPasteFeedbackType("success");
    } else {
      setForm("pasteDetected", null);
      setPasteFeedback(t("entries.add.pasteInvalid"));
      setPasteFeedbackType("error");
    }
  };

  const handleManualToggle = () => {
    setForm("showManualForm", true);
    setForm("pasteDetected", "manual");
  };

  const handleAdvancedToggle = () => {
    setForm("showAdvanced", !form.showAdvanced);
  };

  const clearError = (field: string) => {
    if (form.errors[field]) {
      const { [field]: _, ...rest } = form.errors;
      setForm("errors", rest);
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

  const handleSecretInput = (value: string) => {
    setForm("secret", value);
    if (value.trim() && !isValidBase32(value)) {
      setForm("errors", "secret", t("entries.add.base32Error"));
    } else {
      clearError("secret");
    }
  };

  const handleSave = async () => {
    const errors = validateEntryForm(form);
    if (Object.keys(errors).length > 0) {
      setForm("errors", errors);
      return;
    }

    setForm("isSubmitting", true);
    try {
      const result = await addEntry({
        entryType: "totp",
        name: form.name.trim(),
        issuer: form.issuer.trim() || undefined,
        secret: form.secret.replace(/\s/g, "").toUpperCase(),
        algorithm: form.algorithm,
        digits: form.digits,
        period: form.period,
        folderId: folderId() || undefined,
      });
      toast.success(t("entries.add.success", { name: result.name }));
      resetForm();
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("entries.add.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  const showFields = () => form.showManualForm || form.pasteDetected === "uri" || form.pasteDetected === "base32";

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("entries.add.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button variant="ghost" onClick={handleClose}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            loading={form.isSubmitting}
          >
            {t("entries.add.saveButton")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        {/* Paste Area + Method Toggles (hidden when initialData is provided) */}
        <Show when={!props.initialData}>
          <div class={styles.pasteSection}>
            <label class={styles.pasteLabel} for="paste-input">
              {t("entries.add.pasteLabel")}
            </label>
            <textarea
              id="paste-input"
              class={styles.pasteArea}
              placeholder={t("entries.add.pastePlaceholder")}
              value={form.pasteInput}
              onInput={(e) => handlePasteInput(e.currentTarget.value)}
              rows={3}
              aria-invalid={pasteFeedbackType() === "error" || undefined}
              aria-describedby={pasteFeedback() ? "paste-feedback" : undefined}
            />
            <div class={styles.feedback}>
              <Show when={pasteFeedback()}>
                <span
                  id="paste-feedback"
                  class={
                    pasteFeedbackType() === "success"
                      ? styles.feedbackSuccess
                      : styles.feedbackError
                  }
                  role="status"
                >
                  <Show when={pasteFeedbackType() === "success"}>
                    <Icon name="check" size={14} />
                  </Show>
                  <Show when={pasteFeedbackType() === "error"}>
                    <Icon name="alert" size={14} />
                  </Show>
                  {" "}{pasteFeedback()}
                </span>
              </Show>
            </div>
          </div>

          <div class={styles.methodSection}>
            <button
              class={`${styles.methodLink} ${styles.methodLinkDisabled}`}
              type="button"
              disabled
              title={t("entries.add.comingSoon")}
            >
              {t("entries.add.scanFromScreen")}
            </button>
            <Show when={!showFields()}>
              <button
                class={styles.methodLink}
                type="button"
                onClick={handleManualToggle}
              >
                <Icon name="chevron-right" size={14} /> {t("entries.add.enterManually")}
              </button>
            </Show>
          </div>
        </Show>

        {/* Entry Form Fields (shown after paste detection or manual toggle) */}
        <Show when={showFields()}>
          <hr class={styles.separator} />
          <div class={styles.fieldGroup}>
            <Input
              label={t("entries.add.accountLabel")}
              value={form.name}
              onInput={handleNameInput}
              error={form.errors.name}
              placeholder={t("entries.add.accountPlaceholder")}
            />
            <Input
              label={t("entries.add.issuerLabel")}
              value={form.issuer}
              onInput={handleIssuerInput}
              error={form.errors.issuer}
              placeholder={t("entries.add.issuerPlaceholder")}
            />

            {/* Secret field only shown in manual mode (paste fills it automatically) */}
            <Show when={form.pasteDetected === "manual"}>
              <Input
                label={t("entries.add.secretLabel")}
                value={form.secret}
                onInput={handleSecretInput}
                error={form.errors.secret}
                placeholder={t("entries.add.secretPlaceholder")}
              />
            </Show>

            {/* Folder Selector */}
            <div class={styles.selectWrapper}>
              <label class={styles.selectLabel} for="select-folder">
                {t("entries.add.folderLabel")}
              </label>
              <select
                id="select-folder"
                class={styles.select}
                value={folderId()}
                onChange={(e) => setFolderId(e.currentTarget.value)}
              >
                <option value="">{t("entries.add.folderNone")}</option>
                <For each={folders() ?? []}>
                  {(f) => <option value={f.id}>{f.name}</option>}
                </For>
              </select>
            </div>

            {/* Advanced Settings */}
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
              {t("entries.add.advancedSettings")}
            </button>

            <Show when={form.showAdvanced}>
              <div class={styles.advancedFields}>
                <div class={styles.selectWrapper}>
                  <label class={styles.selectLabel} for="select-algorithm">
                    {t("entries.add.algorithmLabel")}
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
                    {t("entries.add.digitsLabel")}
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
                    {t("entries.add.periodLabel")}
                  </label>
                  <select
                    id="select-period"
                    class={styles.select}
                    value={form.period}
                    onChange={(e) =>
                      setForm("period", Number(e.currentTarget.value) as OtpPeriod)
                    }
                  >
                    <option value="15">{t("entries.add.period15")}</option>
                    <option value="30">{t("entries.add.period30")}</option>
                    <option value="60">{t("entries.add.period60")}</option>
                  </select>
                </div>
              </div>
            </Show>
          </div>
        </Show>
      </div>
    </Modal>
  );
};
