/**
 * AddRecoveryCodeForm — modal form for adding recovery codes.
 *
 * Supports two modes:
 * - Linked: recovery codes linked to an existing TOTP/HOTP entry (AC1)
 * - Standalone: independent recovery codes with a service name (AC2)
 *
 * Includes bulk paste import (AC3) and single-code manual addition (AC4).
 */

import type { Component } from "solid-js";
import { Show, For, createSignal, createResource } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { addEntry, listEntries, type EntryMetadataDto } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./AddRecoveryCodeForm.module.css";

export interface AddRecoveryCodeFormProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

interface FormState {
  mode: "linked" | "standalone";
  linkedEntryId: string;
  linkedEntryName: string;
  name: string;
  issuer: string;
  folderId: string;
  codes: string[];
  singleCode: string;
  bulkText: string;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

const MAX_CODE_LENGTH = 256;

function createInitialState(): FormState {
  return {
    mode: "standalone",
    linkedEntryId: "",
    linkedEntryName: "",
    name: "",
    issuer: "",
    folderId: "",
    codes: [],
    singleCode: "",
    bulkText: "",
    isSubmitting: false,
    errors: {},
  };
}

export const AddRecoveryCodeForm: Component<AddRecoveryCodeFormProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<FormState>(createInitialState());
  const [folders] = createResource(() => props.open ? true : undefined, listFolders);
  const [accountFilter, setAccountFilter] = createSignal("");
  const [accountEntries, setAccountEntries] = createSignal<EntryMetadataDto[]>([]);
  const [showDropdown, setShowDropdown] = createSignal(false);

  // Load TOTP/HOTP entries for the account dropdown
  const loadAccounts = async () => {
    try {
      const all = await listEntries();
      setAccountEntries(
        all.filter((e) => e.entryType === "totp" || e.entryType === "hotp"),
      );
    } catch {
      // Silently fail — dropdown will be empty
    }
  };

  const filteredAccounts = () => {
    const filter = accountFilter().toLowerCase();
    if (!filter) return accountEntries();
    return accountEntries().filter(
      (e) =>
        e.name.toLowerCase().includes(filter) ||
        (e.issuer?.toLowerCase().includes(filter) ?? false),
    );
  };

  const handleClose = () => {
    setForm(createInitialState());
    setAccountFilter("");
    setShowDropdown(false);
    props.onClose();
  };

  const handleModeChange = (mode: "linked" | "standalone") => {
    setForm({
      mode,
      linkedEntryId: "",
      linkedEntryName: "",
      name: "",
      issuer: "",
      errors: {},
    });
    setAccountFilter("");
    if (mode === "linked") {
      loadAccounts();
    }
  };

  const handleSelectAccount = (entry: EntryMetadataDto) => {
    setForm({
      linkedEntryId: entry.id,
      linkedEntryName: entry.name,
      issuer: entry.issuer ?? "",
      name: entry.name,
    });
    setAccountFilter("");
    setShowDropdown(false);
  };

  // Bulk paste: parse newlines, trim, filter empty, validate length
  const handleBulkParse = () => {
    const parsed = form.bulkText
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    const tooLong = parsed.find((c) => c.length > MAX_CODE_LENGTH);
    if (tooLong) {
      setForm("errors", {
        ...form.errors,
        bulk: t("recovery.add.errors.codeTooLong", { max: MAX_CODE_LENGTH }),
      });
      return;
    }

    if (parsed.length === 0) {
      setForm("errors", { ...form.errors, bulk: t("recovery.add.errors.noValidCodes") });
      return;
    }

    // Append to existing codes (deduplicate)
    const existing = new Set(form.codes);
    const newCodes = parsed.filter((c) => !existing.has(c));
    setForm("codes", [...form.codes, ...newCodes]);
    setForm("bulkText", "");
    const { bulk: _, ...rest } = form.errors;
    setForm("errors", rest);
  };

  // Single code add
  const handleAddSingleCode = () => {
    const code = form.singleCode.trim();
    if (!code) return;
    if (code.length > MAX_CODE_LENGTH) {
      setForm("errors", {
        ...form.errors,
        single: t("recovery.add.errors.codeTooLong", { max: MAX_CODE_LENGTH }),
      });
      return;
    }
    if (form.codes.includes(code)) {
      setForm("errors", { ...form.errors, single: t("recovery.add.errors.codeAlreadyAdded") });
      return;
    }
    setForm("codes", [...form.codes, code]);
    setForm("singleCode", "");
    const { single: _, ...rest } = form.errors;
    setForm("errors", rest);
  };

  const handleRemoveCode = (index: number) => {
    setForm("codes", form.codes.filter((_, i) => i !== index));
  };

  const canSave = () => {
    if (form.isSubmitting) return false;
    if (form.codes.length === 0) return false;
    if (form.mode === "linked" && !form.linkedEntryId) return false;
    if (form.mode === "standalone" && !form.name.trim()) return false;
    return true;
  };

  const handleSave = async () => {
    if (!canSave()) return;

    // Validate name for standalone
    if (form.mode === "standalone" && !form.name.trim()) {
      setForm("errors", { name: t("recovery.add.errors.nameRequired") });
      return;
    }

    setForm("isSubmitting", true);
    try {
      await addEntry({
        entryType: "recovery_code",
        name: form.name.trim(),
        issuer: form.issuer.trim() || undefined,
        secret: form.codes.join("\n"),
        linkedEntryId: form.mode === "linked" ? form.linkedEntryId : undefined,
        folderId: form.folderId || undefined,
      });
      toast.success(t("recovery.add.success"));
      setForm(createInitialState());
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(
        typeof err === "string"
          ? err
          : t("recovery.add.error"),
      );
    } finally {
      setForm("isSubmitting", false);
    }
  };

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("recovery.add.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button variant="ghost" onClick={handleClose}>
            {t("recovery.add.cancel")}
          </Button>
          <Button
            variant="primary"
            onClick={handleSave}
            disabled={!canSave()}
            loading={form.isSubmitting}
          >
            <Icon name="check" size={16} /> {t("recovery.add.save")}
          </Button>
        </>
      }
    >
      <div class={styles.form}>
        {/* Mode selector */}
        <div class={styles.modeSelector}>
          <button
            class={`${styles.modeBtn} ${form.mode === "linked" ? styles.modeBtnActive : ""}`}
            onClick={() => handleModeChange("linked")}
            type="button"
          >
            <Icon name="link" size={14} />
            {t("recovery.add.linkToAccount")}
          </button>
          <button
            class={`${styles.modeBtn} ${form.mode === "standalone" ? styles.modeBtnActive : ""}`}
            onClick={() => handleModeChange("standalone")}
            type="button"
          >
            <Icon name="shield" size={14} />
            {t("recovery.add.standalone")}
          </button>
        </div>

        {/* Linked mode: account search dropdown */}
        <Show when={form.mode === "linked"}>
          <div class={styles.fieldGroup}>
            <div
              class={styles.comboboxWrapper}
              onFocusIn={() => {
                loadAccounts();
                setShowDropdown(true);
              }}
              onFocusOut={(e) => {
                // Close dropdown when focus leaves the combobox wrapper entirely.
                // Small delay allows click events on dropdown items to fire first.
                const wrapper = e.currentTarget;
                setTimeout(() => {
                  if (!wrapper.contains(document.activeElement)) {
                    setShowDropdown(false);
                  }
                }, 150);
              }}
            >
              <Input
                label={t("recovery.add.linkLabel")}
                value={form.linkedEntryName || accountFilter()}
                onInput={(value) => {
                  setAccountFilter(value);
                  setForm("linkedEntryId", "");
                  setForm("linkedEntryName", "");
                  setShowDropdown(true);
                }}
                placeholder={t("recovery.add.searchPlaceholder")}
              />
              <Show when={showDropdown() && filteredAccounts().length > 0}>
                <ul class={styles.dropdown}>
                  <For each={filteredAccounts()}>
                    {(entry) => (
                      <li>
                        <button
                          class={styles.dropdownItem}
                          onClick={() => handleSelectAccount(entry)}
                          type="button"
                        >
                          <span class={styles.dropdownName}>{entry.name}</span>
                          <Show when={entry.issuer}>
                            <span class={styles.dropdownIssuer}>{entry.issuer}</span>
                          </Show>
                        </button>
                      </li>
                    )}
                  </For>
                </ul>
              </Show>
            </div>
          </div>
        </Show>

        {/* Standalone mode: name + issuer fields */}
        <Show when={form.mode === "standalone"}>
          <div class={styles.fieldGroup}>
            <Input
              label={t("recovery.add.serviceName")}
              value={form.name}
              onInput={(value) => {
                setForm("name", value);
                if (form.errors.name) {
                  const { name: _, ...rest } = form.errors;
                  setForm("errors", rest);
                }
              }}
              error={form.errors.name}
              placeholder={t("recovery.add.serviceNamePlaceholder")}
            />
            <Input
              label={t("recovery.add.issuer")}
              value={form.issuer}
              onInput={(value) => setForm("issuer", value)}
              placeholder={t("recovery.add.issuerPlaceholder")}
            />
          </div>
        </Show>

        {/* Folder Selector */}
        <div class={styles.fieldGroup}>
          <div class={styles.selectWrapper}>
            <label class={styles.selectLabel} for="select-folder">
              {t("recovery.add.folder")}
            </label>
            <select
              id="select-folder"
              class={styles.select}
              value={form.folderId}
              onChange={(e) => setForm("folderId", e.currentTarget.value)}
            >
              <option value="">{t("recovery.add.folderNone")}</option>
              <For each={folders() ?? []}>
                {(f) => <option value={f.id}>{f.name}</option>}
              </For>
            </select>
          </div>
        </div>

        <hr class={styles.separator} />

        {/* Bulk paste area */}
        <div class={styles.fieldGroup}>
          <label class={styles.textareaLabel} for="bulk-paste">
            {t("recovery.add.pasteLabel")}
          </label>
          <textarea
            id="bulk-paste"
            class={styles.textarea}
            value={form.bulkText}
            onInput={(e) => {
              setForm("bulkText", e.currentTarget.value);
              if (form.errors.bulk) {
                const { bulk: _, ...rest } = form.errors;
                setForm("errors", rest);
              }
            }}
            placeholder={t("recovery.add.pastePlaceholder")}
            rows={4}
          />
          <Show when={form.errors.bulk}>
            <span class={styles.fieldError}>{form.errors.bulk}</span>
          </Show>
          <Button
            variant="ghost"
            onClick={handleBulkParse}
            disabled={!form.bulkText.trim()}
          >
            <Icon name="plus" size={14} /> {t("recovery.add.importCodes")}
          </Button>
        </div>

        <hr class={styles.separator} />

        {/* Single code add */}
        <div class={styles.singleAddRow}>
          <div
            class={styles.singleInput}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                handleAddSingleCode();
              }
            }}
          >
            <Input
              label={t("recovery.add.addSingleCode")}
              value={form.singleCode}
              onInput={(value) => {
                setForm("singleCode", value);
                if (form.errors.single) {
                  const { single: _, ...rest } = form.errors;
                  setForm("errors", rest);
                }
              }}
              error={form.errors.single}
              placeholder={t("recovery.add.singleCodePlaceholder")}
            />
          </div>
          <Button
            variant="ghost"
            onClick={handleAddSingleCode}
            disabled={!form.singleCode.trim()}
          >
            {t("recovery.add.addBtn")}
          </Button>
        </div>

        {/* Code preview list */}
        <Show when={form.codes.length > 0}>
          <div class={styles.codeList}>
            <div class={styles.codeListHeader}>
              <span class={styles.codeListBadge}>
                {t("recovery.add.codeCount", { count: form.codes.length })}
              </span>
            </div>
            <ol class={styles.codeItems}>
              <For each={form.codes}>
                {(code, index) => (
                  <li class={styles.codeItem}>
                    <span class={styles.codeText}>{code}</span>
                    <button
                      class={styles.removeBtn}
                      onClick={() => handleRemoveCode(index())}
                      aria-label={t("recovery.add.removeCodeAria", { n: index() + 1 })}
                      type="button"
                    >
                      <Icon name="x" size={14} />
                    </button>
                  </li>
                )}
              </For>
            </ol>
          </div>
        </Show>
      </div>
    </Modal>
  );
};
