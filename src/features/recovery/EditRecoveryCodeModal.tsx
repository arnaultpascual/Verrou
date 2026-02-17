/**
 * EditRecoveryCodeModal — edit recovery code metadata and manage code list.
 *
 * Allows editing name/issuer (no re-auth), and adding/removing codes
 * (requires re-auth since codes are Layer 2 encrypted).
 */

import type { Component } from "solid-js";
import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Input } from "../../components/Input";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { useToast } from "../../components/useToast";
import { getEntry, updateEntry } from "../entries/ipc";
import { revealRecoveryCodes, updateRecoveryCodes } from "./ipc";
import type { RecoveryCodeDisplay } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./EditRecoveryCodeModal.module.css";

const MAX_CODE_LENGTH = 256;

export interface EditRecoveryCodeModalProps {
  open: boolean;
  entryId: string;
  onClose: () => void;
  onSuccess: () => void;
}

interface EditFormState {
  name: string;
  issuer: string;
  pinned: boolean;
  isSubmitting: boolean;
  errors: Record<string, string>;
}

const INITIAL_FORM: EditFormState = {
  name: "",
  issuer: "",
  pinned: false,
  isSubmitting: false,
  errors: {},
};

export const EditRecoveryCodeModal: Component<EditRecoveryCodeModalProps> = (props) => {
  const toast = useToast();
  const [form, setForm] = createStore<EditFormState>({ ...INITIAL_FORM });
  const [showReAuth, setShowReAuth] = createSignal(false);
  const [revealedCodes, setRevealedCodes] = createSignal<RecoveryCodeDisplay | null>(null);
  const [sessionPassword, setSessionPassword] = createSignal<string | null>(null);
  const [codesToAdd, setCodesToAdd] = createSignal<string[]>([]);
  const [indexesToRemove, setIndexesToRemove] = createSignal<Set<number>>(new Set());
  const [singleCode, setSingleCode] = createSignal("");
  const [bulkText, setBulkText] = createSignal("");

  // Fetch entry detail when modal opens
  const [entryDetail] = createResource(
    () => (props.open ? props.entryId : undefined),
    (id) => getEntry(id),
  );

  // Pre-populate form when entry detail loads
  createEffect(() => {
    const entry = entryDetail();
    if (entry) {
      setForm({
        name: entry.name,
        issuer: entry.issuer ?? "",
        pinned: entry.pinned,
        isSubmitting: false,
        errors: {},
      });
      // Reset code editing state
      setRevealedCodes(null);
      setSessionPassword(null);
      setCodesToAdd([]);
      setIndexesToRemove(new Set<number>());
      setSingleCode("");
      setBulkText("");
    }
  });

  const hasCodeChanges = () =>
    codesToAdd().length > 0 || indexesToRemove().size > 0;

  const handleRevealRequest = () => {
    setShowReAuth(true);
  };

  const handleVerified = async (password: string) => {
    setShowReAuth(false);
    try {
      const data = await revealRecoveryCodes(props.entryId, password);
      setRevealedCodes(data);
      setSessionPassword(password);
    } catch (err) {
      const msg = typeof err === "string" ? err : t("recovery.edit.incorrectPassword");
      toast.error(msg);
    }
  };

  const handleAddSingleCode = () => {
    const code = singleCode().trim();
    if (!code) return;
    if (code.length > MAX_CODE_LENGTH) {
      setForm("errors", { ...form.errors, single: t("recovery.edit.errors.codeTooLong", { max: MAX_CODE_LENGTH }) });
      return;
    }
    // Check duplicates against existing + pending
    const existing = revealedCodes()?.codes ?? [];
    const pending = codesToAdd();
    if (existing.includes(code) || pending.includes(code)) {
      setForm("errors", { ...form.errors, single: t("recovery.edit.errors.codeAlreadyExists") });
      return;
    }
    setCodesToAdd([...pending, code]);
    setSingleCode("");
    const { single: _, ...rest } = form.errors;
    setForm("errors", rest);
  };

  const handleBulkParse = () => {
    const parsed = bulkText()
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0);

    const tooLong = parsed.find((c) => c.length > MAX_CODE_LENGTH);
    if (tooLong) {
      setForm("errors", { ...form.errors, bulk: t("recovery.edit.errors.codeTooLong", { max: MAX_CODE_LENGTH }) });
      return;
    }

    if (parsed.length === 0) {
      setForm("errors", { ...form.errors, bulk: t("recovery.edit.errors.noValidCodes") });
      return;
    }

    const existing = new Set(revealedCodes()?.codes ?? []);
    const pendingSet = new Set(codesToAdd());
    const newCodes = parsed.filter((c) => !existing.has(c) && !pendingSet.has(c));
    setCodesToAdd([...codesToAdd(), ...newCodes]);
    setBulkText("");
    const { bulk: _, ...rest } = form.errors;
    setForm("errors", rest);
  };

  const handleRemoveExistingCode = (index: number) => {
    const updated = new Set(indexesToRemove());
    if (updated.has(index)) {
      updated.delete(index);
    } else {
      updated.add(index);
    }
    setIndexesToRemove(updated);
  };

  const handleRemovePendingCode = (index: number) => {
    setCodesToAdd(codesToAdd().filter((_, i) => i !== index));
  };

  const validateForm = (): Record<string, string> => {
    const errors: Record<string, string> = {};
    const trimmedName = form.name.trim();
    if (!trimmedName) {
      errors.name = t("recovery.edit.errors.nameRequired");
    } else if (trimmedName.length > 100) {
      errors.name = t("recovery.edit.errors.nameTooLong");
    }
    if (form.issuer && form.issuer.length > 100) {
      errors.issuer = t("recovery.edit.errors.issuerTooLong");
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
      // Step 1: Save metadata (name/issuer) — no re-auth needed
      await updateEntry({
        id: props.entryId,
        name: form.name.trim(),
        issuer: form.issuer.trim() || null,
        pinned: form.pinned,
      });

      // Step 2: Save code changes (add/remove) — requires re-auth
      if (hasCodeChanges()) {
        const pw = sessionPassword();
        if (!pw) {
          toast.error(t("recovery.edit.reAuthRequired"));
          setForm("isSubmitting", false);
          return;
        }
        await updateRecoveryCodes(
          props.entryId,
          codesToAdd(),
          Array.from(indexesToRemove()),
          pw,
        );
      }

      toast.success(t("recovery.edit.success"));
      props.onSuccess();
      props.onClose();
    } catch (err) {
      toast.error(typeof err === "string" ? err : t("recovery.edit.error"));
    } finally {
      setForm("isSubmitting", false);
    }
  };

  const handleClose = () => {
    setSessionPassword(null);
    setRevealedCodes(null);
    setCodesToAdd([]);
    setIndexesToRemove(new Set<number>());
    setSingleCode("");
    setBulkText("");
    props.onClose();
  };

  return (
    <>
      <Modal
        open={props.open}
        onClose={handleClose}
        title={t("recovery.edit.title")}
        closeOnOverlayClick={false}
        actions={
          <>
            <Button variant="ghost" onClick={handleClose}>
              {t("recovery.edit.cancel")}
            </Button>
            <Button
              variant="primary"
              onClick={handleSave}
              loading={form.isSubmitting}
            >
              {t("recovery.edit.save")}
            </Button>
          </>
        }
      >
        <div class={styles.form}>
          {/* Metadata fields */}
          <div class={styles.fieldGroup}>
            <Input
              label={t("recovery.edit.serviceName")}
              value={form.name}
              onInput={(value) => {
                setForm("name", value);
                if (form.errors.name) {
                  const { name: _, ...rest } = form.errors;
                  setForm("errors", rest);
                }
              }}
              error={form.errors.name}
              placeholder={t("recovery.edit.serviceNamePlaceholder")}
            />
            <Input
              label={t("recovery.edit.issuer")}
              value={form.issuer}
              onInput={(value) => {
                setForm("issuer", value);
                if (form.errors.issuer) {
                  const { issuer: _, ...rest } = form.errors;
                  setForm("errors", rest);
                }
              }}
              error={form.errors.issuer}
              placeholder={t("recovery.edit.issuerPlaceholder")}
            />

            {/* Pin as favorite */}
            <label class={styles.pinCheckbox}>
              <input
                type="checkbox"
                checked={form.pinned}
                onChange={(e) => setForm("pinned", e.currentTarget.checked)}
              />
              <Icon name="star" size={14} />
              <span>{t("recovery.edit.pinFavorite")}</span>
            </label>
          </div>

          <hr class={styles.separator} />

          {/* Code management section */}
          <Show
            when={revealedCodes()}
            fallback={
              <div class={styles.revealPrompt}>
                <Icon name="lock" size={24} />
                <p>{t("recovery.edit.reAuthPrompt")}</p>
                <Button variant="primary" onClick={handleRevealRequest}>
                  <Icon name="eye" size={16} />
                  {t("recovery.edit.revealCodes")}
                </Button>
              </div>
            }
          >
            {(data) => (
              <div class={styles.codeSection}>
                <div class={styles.codeSectionHeader}>
                  <span class={styles.codeBadge}>
                    {t("recovery.edit.codeCount", { count: data().codes.length - indexesToRemove().size + codesToAdd().length })}
                  </span>
                  <Show when={indexesToRemove().size > 0}>
                    <span class={styles.removeCount}>
                      {t("recovery.edit.markedForRemoval", { count: indexesToRemove().size })}
                    </span>
                  </Show>
                </div>

                {/* Existing codes with remove toggles */}
                <ul class={styles.codeList}>
                  <For each={data().codes}>
                    {(code, index) => {
                      const isMarkedForRemoval = () => indexesToRemove().has(index());
                      const isUsed = () => data().used.includes(index());
                      return (
                        <li
                          class={`${styles.codeItem} ${isMarkedForRemoval() ? styles.codeMarkedRemoval : ""} ${isUsed() ? styles.codeUsed : ""}`}
                        >
                          <span class={styles.codeText}>{code}</span>
                          <Show when={isUsed()}>
                            <span class={styles.usedBadge}>{t("recovery.edit.usedBadge")}</span>
                          </Show>
                          <button
                            class={styles.removeBtn}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRemoveExistingCode(index());
                            }}
                            onKeyDown={(e) => e.stopPropagation()}
                            type="button"
                            aria-label={isMarkedForRemoval()
                              ? t("recovery.edit.undoRemovalAria", { n: index() + 1 })
                              : t("recovery.edit.removeCodeAria", { n: index() + 1 })}
                          >
                            <Icon name={isMarkedForRemoval() ? "undo" : "x"} size={14} />
                          </button>
                        </li>
                      );
                    }}
                  </For>
                </ul>

                {/* Pending new codes */}
                <Show when={codesToAdd().length > 0}>
                  <div class={styles.pendingHeader}>
                    <span class={styles.codeBadge}>
                      {t("recovery.edit.newCodesCount", { count: codesToAdd().length })}
                    </span>
                  </div>
                  <ul class={styles.codeList}>
                    <For each={codesToAdd()}>
                      {(code, index) => (
                        <li class={`${styles.codeItem} ${styles.codeNew}`}>
                          <span class={styles.codeText}>{code}</span>
                          <button
                            class={styles.removeBtn}
                            onClick={(e) => {
                              e.stopPropagation();
                              handleRemovePendingCode(index());
                            }}
                            onKeyDown={(e) => e.stopPropagation()}
                            type="button"
                            aria-label={t("recovery.edit.removeNewCodeAria", { n: index() + 1 })}
                          >
                            <Icon name="x" size={14} />
                          </button>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>

                <hr class={styles.separator} />

                {/* Bulk paste */}
                <div class={styles.fieldGroup}>
                  <label class={styles.textareaLabel} for="edit-bulk-paste">
                    {t("recovery.edit.pasteLabel")}
                  </label>
                  <textarea
                    id="edit-bulk-paste"
                    class={styles.textarea}
                    value={bulkText()}
                    onInput={(e) => {
                      setBulkText(e.currentTarget.value);
                      if (form.errors.bulk) {
                        const { bulk: _, ...rest } = form.errors;
                        setForm("errors", rest);
                      }
                    }}
                    placeholder={t("recovery.edit.pastePlaceholder")}
                    rows={3}
                  />
                  <Show when={form.errors.bulk}>
                    <span class={styles.fieldError}>{form.errors.bulk}</span>
                  </Show>
                  <Button
                    variant="ghost"
                    onClick={handleBulkParse}
                    disabled={!bulkText().trim()}
                  >
                    <Icon name="plus" size={14} /> {t("recovery.edit.importCodes")}
                  </Button>
                </div>

                {/* Single code add */}
                <div
                  class={styles.singleAddRow}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      handleAddSingleCode();
                    }
                  }}
                >
                  <div class={styles.singleInput}>
                    <Input
                      label={t("recovery.edit.addSingleCode")}
                      value={singleCode()}
                      onInput={(value) => {
                        setSingleCode(value);
                        if (form.errors.single) {
                          const { single: _, ...rest } = form.errors;
                          setForm("errors", rest);
                        }
                      }}
                      error={form.errors.single}
                      placeholder={t("recovery.edit.singleCodePlaceholder")}
                    />
                  </div>
                  <Button
                    variant="ghost"
                    onClick={handleAddSingleCode}
                    disabled={!singleCode().trim()}
                  >
                    {t("recovery.edit.addBtn")}
                  </Button>
                </div>
              </div>
            )}
          </Show>
        </div>
      </Modal>

      <ReAuthPrompt
        open={showReAuth()}
        onClose={() => setShowReAuth(false)}
        onVerified={handleVerified}
      />
    </>
  );
};
