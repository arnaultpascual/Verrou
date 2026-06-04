/**
 * RecoveryCodeDetailModal — detail view for recovery code entries.
 *
 * Shows entry metadata (name, issuer, code count, created date) with
 * masked codes and a "Reveal" button requiring re-authentication (AC8).
 * Uses the shared reveal grammar (`useReveal` + `AutoHideCountdown`): one
 * re-auth gate, the unified 60s auto-hide, clear-on-lock, clear-on-cleanup.
 * Supports marking codes as used/unused with toggle checkboxes (Story 6.5).
 *
 * The reveal payload from `useReveal` is read-only, but the used/unused toggle
 * mutates the code list in place. We therefore keep a THIN local signal seeded
 * from the revealed data (via the hook's `onReveal` callback) and update it from
 * `toggleRecoveryCodeUsed`. The toggle reuses the retained session password and
 * does NOT restart the countdown (the countdown only starts inside the hook's
 * `onVerified`). Deletion has its OWN re-auth prompt — `useReveal` governs the
 * reveal gate only, never delete.
 */

import type { Component } from "solid-js";
import { Show, For, createSignal, createMemo } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { AutoHideCountdown } from "../../components/AutoHideCountdown";
import { useToast } from "../../components/useToast";
import { Icon } from "../../components/Icon";
import { revealRecoveryCodes, toggleRecoveryCodeUsed, deleteRecoveryCodeEntry } from "./ipc";
import type { RecoveryCodeDisplay } from "./ipc";
import { useReveal } from "../entries/useReveal";
import { AttachmentsSection } from "../attachments/AttachmentsSection";
import { t } from "../../stores/i18nStore";
import styles from "./RecoveryCodeDetailModal.module.css";

/** Derive alert severity from remaining code count. */
function getAlertSeverity(remaining: number): "none" | "warning" | "danger" {
  if (remaining === 0) return "danger";
  if (remaining <= 2) return "warning";
  return "none";
}

export interface RecoveryCodeDetailModalProps {
  open: boolean;
  onClose: () => void;
  entryId: string;
  name: string;
  issuer?: string;
  createdAt: string;
  onDeleted?: () => void;
  onStatsChanged?: () => void;
  onEdit?: (entryId: string) => void;
}

export const RecoveryCodeDetailModal: Component<RecoveryCodeDetailModalProps> = (props) => {
  const toast = useToast();

  // Mutable copy of the revealed codes. The reveal payload from `useReveal` is
  // read-only, so the used/unused toggle drives this thin local signal instead.
  // Seeded on reveal via `onReveal`, cleared on hide so it never outlives the
  // revealed gate.
  const [localCodes, setLocalCodes] = createSignal<RecoveryCodeDisplay | null>(null);
  const [deleteReAuth, setDeleteReAuth] = createSignal(false);
  const [toggling, setToggling] = createSignal<number | null>(null);

  // Shared reveal grammar: re-auth gate, unified 60s auto-hide, clear-on-lock,
  // clear-on-cleanup. The recovery codes are never copied across IPC except as
  // the display-safe list returned by revealRecoveryCodes.
  const reveal = useReveal<RecoveryCodeDisplay>({
    revealFn: (password) => revealRecoveryCodes(props.entryId, password),
    onReveal: (data) => setLocalCodes(data),
    onHide: () => {
      setLocalCodes(null);
      setToggling(null);
    },
  });

  // Sorted code indexes: unused first, then used (stable original order within each group)
  const sortedIndexes = createMemo(() => {
    const data = localCodes();
    if (!data) return [];
    const usedSet = new Set(data.used);
    const indexes = data.codes.map((_, i) => i);
    const unused = indexes.filter((i) => !usedSet.has(i));
    const used = indexes.filter((i) => usedSet.has(i));
    return [...unused, ...used];
  });

  const handleClose = () => {
    // Clear any revealed secret + close both re-auth prompts before closing.
    reveal.hide();
    reveal.cancelReAuth();
    setDeleteReAuth(false);
    props.onClose();
  };

  const handleDeleteRequest = () => {
    setDeleteReAuth(true);
  };

  const handleDeleteVerified = async (password: string) => {
    // Throws on wrong password — ReAuthPrompt shows the error inline.
    await deleteRecoveryCodeEntry(props.entryId, password);
    setDeleteReAuth(false);
    toast.success(t("recovery.detail.deleted"));
    props.onDeleted?.();
  };

  const handleToggle = async (codeIndex: number) => {
    // Reuse the password retained by the active reveal session. Does NOT restart
    // the auto-hide countdown — that only starts inside the hook's onVerified.
    const pw = reveal.sessionPassword();
    if (!pw || toggling() !== null) return;

    setToggling(codeIndex);
    try {
      const updated = await toggleRecoveryCodeUsed(props.entryId, codeIndex, pw);
      const isNowUsed = updated.used.includes(codeIndex);
      setLocalCodes(updated);
      toast.success(isNowUsed ? t("recovery.detail.markedUsed") : t("recovery.detail.unmarked"));
      props.onStatsChanged?.();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("recovery.detail.toggleError");
      toast.error(msg);
    } finally {
      setToggling(null);
    }
  };

  const formatDate = (iso: string) => {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return iso;
    }
  };

  return (
    <>
      <Modal
        open={props.open}
        onClose={handleClose}
        title={t("recovery.detail.title")}
        closeOnOverlayClick={false}
        actions={
          <>
            <Show when={props.onEdit}>
              <Button
                variant="ghost"
                onClick={() => props.onEdit?.(props.entryId)}
                class={styles.editBtn}
              >
                <Icon name="edit" size={16} />
                {t("recovery.detail.edit")}
              </Button>
            </Show>
            <Button
              variant="danger"
              onClick={handleDeleteRequest}
            >
              {t("recovery.detail.delete")}
            </Button>
            <Button variant="ghost" onClick={handleClose}>
              {t("recovery.detail.close")}
            </Button>
          </>
        }
      >
        <div class={styles.container}>
          {/* Metadata section */}
          <div class={styles.metadata}>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("recovery.detail.serviceLabel")}</span>
              <span class={styles.metaValue}>{props.name}</span>
            </div>
            <Show when={props.issuer}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("recovery.detail.issuerLabel")}</span>
                <span class={styles.metaValue}>{props.issuer}</span>
              </div>
            </Show>
            <Show when={localCodes()}>
              {(data) => (
                <div class={styles.metaRow}>
                  <span class={styles.metaLabel}>{t("recovery.detail.codesLabel")}</span>
                  <span class={styles.metaValue}>
                    <span class={styles.codeCount}>
                      {data().remainingCodes}/{data().totalCodes}
                    </span>
                    {t("recovery.detail.remaining")}
                  </span>
                </div>
              )}
            </Show>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("recovery.detail.addedLabel")}</span>
              <span class={styles.metaValue}>{formatDate(props.createdAt)}</span>
            </div>
          </div>

          <hr class={styles.separator} />

          {/* Code viewer — gate visibility on the reveal grammar, render from the
              thin local signal that the toggle mutates. */}
          <Show
            when={reveal.revealed()}
            fallback={
              <div class={styles.maskedContainer}>
                <div class={styles.maskedCodes}>
                  <Icon name="lock" size={24} />
                  <span>{t("recovery.detail.codesHidden")}</span>
                </div>
                <Button variant="primary" onClick={reveal.request}>
                  <Icon name="eye" size={16} />
                  {t("recovery.detail.reveal")}
                </Button>
              </div>
            }
          >
            <Show when={localCodes()}>
              {(data) => {
                const severity = () => getAlertSeverity(data().remainingCodes);
                return (
                  <div class={styles.revealedContainer}>
                    {/* Alert banner */}
                    <Show when={severity() !== "none"}>
                      <div
                        class={`${styles.alertBanner} ${severity() === "danger" ? styles.alertDanger : styles.alertWarning}`}
                        role="alert"
                      >
                        <Icon name="alert-triangle" size={16} />
                        <span>
                          {severity() === "danger"
                            ? t("recovery.detail.alertDanger", { name: props.name })
                            : t("recovery.detail.alertWarning", { name: props.name })}
                        </span>
                      </div>
                    </Show>

                    <AutoHideCountdown
                      remainingMs={reveal.remainingMs()}
                      onHide={reveal.hide}
                    />
                    <ul class={styles.codeList}>
                      <For each={sortedIndexes()}>
                        {(codeIdx) => {
                          const isUsed = () => data().used.includes(codeIdx);
                          const anyToggling = () => toggling() !== null;
                          return (
                            <li
                              class={`${styles.codeItem} ${isUsed() ? styles.codeUsed : ""}`}
                            >
                              <input
                                type="checkbox"
                                class={styles.codeCheckbox}
                                checked={isUsed()}
                                disabled={anyToggling()}
                                aria-label={t("recovery.detail.toggleCodeAria", { n: codeIdx + 1, status: isUsed() ? t("recovery.detail.unused") : t("recovery.detail.used") })}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleToggle(codeIdx);
                                }}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter" || e.key === " ") {
                                    e.stopPropagation();
                                  }
                                }}
                              />
                              <span class={styles.codeText}>{data().codes[codeIdx]}</span>
                              <Show when={isUsed()}>
                                <span class={styles.usedBadge}>{t("recovery.detail.used")}</span>
                              </Show>
                            </li>
                          );
                        }}
                      </For>
                    </ul>
                    <div class={styles.revealedActions}>
                      <Button variant="ghost" onClick={reveal.hide}>
                        <Icon name="eye-off" size={16} />
                        {t("recovery.detail.hide")}
                      </Button>
                    </div>
                  </div>
                );
              }}
            </Show>
          </Show>
          <AttachmentsSection entryId={props.entryId} />
        </div>
      </Modal>

      {/* Reveal re-auth (governed by useReveal) */}
      <ReAuthPrompt
        open={reveal.showReAuth()}
        onClose={reveal.cancelReAuth}
        onVerified={reveal.onVerified}
      />

      {/* Delete re-auth (separate gate — not governed by useReveal) */}
      <ReAuthPrompt
        open={deleteReAuth()}
        onClose={() => setDeleteReAuth(false)}
        onVerified={handleDeleteVerified}
      />
    </>
  );
};
