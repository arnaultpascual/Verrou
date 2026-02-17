/**
 * RecoveryCodeDetailModal — detail view for recovery code entries.
 *
 * Shows entry metadata (name, issuer, code count, created date) with
 * masked codes and a "Reveal" button requiring re-authentication (AC8).
 * Includes 60s auto-hide countdown matching the SeedViewer pattern.
 * Supports marking codes as used/unused with toggle checkboxes (Story 6.5).
 */

import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, on, onCleanup, onMount, createMemo } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { useToast } from "../../components/useToast";
import { Icon } from "../../components/Icon";
import { revealRecoveryCodes, toggleRecoveryCodeUsed, deleteRecoveryCodeEntry } from "./ipc";
import type { RecoveryCodeDisplay } from "./ipc";
import { AttachmentsSection } from "../attachments/AttachmentsSection";
import { t } from "../../stores/i18nStore";
import styles from "./RecoveryCodeDetailModal.module.css";

const AUTO_HIDE_SECONDS = 60;

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
  const [revealedData, setRevealedData] = createSignal<RecoveryCodeDisplay | null>(null);
  const [showReAuth, setShowReAuth] = createSignal(false);
  const [deleteReAuth, setDeleteReAuth] = createSignal(false);
  const [remaining, setRemaining] = createSignal(AUTO_HIDE_SECONDS);
  const [sessionPassword, setSessionPassword] = createSignal<string | null>(null);
  const [toggling, setToggling] = createSignal<number | null>(null);
  let timerHandle: ReturnType<typeof setInterval> | undefined;

  // Sorted code indexes: unused first, then used (stable original order within each group)
  const sortedIndexes = createMemo(() => {
    const data = revealedData();
    if (!data) return [];
    const usedSet = new Set(data.used);
    const indexes = data.codes.map((_, i) => i);
    const unused = indexes.filter((i) => !usedSet.has(i));
    const used = indexes.filter((i) => usedSet.has(i));
    return [...unused, ...used];
  });

  // Start countdown only on reveal (null → data), not on toggle updates within revealed state
  let wasRevealed = false;
  createEffect(on(() => revealedData(), (data) => {
    if (data && !wasRevealed) {
      // Fresh reveal: start countdown
      wasRevealed = true;
      clearCountdown();
      setRemaining(AUTO_HIDE_SECONDS);
      timerHandle = setInterval(() => {
        setRemaining((prev) => {
          const next = prev - 1;
          if (next <= 0) {
            clearCountdown();
            handleHide();
            return 0;
          }
          return next;
        });
      }, 1000);
    } else if (!data) {
      // Hidden: reset state
      wasRevealed = false;
      clearCountdown();
    }
  }));

  // Listen for vault-locked event
  onMount(async () => {
    try {
      const IS_TAURI = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
      if (IS_TAURI) {
        const { listen } = await import("@tauri-apps/api/event");
        const unlisten = await listen("verrou://vault-locked", () => {
          handleHide();
        });
        onCleanup(unlisten);
      }
    } catch {
      // Non-Tauri environment
    }
  });

  onCleanup(() => {
    clearCountdown();
    clearSessionPassword();
  });

  const clearCountdown = () => {
    if (timerHandle !== undefined) {
      clearInterval(timerHandle);
      timerHandle = undefined;
    }
  };

  const clearSessionPassword = () => {
    setSessionPassword(null);
  };

  const handleRevealRequest = () => {
    setShowReAuth(true);
  };

  const handleVerified = async (password: string) => {
    setShowReAuth(false);
    try {
      const data = await revealRecoveryCodes(props.entryId, password);
      setRevealedData(data);
      setSessionPassword(password);
    } catch (err) {
      const msg = typeof err === "string" ? err : t("recovery.detail.revealError");
      toast.error(msg);
    }
  };

  const handleHide = () => {
    clearCountdown();
    setRevealedData(null);
    clearSessionPassword();
  };

  const handleClose = () => {
    clearCountdown();
    setRevealedData(null);
    clearSessionPassword();
    setShowReAuth(false);
    setDeleteReAuth(false);
    props.onClose();
  };

  const handleDeleteRequest = () => {
    setDeleteReAuth(true);
  };

  const handleDeleteVerified = async (password: string) => {
    setDeleteReAuth(false);
    try {
      await deleteRecoveryCodeEntry(props.entryId, password);
      toast.success(t("recovery.detail.deleted"));
      props.onDeleted?.();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("recovery.detail.deleteError");
      toast.error(msg);
    }
  };

  const handleToggle = async (codeIndex: number) => {
    const pw = sessionPassword();
    if (!pw || toggling() !== null) return;

    setToggling(codeIndex);
    try {
      const updated = await toggleRecoveryCodeUsed(props.entryId, codeIndex, pw);
      const isNowUsed = updated.used.includes(codeIndex);
      setRevealedData(updated);
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
            <Show when={revealedData()}>
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

          {/* Code viewer */}
          <Show
            when={revealedData()}
            fallback={
              <div class={styles.maskedContainer}>
                <div class={styles.maskedCodes}>
                  <Icon name="lock" size={24} />
                  <span>{t("recovery.detail.codesHidden")}</span>
                </div>
                <Button variant="primary" onClick={handleRevealRequest}>
                  <Icon name="eye" size={16} />
                  {t("recovery.detail.reveal")}
                </Button>
              </div>
            }
          >
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

                  <div class={styles.timerBar}>
                    <Icon name="clock" size={14} />
                    <span>{t("recovery.detail.hidingIn", { seconds: remaining() })}</span>
                  </div>
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
                    <Button variant="ghost" onClick={handleHide}>
                      <Icon name="eye-off" size={16} />
                      {t("recovery.detail.hide")}
                    </Button>
                  </div>
                </div>
              );
            }}
          </Show>
          <AttachmentsSection entryId={props.entryId} />
        </div>
      </Modal>

      <ReAuthPrompt
        open={showReAuth()}
        onClose={() => setShowReAuth(false)}
        onVerified={handleVerified}
      />

      <ReAuthPrompt
        open={deleteReAuth()}
        onClose={() => setDeleteReAuth(false)}
        onVerified={handleDeleteVerified}
      />
    </>
  );
};
