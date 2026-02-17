import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, on, onCleanup, createResource } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { revealPassword, copyToClipboard, generateTotpCode } from "../entries/ipc";
import type { CredentialDisplay, TotpCodeDto } from "../entries/ipc";
import { listFolders } from "../folders/ipc";
import { getTemplateById } from "./templates";
import { AttachmentsSection } from "../attachments/AttachmentsSection";
import { t } from "../../stores/i18nStore";
import styles from "./CredentialDetailModal.module.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CredentialDetailModalProps {
  open: boolean;
  onClose: () => void;
  entryId: string;
  name: string;
  issuer?: string;
  tags?: string[];
  folderId?: string;
  createdAt: string;
  onEdit?: (entryId: string) => void;
  onDeleted?: () => void;
}

const AUTO_HIDE_SECONDS = 30;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

function formatTotpCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export const CredentialDetailModal: Component<CredentialDetailModalProps> = (props) => {
  const toast = useToast();
  const [revealedData, setRevealedData] = createSignal<CredentialDisplay | null>(null);
  const [showReAuth, setShowReAuth] = createSignal(false);
  const [remaining, setRemaining] = createSignal(AUTO_HIDE_SECONDS);
  const [historyVisible, setHistoryVisible] = createStore<Record<number, boolean>>({});
  const [customFieldVisible, setCustomFieldVisible] = createStore<Record<number, boolean>>({});
  const [totpCode, setTotpCode] = createSignal<TotpCodeDto | null>(null);

  const [folders] = createResource(listFolders);
  const folderName = () => {
    if (!props.folderId) return undefined;
    const all = folders() ?? [];
    return all.find((f) => f.id === props.folderId)?.name;
  };

  let timerHandle: ReturnType<typeof setInterval> | undefined;
  let totpHandle: ReturnType<typeof setInterval> | undefined;

  // ── Reset on open ──

  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          setRevealedData(null);
          setShowReAuth(false);
          setRemaining(AUTO_HIDE_SECONDS);
          setHistoryVisible({});
          setCustomFieldVisible({});
          setTotpCode(null);
          if (timerHandle) clearInterval(timerHandle);
          if (totpHandle) clearInterval(totpHandle);
        }
      },
    ),
  );

  onCleanup(() => {
    if (timerHandle) clearInterval(timerHandle);
    if (totpHandle) clearInterval(totpHandle);
  });

  // ── Auto-hide timer ──

  const startAutoHide = () => {
    setRemaining(AUTO_HIDE_SECONDS);
    if (timerHandle) clearInterval(timerHandle);
    timerHandle = setInterval(() => {
      setRemaining((prev) => {
        if (prev <= 1) {
          clearInterval(timerHandle);
          timerHandle = undefined;
          setRevealedData(null);
          setHistoryVisible({});
          setCustomFieldVisible({});
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  };

  // ── Linked TOTP polling ──

  const startTotpPolling = (linkedTotpId: string) => {
    const fetchCode = async () => {
      try {
        const code = await generateTotpCode(linkedTotpId);
        setTotpCode(code);
      } catch {
        // Linked entry may have been deleted — silently ignore
      }
    };
    fetchCode();
    if (totpHandle) clearInterval(totpHandle);
    totpHandle = setInterval(fetchCode, 1000);
  };

  // ── Reveal flow ──

  const handleRevealRequest = () => {
    setShowReAuth(true);
  };

  const handleVerified = async (password: string) => {
    setShowReAuth(false);
    try {
      const data = await revealPassword(props.entryId, password);
      setRevealedData(data);
      startAutoHide();
      // Start TOTP polling if linked
      if (data.linkedTotpId) {
        startTotpPolling(data.linkedTotpId);
      }
    } catch (err) {
      const msg = typeof err === "string" ? err : t("credentials.detail.revealError");
      toast.error(msg);
    }
  };

  const handleHide = () => {
    if (timerHandle) clearInterval(timerHandle);
    timerHandle = undefined;
    if (totpHandle) clearInterval(totpHandle);
    totpHandle = undefined;
    setRevealedData(null);
    setHistoryVisible({});
    setCustomFieldVisible({});
    setTotpCode(null);
  };

  // ── Copy handlers ──

  const handleCopyUsername = async () => {
    const data = revealedData();
    if (data?.username) {
      await copyToClipboard(data.username);
      toast.success(t("credentials.detail.usernameCopied"));
    }
  };

  const handleCopyPassword = async () => {
    const data = revealedData();
    if (data?.password) {
      await copyToClipboard(data.password);
      toast.success(t("credentials.detail.passwordCopied"));
    }
  };

  const handleCopyHistory = async (password: string, dateStr: string) => {
    await copyToClipboard(password);
    toast.success(t("credentials.detail.historyCopied", { date: formatDate(dateStr) }));
  };

  const handleCopyTotp = async () => {
    const code = totpCode();
    if (code) {
      await copyToClipboard(code.code);
      toast.success(t("credentials.detail.totpCopied"));
    }
  };

  // ── Close ──

  const handleClose = () => {
    if (timerHandle) clearInterval(timerHandle);
    if (totpHandle) clearInterval(totpHandle);
    timerHandle = undefined;
    totpHandle = undefined;
    setRevealedData(null);
    setShowReAuth(false);
    setHistoryVisible({});
    setCustomFieldVisible({});
    setTotpCode(null);
    props.onClose();
  };

  // ── Render ──

  return (
    <>
      <Modal
        open={props.open}
        onClose={handleClose}
        title={t("credentials.detail.title")}
        closeOnOverlayClick={false}
        actions={
          <>
            <Show when={props.onDeleted}>
              <Button
                variant="danger"
                onClick={() => props.onDeleted?.()}
                class={styles.deleteBtn}
                data-testid="credential-detail-delete-btn"
              >
                {t("credentials.detail.delete")}
              </Button>
            </Show>
            <Show when={props.onEdit}>
              <Button
                variant="ghost"
                onClick={() => props.onEdit?.(props.entryId)}
                data-testid="credential-detail-edit-btn"
              >
                <Icon name="edit" size={14} />
                {t("credentials.detail.edit")}
              </Button>
            </Show>
            <Button variant="ghost" onClick={handleClose}>
              {t("credentials.detail.close")}
            </Button>
          </>
        }
      >
        <div class={styles.container}>
          {/* ── Metadata ── */}
          <div class={styles.metadata}>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("credentials.detail.nameLabel")}</span>
              <span class={styles.metaValue} data-testid="credential-detail-name">
                {props.name}
              </span>
            </div>
            <Show when={props.issuer}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("credentials.detail.issuerLabel")}</span>
                <span class={styles.metaValue} data-testid="credential-detail-issuer">
                  {props.issuer}
                </span>
              </div>
            </Show>
            <div class={styles.metaRow}>
              <span class={styles.metaLabel}>{t("credentials.detail.addedLabel")}</span>
              <span class={styles.metaValue}>{formatDate(props.createdAt)}</span>
            </div>
            <Show when={revealedData()?.template}>
              {(templateId) => {
                const tmpl = () => getTemplateById(templateId());
                return (
                  <Show when={tmpl()}>
                    {(tmplData) => (
                      <div class={styles.metaRow}>
                        <span class={styles.metaLabel}>{t("credentials.detail.templateLabel")}</span>
                        <span class={styles.metaValue}>
                          <Icon name={tmplData().icon} size={14} /> {tmplData().name}
                        </span>
                      </div>
                    )}
                  </Show>
                );
              }}
            </Show>
            <Show when={folderName()}>
              <div class={styles.metaRow}>
                <span class={styles.metaLabel}>{t("credentials.detail.folderLabel")}</span>
                <span class={styles.metaValue} data-testid="credential-detail-folder">
                  {folderName()}
                </span>
              </div>
            </Show>
          </div>

          {/* ── Tags ── */}
          <Show when={props.tags && props.tags.length > 0}>
            <div class={styles.tagList} data-testid="credential-detail-tags">
              <For each={props.tags}>
                {(tag) => <span class={styles.tag}>{tag}</span>}
              </For>
            </div>
          </Show>

          <hr class={styles.separator} />

          {/* ── Password Section ── */}
          <div>
            <span class={styles.sectionLabel}>{t("credentials.detail.password")}</span>
            <div class={styles.secretRow}>
              <Show
                when={revealedData()}
                fallback={
                  <>
                    <span class={`${styles.secretValue} ${styles.masked}`}>{"••••••••"}</span>
                    <button
                      type="button"
                      class={styles.revealBtn}
                      onClick={handleRevealRequest}
                      aria-label={t("credentials.detail.revealAria")}
                      data-testid="credential-reveal-btn"
                    >
                      <Icon name="eye" size={14} />
                      {t("credentials.detail.reveal")}
                    </button>
                  </>
                }
              >
                <span class={styles.secretValue} data-testid="credential-password-revealed">
                  {revealedData()!.password}
                </span>
                <button
                  type="button"
                  class={styles.copyBtn}
                  onClick={(e) => { e.stopPropagation(); handleCopyPassword(); }}
                  aria-label={t("credentials.detail.copyPasswordAria")}
                  data-testid="credential-copy-password-btn"
                >
                  <Icon name="copy" size={14} />
                </button>
                <button
                  type="button"
                  class={styles.revealBtn}
                  onClick={handleHide}
                  aria-label={t("credentials.detail.hideAria")}
                  data-testid="credential-hide-btn"
                >
                  <Icon name="eye-off" size={14} />
                  {t("credentials.detail.hide")}
                </button>
              </Show>
            </div>
            <Show when={revealedData()}>
              <div class={styles.timer} aria-live="polite">
                <Icon name="clock" size={12} />
                <span>{t("credentials.detail.hidingIn", { seconds: remaining() })}</span>
              </div>
            </Show>
          </div>

          {/* ── Username Section ── */}
          <Show when={revealedData()?.username}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.username")}</span>
              <div class={styles.secretRow}>
                <span class={styles.secretValue} data-testid="credential-username">
                  {revealedData()!.username}
                </span>
                <button
                  type="button"
                  class={styles.copyBtn}
                  onClick={(e) => { e.stopPropagation(); handleCopyUsername(); }}
                  aria-label={t("credentials.detail.copyUsernameAria")}
                  data-testid="credential-copy-username-btn"
                >
                  <Icon name="copy" size={14} />
                </button>
              </div>
            </div>
          </Show>

          {/* ── URLs Section ── */}
          <Show when={revealedData()?.urls && revealedData()!.urls.length > 0}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.urls")}</span>
              <div class={styles.urlList}>
                <For each={revealedData()!.urls}>
                  {(url) => (
                    <span class={styles.urlItem} data-testid="credential-url">
                      {url}
                    </span>
                  )}
                </For>
              </div>
            </div>
          </Show>

          {/* ── Linked TOTP ── */}
          <Show when={revealedData()?.linkedTotpId && totpCode()}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.linkedTotp")}</span>
              <div class={styles.totpInline}>
                <button
                  type="button"
                  class={styles.totpCode}
                  onClick={(e) => { e.stopPropagation(); handleCopyTotp(); }}
                  aria-label={t("credentials.detail.copyTotpAria")}
                  data-testid="credential-totp-code"
                >
                  {formatTotpCode(totpCode()!.code)}
                </button>
                <span class={styles.totpCountdown} data-testid="credential-totp-countdown">
                  {totpCode()!.remainingSeconds}s
                </span>
              </div>
            </div>
          </Show>

          {/* ── Notes Section ── */}
          <Show when={revealedData()?.notes}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.notes")}</span>
              <p class={styles.notesContent} data-testid="credential-notes">
                {revealedData()!.notes}
              </p>
            </div>
          </Show>

          {/* ── Custom Fields Section ── */}
          <Show when={revealedData()?.customFields && revealedData()!.customFields.length > 0}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.customFields")}</span>
              <div class={styles.metadata}>
                <For each={revealedData()!.customFields}>
                  {(field, index) => (
                    <div class={styles.customFieldRow}>
                      <span class={styles.customFieldLabel}>{field.label}</span>
                      <div class={styles.customFieldValue}>
                        <Show
                          when={field.fieldType !== "hidden" || customFieldVisible[index()]}
                          fallback={<span class={styles.masked}>{"••••••••"}</span>}
                        >
                          <span>{field.value}</span>
                        </Show>
                        <Show when={field.fieldType === "hidden"}>
                          <button
                            type="button"
                            class={styles.hiddenToggleBtn}
                            onClick={(e) => {
                              e.stopPropagation();
                              setCustomFieldVisible(index(), !customFieldVisible[index()]);
                            }}
                            aria-label={
                              customFieldVisible[index()]
                                ? t("credentials.detail.hideFieldAria", { name: field.label })
                                : t("credentials.detail.showFieldAria", { name: field.label })
                            }
                          >
                            <Icon
                              name={customFieldVisible[index()] ? "eye-off" : "eye"}
                              size={14}
                            />
                          </button>
                        </Show>
                        <button
                          type="button"
                          class={styles.copyBtn}
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(field.value);
                            toast.success(t("credentials.detail.fieldCopied", { name: field.label }));
                          }}
                          aria-label={t("credentials.detail.copyFieldAria", { name: field.label })}
                        >
                          <Icon name="copy" size={14} />
                        </button>
                      </div>
                    </div>
                  )}
                </For>
              </div>
            </div>
          </Show>

          <hr class={styles.separator} />

          {/* ── Password History Section ── */}
          <Show when={revealedData()?.passwordHistory && revealedData()!.passwordHistory.length > 0}>
            <div class={styles.historySection}>
              <span class={styles.sectionLabel}>
                {t("credentials.detail.passwordHistory", { count: revealedData()!.passwordHistory.length })}
              </span>
              <For each={revealedData()!.passwordHistory}>
                {(entry, index) => (
                  <div class={styles.historyRow} data-testid="credential-history-row">
                    <span class={styles.historyDate}>{formatDate(entry.changedAt)}</span>
                    <span class={styles.historyPassword}>
                      {historyVisible[index()] ? entry.password : "••••••••"}
                    </span>
                    <button
                      type="button"
                      class={styles.historyToggle}
                      onClick={(e) => {
                        e.stopPropagation();
                        setHistoryVisible(index(), !historyVisible[index()]);
                      }}
                      aria-label={
                        historyVisible[index()]
                          ? t("credentials.detail.hideHistoryAria", { date: formatDate(entry.changedAt) })
                          : t("credentials.detail.showHistoryAria", { date: formatDate(entry.changedAt) })
                      }
                    >
                      <Icon name={historyVisible[index()] ? "eye-off" : "eye"} size={14} />
                    </button>
                    <button
                      type="button"
                      class={styles.historyCopy}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopyHistory(entry.password, entry.changedAt);
                      }}
                      aria-label={t("credentials.detail.copyHistoryAria", { date: formatDate(entry.changedAt) })}
                    >
                      <Icon name="copy" size={14} />
                    </button>
                  </div>
                )}
              </For>
            </div>
          </Show>

          {/* ── Attachments Section ── */}
          <AttachmentsSection entryId={props.entryId} />
        </div>
      </Modal>

      {/* Re-auth modal (stacks on top of detail modal) */}
      <ReAuthPrompt
        open={showReAuth()}
        onClose={() => setShowReAuth(false)}
        onVerified={handleVerified}
      />
    </>
  );
};
