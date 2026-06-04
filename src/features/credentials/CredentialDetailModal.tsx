import type { Component } from "solid-js";
import { Show, For, createSignal, createEffect, on, createResource } from "solid-js";
import { createStore } from "solid-js/store";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { AutoHideCountdown } from "../../components/AutoHideCountdown";
import { Icon } from "../../components/Icon";
import { revealPassword, generateTotpCode } from "../entries/ipc";
import type { CredentialDisplay, TotpCodeDto } from "../entries/ipc";
import { useReveal } from "../entries/useReveal";
import { useRevealCopy } from "../entries/useRevealCopy";
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
  const copyReveal = useRevealCopy();

  // Per-field show/hide state lives locally — the reveal grammar owns the
  // password reveal + auto-hide, but these toggles are credential-specific.
  const [historyVisible, setHistoryVisible] = createStore<Record<number, boolean>>({});
  const [customFieldVisible, setCustomFieldVisible] = createStore<Record<number, boolean>>({});
  const [totpCode, setTotpCode] = createSignal<TotpCodeDto | null>(null);

  const [folders] = createResource(listFolders);
  const folderName = () => {
    if (!props.folderId) return undefined;
    const all = folders() ?? [];
    return all.find((f) => f.id === props.folderId)?.name;
  };

  // ── Linked TOTP polling ──
  // The polling interval handle stays LOCAL to the component; the reveal hook
  // only knows to start/stop it via onReveal/onHide.
  let totpHandle: ReturnType<typeof setInterval> | undefined;

  const startTotpPolling = (linkedTotpId: string) => {
    const fetchCode = async () => {
      try {
        const code = await generateTotpCode(linkedTotpId);
        setTotpCode(code);
      } catch {
        // Linked entry may have been deleted — silently ignore
      }
    };
    void fetchCode();
    if (totpHandle) clearInterval(totpHandle);
    totpHandle = setInterval(() => void fetchCode(), 1000);
  };

  const stopTotpPolling = () => {
    if (totpHandle) clearInterval(totpHandle);
    totpHandle = undefined;
  };

  // ── Shared reveal grammar ──
  // Re-auth gate, unified 60s auto-hide, clear-on-lock, clear-on-cleanup. The
  // password only appears after re-auth via revealPassword. On reveal we kick
  // off linked-TOTP polling; on hide we stop it and reset per-field visibility.
  const reveal = useReveal<CredentialDisplay>({
    revealFn: (password) => revealPassword(props.entryId, password),
    onReveal: (data) => {
      if (data.linkedTotpId) startTotpPolling(data.linkedTotpId);
    },
    onHide: () => {
      stopTotpPolling();
      setHistoryVisible({});
      setCustomFieldVisible({});
      setTotpCode(null);
    },
  });

  // ── Reset on open ──
  createEffect(
    on(
      () => props.open,
      (open) => {
        if (open) {
          reveal.hide();
          reveal.cancelReAuth();
          setHistoryVisible({});
          setCustomFieldVisible({});
        }
      },
    ),
  );

  // ── Copy handlers (unified reveal-copy grammar) ──

  const handleCopyUsername = () => {
    const data = reveal.revealed();
    if (data?.username) void copyReveal(data.username, t("credentials.detail.usernameLabel"));
  };

  const handleCopyPassword = () => {
    const data = reveal.revealed();
    if (data?.password) void copyReveal(data.password, t("credentials.detail.passwordLabel"));
  };

  const handleCopyHistory = (password: string) => {
    // A history entry is still a password; reuse the existing password label so
    // the unified copy toast reads "Password copied · clears in {n}s".
    void copyReveal(password, t("credentials.detail.passwordLabel"));
  };

  const handleCopyTotp = () => {
    const code = totpCode();
    if (code) void copyReveal(code.code, t("credentials.detail.linkedTotpLabel"));
  };

  // ── Close ──

  const handleClose = () => {
    // Clear any revealed secret + close the re-auth prompt before closing.
    reveal.hide();
    reveal.cancelReAuth();
    setHistoryVisible({});
    setCustomFieldVisible({});
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
            <Show when={reveal.revealed()?.template}>
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
                when={reveal.revealed()}
                fallback={
                  <>
                    <span class={`${styles.secretValue} ${styles.masked}`}>{"••••••••"}</span>
                    <button
                      type="button"
                      class={styles.revealBtn}
                      onClick={reveal.request}
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
                  {reveal.revealed()!.password}
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
                  onClick={reveal.hide}
                  aria-label={t("credentials.detail.hideAria")}
                  data-testid="credential-hide-btn"
                >
                  <Icon name="eye-off" size={14} />
                  {t("credentials.detail.hide")}
                </button>
              </Show>
            </div>
            <Show when={reveal.revealed()}>
              <AutoHideCountdown
                remainingMs={reveal.remainingMs()}
                onHide={reveal.hide}
              />
            </Show>
          </div>

          {/* ── Username Section ── */}
          <Show when={reveal.revealed()?.username}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.username")}</span>
              <div class={styles.secretRow}>
                <span class={styles.secretValue} data-testid="credential-username">
                  {reveal.revealed()!.username}
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
          <Show when={reveal.revealed()?.urls && reveal.revealed()!.urls.length > 0}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.urls")}</span>
              <div class={styles.urlList}>
                <For each={reveal.revealed()!.urls}>
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
          <Show when={reveal.revealed()?.linkedTotpId && totpCode()}>
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
          <Show when={reveal.revealed()?.notes}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.notes")}</span>
              <p class={styles.notesContent} data-testid="credential-notes">
                {reveal.revealed()!.notes}
              </p>
            </div>
          </Show>

          {/* ── Custom Fields Section ── */}
          <Show when={reveal.revealed()?.customFields && reveal.revealed()!.customFields.length > 0}>
            <div>
              <span class={styles.sectionLabel}>{t("credentials.detail.customFields")}</span>
              <div class={styles.metadata}>
                <For each={reveal.revealed()!.customFields}>
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
                            void copyReveal(field.value, field.label);
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
          <Show when={reveal.revealed()?.passwordHistory && reveal.revealed()!.passwordHistory.length > 0}>
            <div class={styles.historySection}>
              <span class={styles.sectionLabel}>
                {t("credentials.detail.passwordHistory", { count: reveal.revealed()!.passwordHistory.length })}
              </span>
              <For each={reveal.revealed()!.passwordHistory}>
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
                        handleCopyHistory(entry.password);
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
        open={reveal.showReAuth()}
        onClose={reveal.cancelReAuth}
        onVerified={reveal.onVerified}
      />
    </>
  );
};
