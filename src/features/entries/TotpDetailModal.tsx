/**
 * TotpDetailModal — calm, READ-ONLY detail view for `totp` / `hotp` entries.
 *
 * Mirrors the other entry-type detail modals (seed / recovery / credential):
 * a card click opens this view, and Edit / Export / Delete are reached from the
 * footer — never directly. Crypto parameters (algorithm, digits, period) are
 * shown here as read-only metadata; they can only be changed via Edit.
 *
 * For `totp` it shows the live code (reusing `useTotpCode` + `CountdownRing`),
 * which copies to the concealed, auto-clearing clipboard on click via
 * `useCopyOtp` (the unified "{name} copied · clears in {n}s" toast).
 *
 * For `hotp` (counter-based, RFC 4226) there is no time window or countdown, so
 * instead of a live code it shows a "Generate next code" action. Generating
 * computes the next code from the stored counter, advances + persists it, copies
 * the code to the concealed clipboard (same unified toast), and shows the code
 * plus the new counter value.
 */

import type { Component } from "solid-js";
import { Show, createSignal } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { CountdownRing } from "./CountdownRing";
import { formatTotpCode } from "./formatCode";
import { useTotpCode } from "./useTotpCode";
import { useCopyOtp } from "./useCopyOtp";
import { useToast } from "../../components/useToast";
import { generateHotpCode, copyToClipboard } from "./ipc";
import { clipboardAutoClearMs } from "../../stores/preferencesStore";
import { t, formatDate } from "../../stores/i18nStore";
import styles from "./TotpDetailModal.module.css";

export interface TotpDetailModalProps {
  /** Controlled open state. */
  open: boolean;
  /** Called when the dialog should close. */
  onClose: () => void;
  /** Entry ID of the TOTP/HOTP entry. */
  entryId: string;
  /** Entry type — "totp" or "hotp". */
  entryType: string;
  /** Account / display name. */
  name: string;
  /** Issuer (optional). */
  issuer?: string;
  /** OTP algorithm (e.g. "SHA1"). */
  algorithm: string;
  /** Number of code digits (6 or 8). */
  digits: number;
  /** Time-step period in seconds. */
  period: number;
  /** ISO 8601 creation timestamp. */
  createdAt: string;
  /** Open the existing EditEntryModal for this entry. */
  onEdit: (entryId: string) => void;
  /** Open the existing ExportUriModal for this entry. */
  onExport: (entryId: string) => void;
  /** Request deletion (routes to ConfirmDeleteModal). */
  onDelete: (entryId: string, entryName: string) => void;
}

/** Placeholder for the code zone while the first live code is loading. */
function placeholder(digits: number): string {
  return digits === 8 ? "---- ----" : "--- ---";
}

/**
 * Live, copyable TOTP code block. Internal so the reactive `useTotpCode` /
 * `useCopyOtp` hooks only run while a `totp` entry is shown.
 */
const TotpLiveCode: Component<{
  entryId: string;
  name: string;
  digits: number;
  period: number;
}> = (props) => {
  const totp = useTotpCode(props.entryId, props.period);
  const { copyCode } = useCopyOtp(props.entryId, props.name, props.period);

  const handleClick = () => {
    void copyCode();
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      void copyCode();
    }
  };

  return (
    <div
      class={styles.codeZone}
      role="button"
      tabindex={0}
      title={t("entries.totpDetail.copyHint")}
      aria-label={t("entries.totpDetail.copyHint")}
      data-testid="totp-detail-copy"
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <span class={styles.code} aria-live="polite" data-testid="totp-detail-code">
        <Show when={totp.code()} fallback={placeholder(props.digits)}>
          {formatTotpCode(totp.code(), props.digits)}
        </Show>
      </span>
      <CountdownRing remaining={totp.remainingSeconds()} period={props.period} />
    </div>
  );
};

/**
 * HOTP "Generate next code" block. Counter-based, so no countdown: the user
 * explicitly requests the next code, which advances + persists the counter and
 * copies the code to the concealed, auto-clearing clipboard.
 */
const HotpGenerate: Component<{
  entryId: string;
  name: string;
  digits: number;
}> = (props) => {
  const toast = useToast();
  const [code, setCode] = createSignal("");
  const [counter, setCounter] = createSignal<number | null>(null);
  const [isGenerating, setIsGenerating] = createSignal(false);

  const generate = async () => {
    if (isGenerating()) return;
    setIsGenerating(true);
    try {
      const result = await generateHotpCode(props.entryId);
      setCode(result.code);
      setCounter(result.counter + 1);
      await copyToClipboard(result.code);
      const seconds = Math.round(clipboardAutoClearMs() / 1000);
      toast.success(t("reveal.copied", { label: props.name, seconds: String(seconds) }));
    } catch {
      toast.error(t("reveal.copyFailed", { label: props.name }));
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div class={styles.hotpZone} data-testid="totp-detail-hotp">
      <Show
        when={code()}
        fallback={
          <Button
            variant="primary"
            onClick={() => void generate()}
            loading={isGenerating()}
            data-testid="totp-detail-hotp-generate"
          >
            <Icon name="refresh" size={16} />
            {t("entries.totpDetail.generateHotp")}
          </Button>
        }
      >
        <button
          class={styles.hotpCodeButton}
          type="button"
          title={t("entries.totpDetail.copyHint")}
          aria-label={t("entries.totpDetail.copyHint")}
          data-testid="totp-detail-hotp-copy"
          onClick={() => void generate()}
        >
          <span class={styles.code} aria-live="polite" data-testid="totp-detail-hotp-code">
            {formatTotpCode(code(), props.digits)}
          </span>
          <Icon name="refresh" size={16} />
        </button>
        <Show when={counter() !== null}>
          <span class={styles.hotpCounter} data-testid="totp-detail-hotp-counter">
            {t("entries.totpDetail.counterValue", { counter: String(counter()) })}
          </span>
        </Show>
      </Show>
    </div>
  );
};

export const TotpDetailModal: Component<TotpDetailModalProps> = (props) => {
  const isHotp = () => props.entryType === "hotp";

  return (
    <Modal
      open={props.open}
      onClose={props.onClose}
      title={t("entries.totpDetail.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button
            variant="danger"
            onClick={() => props.onDelete(props.entryId, props.name)}
            class={styles.deleteBtn}
            data-testid="totp-detail-delete-btn"
          >
            {t("entries.totpDetail.delete")}
          </Button>
          <Button
            variant="ghost"
            onClick={() => props.onExport(props.entryId)}
            data-testid="totp-detail-export-btn"
          >
            <Icon name="share" size={16} />
            {t("entries.totpDetail.export")}
          </Button>
          <Button
            variant="ghost"
            onClick={() => props.onEdit(props.entryId)}
            data-testid="totp-detail-edit-btn"
          >
            <Icon name="edit" size={16} />
            {t("entries.totpDetail.edit")}
          </Button>
          <Button variant="ghost" onClick={props.onClose}>
            {t("entries.totpDetail.close")}
          </Button>
        </>
      }
    >
      <div class={styles.container}>
        {/* Header: name + issuer */}
        <div class={styles.heading}>
          <span class={styles.name} data-testid="totp-detail-name">{props.name}</span>
          <Show when={props.issuer}>
            <span class={styles.issuer} data-testid="totp-detail-issuer">{props.issuer}</span>
          </Show>
        </div>

        {/* Live code (TOTP) or counter-based generate (HOTP) */}
        <Show
          when={!isHotp()}
          fallback={
            <HotpGenerate
              entryId={props.entryId}
              name={props.name}
              digits={props.digits}
            />
          }
        >
          <TotpLiveCode
            entryId={props.entryId}
            name={props.name}
            digits={props.digits}
            period={props.period}
          />
        </Show>

        <hr class={styles.separator} />

        {/* Read-only crypto metadata */}
        <div class={styles.metadata}>
          <div class={styles.metaRow}>
            <span class={styles.metaLabel}>{t("entries.totpDetail.algorithm")}</span>
            <span class={styles.metaValue} data-testid="totp-detail-algorithm">{props.algorithm}</span>
          </div>
          <div class={styles.metaRow}>
            <span class={styles.metaLabel}>{t("entries.totpDetail.digits")}</span>
            <span class={styles.metaValue} data-testid="totp-detail-digits">{props.digits}</span>
          </div>
          <div class={styles.metaRow}>
            <span class={styles.metaLabel}>{t("entries.totpDetail.period")}</span>
            <span class={styles.metaValue} data-testid="totp-detail-period">
              {t("entries.totpDetail.periodSeconds", { seconds: String(props.period) })}
            </span>
          </div>
          <div class={styles.metaRow}>
            <span class={styles.metaLabel}>{t("entries.totpDetail.added")}</span>
            <span class={styles.metaValue}>{formatDate(props.createdAt)}</span>
          </div>
        </div>
      </div>
    </Modal>
  );
};
