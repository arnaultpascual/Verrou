import type { Component } from "solid-js";
import { createSignal, Show, For, Switch, Match } from "solid-js";
import { Icon } from "../../components/Icon";
import { CountdownRing } from "./CountdownRing";
import { formatTotpCode } from "./formatCode";
import { TypeBadge } from "./TypeBadge";
import { useCopyOtp } from "./useCopyOtp";
import { useTotpCode } from "./useTotpCode";
import type { RecoveryStatsMap } from "../recovery/ipc";
import type { EntryMetadataDto } from "./ipc";
import { setSearchQuery } from "../../stores/searchStore";
import { t } from "../../stores/i18nStore";
import styles from "./EntryCard.module.css";

/** Must match --duration-normal in variables.css */
const HIGHLIGHT_DURATION_MS = 200;

export interface EntryCardProps {
  entry: EntryMetadataDto;
  onSelect?: (id: string) => void;
  onTogglePin?: (entryId: string, pinned: boolean) => void;
  recoveryStats?: RecoveryStatsMap;
}

/** Format placeholder code with digit grouping. */
function formatPlaceholder(digits: number): string {
  if (digits === 8) return "---- ----";
  return "--- ---";
}

/** Map entry type to i18n key for aria labels. */
const TYPE_LABEL_KEYS: Record<string, string> = {
  totp: "entries.type.totp",
  hotp: "entries.type.hotp",
  seed_phrase: "entries.type.seed",
  recovery_code: "entries.type.recovery",
  secure_note: "entries.type.note",
  credential: "entries.type.credential",
};

/** Build descriptive aria-label for the entry card. */
function buildAriaLabel(entry: EntryMetadataDto): string {
  const key = TYPE_LABEL_KEYS[entry.entryType];
  const typeLabel = key ? t(key) : entry.entryType;
  const parts = [entry.name, `${typeLabel} entry`];
  if (entry.pinned) parts.push(t("entries.card.pinned"));
  return parts.join(", ");
}

/** Internal component for live TOTP code display with copy-on-click. */
const TotpLiveCode: Component<{
  entryId: string;
  entryName: string;
  digits: number;
  period: number;
  onCopied?: () => void;
}> = (props) => {
  const totp = useTotpCode(props.entryId, props.period);
  const { copyCode } = useCopyOtp(props.entryId, props.entryName, props.period);

  const handleClick = (e: MouseEvent) => {
    e.stopPropagation();
    copyCode().then(() => props.onCopied?.());
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      e.stopPropagation();
      copyCode().then(() => props.onCopied?.());
    }
  };

  return (
    <div
      class={`${styles.codeZone} ${styles.codeZoneCopyable}`}
      aria-live="polite"
      role="button"
      tabindex={0}
      title={t("entries.card.copyCode")}
      data-testid="copy-trigger"
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      <Show
        when={totp.code()}
        fallback={<span class={styles.code}>{formatPlaceholder(props.digits)}</span>}
      >
        <span class={styles.liveCode} data-testid="live-totp-code">
          {formatTotpCode(totp.code(), props.digits)}
        </span>
      </Show>
      <CountdownRing remaining={totp.remainingSeconds()} period={props.period} />
    </div>
  );
};

export const EntryCard: Component<EntryCardProps> = (props) => {
  const [copied, setCopied] = createSignal(false);

  const handleCopied = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), HIGHLIGHT_DURATION_MS);
  };

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      if (props.entry.entryType === "totp") {
        const copyTrigger = (e.currentTarget as HTMLElement).querySelector('[data-testid="copy-trigger"]') as HTMLElement | null;
        copyTrigger?.click();
      } else {
        props.onSelect?.(props.entry.id);
      }
    }
  };

  return (
    <li
      class={`${styles.card} ${copied() ? styles.cardCopied : ""}`}
      aria-label={buildAriaLabel(props.entry)}
      onClick={() => props.onSelect?.(props.entry.id)}
      onKeyDown={handleKeyDown}
      tabindex={props.onSelect ? 0 : undefined}
    >
      {/* ── Header ── */}
      <div class={styles.header}>
        <TypeBadge entryType={props.entry.entryType} />
        <div class={styles.nameBlock}>
          <span class={styles.name}>{props.entry.name}</span>
          <Show when={props.entry.issuer}>
            <span class={styles.issuer}>{props.entry.issuer}</span>
          </Show>
        </div>
        <Show
          when={props.onTogglePin}
          fallback={
            <Show when={props.entry.pinned}>
              <Icon name="star" size={14} label={t("entries.card.pinned")} class={styles.pin} />
            </Show>
          }
        >
          <button
            class={`${styles.pinToggle} ${props.entry.pinned ? styles.pinTogglePinned : ""}`}
            aria-label={props.entry.pinned ? t("entries.card.unpin") : t("entries.card.pin")}
            data-testid="pin-toggle"
            onClick={(e) => {
              e.stopPropagation();
              props.onTogglePin!(props.entry.id, !props.entry.pinned);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                e.stopPropagation();
                props.onTogglePin!(props.entry.id, !props.entry.pinned);
              }
            }}
          >
            <Icon name="star" size={14} />
          </button>
        </Show>
      </div>

      {/* ── Type-specific content zone ── */}
      <div class={styles.content}>
        <Switch fallback={<span class={styles.fallbackText}>{props.entry.entryType}</span>}>
          <Match when={props.entry.entryType === "totp"}>
            <TotpLiveCode
              entryId={props.entry.id}
              entryName={props.entry.name}
              digits={props.entry.digits}
              period={props.entry.period}
              onCopied={handleCopied}
            />
            <Show when={props.recoveryStats?.get(props.entry.id)}>
              {(stats) => (
                <span class={styles.recoveryMeta} title={t("entries.card.recoveryTitle")}>
                  {t("entries.card.recoveryRemaining", { remaining: String(stats().remaining), total: String(stats().total) })}
                </span>
              )}
            </Show>
          </Match>
          <Match when={props.entry.entryType === "hotp"}>
            <div class={styles.codeZone}>
              <span class={styles.code}>{formatPlaceholder(props.entry.digits)}</span>
            </div>
          </Match>
          <Match when={props.entry.entryType === "seed_phrase"}>
            <div class={styles.seedZone}>
              <span class={styles.masked} data-testid="seed-masked">
                {"●●●●● ●●●●● ●●●●●"}
              </span>
              <span class={styles.seedMeta}>{t("entries.card.seedWords", { count: "24" })}</span>
            </div>
          </Match>
          <Match when={props.entry.entryType === "recovery_code"}>
            <div class={styles.recoveryZone}>
              <Show
                when={props.recoveryStats?.get(props.entry.id)}
                fallback={
                  <>
                    <span class={styles.recoveryText}>{t("entries.card.recoveryTitle")}</span>
                    <span class={styles.recoveryMeta}>{t("entries.card.clickToView")}</span>
                  </>
                }
              >
                {(stats) => {
                  const remaining = () => stats().remaining;
                  const total = () => stats().total;
                  const isWarning = () => remaining() > 0 && remaining() <= 2;
                  const isDanger = () => remaining() === 0;
                  return (
                    <>
                      <span class={styles.recoveryText}>
                        {t("entries.card.recoveryRemaining", { remaining: String(remaining()), total: String(total()) })}
                      </span>
                      <Show when={isDanger()}>
                        <span class={styles.recoveryAlertDanger}>
                          <Icon name="alert-triangle" size={12} />
                          {t("entries.card.recoveryNone")}
                        </span>
                      </Show>
                      <Show when={isWarning()}>
                        <span class={styles.recoveryAlertWarning}>
                          <Icon name="alert-triangle" size={12} />
                          {t("entries.card.recoveryLow")}
                        </span>
                      </Show>
                      <Show when={!isWarning() && !isDanger()}>
                        <span class={styles.recoveryMeta}>{t("entries.card.clickToView")}</span>
                      </Show>
                    </>
                  );
                }}
              </Show>
            </div>
          </Match>
          <Match when={props.entry.entryType === "secure_note"}>
            <div class={styles.noteZone}>
              <span class={styles.noteText}>{t("entries.card.secureNote")}</span>
              <Show when={(props.entry.tags ?? []).length > 0}>
                <div class={styles.noteTags}>
                  <For each={props.entry.tags}>
                    {(tag) => (
                      <button
                        class={styles.noteTag}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSearchQuery(tag);
                        }}
                        title={t("entries.card.filterByTag", { tag })}
                      >
                        {tag}
                      </button>
                    )}
                  </For>
                </div>
              </Show>
            </div>
          </Match>
          <Match when={props.entry.entryType === "credential"}>
            <div class={styles.credentialZone}>
              <Switch fallback={
                <>
                  <Show when={props.entry.username}>
                    <span class={styles.credentialUsername}>{props.entry.username}</span>
                  </Show>
                  <span class={styles.masked}>{"••••••"}</span>
                </>
              }>
                <Match when={props.entry.template === "credit_card"}>
                  <Icon name="credit-card" size={14} />
                  <span class={styles.masked}>{"•••• ••••"}</span>
                </Match>
                <Match when={props.entry.template === "ssh_key"}>
                  <Icon name="terminal" size={14} />
                  <span class={styles.credentialUsername}>{t("entries.card.templateSshKey")}</span>
                </Match>
                <Match when={props.entry.template === "software_license"}>
                  <Icon name="file-text" size={14} />
                  <span class={styles.credentialUsername}>{t("entries.card.templateLicense")}</span>
                </Match>
                <Match when={props.entry.template === "identity"}>
                  <Icon name="user" size={14} />
                  <span class={styles.credentialUsername}>
                    {props.entry.username || t("entries.card.templateIdentity")}
                  </span>
                </Match>
              </Switch>
            </div>
          </Match>
        </Switch>
      </div>
    </li>
  );
};
