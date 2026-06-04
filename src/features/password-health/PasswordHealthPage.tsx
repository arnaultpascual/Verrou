import type { Component } from "solid-js";
import { createResource, createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Icon, Button, useToast } from "../../components";
import { EditCredentialModal } from "../credentials/EditCredentialModal";
import { t } from "../../stores/i18nStore";
import { getPasswordHealth } from "./ipc";
import type {
  PasswordHealthReport,
  CredentialRef,
  WeakCredential,
  OldCredential,
} from "./ipc";
import styles from "./PasswordHealthPage.module.css";

// ---------------------------------------------------------------------------
// Score helpers
// ---------------------------------------------------------------------------

const RING_RADIUS = 32;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function scoreColor(score: number): string {
  if (score >= 70) return styles.good;
  if (score >= 50) return styles.warning;
  return styles.danger;
}

function scoreLabel(score: number): string {
  if (score >= 90) return t("passwordHealth.scoreExcellent");
  if (score >= 70) return t("passwordHealth.scoreGood");
  if (score >= 50) return t("passwordHealth.scoreAttention");
  return t("passwordHealth.scoreAtRisk");
}

function scoreCssVar(score: number): string {
  if (score >= 70) return "var(--color-success)";
  if (score >= 50) return "var(--color-warning)";
  return "var(--color-danger)";
}

/** Friendly label for a weak/fair strength tier. */
function strengthLabel(strength: string): string {
  return strength === "weak"
    ? t("passwordHealth.strengthWeak")
    : t("passwordHealth.strengthFair");
}

/** Humanize "days since the password changed" into a calm relative phrase. */
function humanizeAge(days: number): string {
  if (days >= 730) {
    return t("passwordHealth.ageOverYears", { years: String(Math.floor(days / 365)) });
  }
  if (days >= 365) return t("passwordHealth.ageOverYear");
  if (days >= 180) return t("passwordHealth.ageOverSixMonths");
  const months = Math.max(1, Math.round(days / 30));
  return t("passwordHealth.ageMonths", { count: String(months) });
}

// ---------------------------------------------------------------------------
// Small pieces
// ---------------------------------------------------------------------------

const Chip: Component<{ text: string; tone: "danger" | "warning" }> = (props) => (
  <span
    class={`${styles.chip} ${props.tone === "danger" ? styles.chipDanger : styles.chipWarning}`}
  >
    {props.text}
  </span>
);

/** Honest, expandable explanation of how the score is computed. */
const ScoreExplainer: Component = () => {
  const [open, setOpen] = createSignal(false);
  return (
    <div class={styles.explainer}>
      <button
        type="button"
        class={styles.explainerToggle}
        aria-expanded={open()}
        onClick={() => setOpen(!open())}
      >
        <Icon name="info" size={13} />
        {t("passwordHealth.scoreExplainerToggle")}
      </button>
      <Show when={open()}>
        <p class={styles.explainerPanel}>{t("passwordHealth.scoreExplainer")}</p>
      </Show>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Scored category card (reused / weak / old) — expandable, with inline Fix
// ---------------------------------------------------------------------------

interface IssueRow {
  id: string;
  name: string;
  chip?: { text: string; tone: "danger" | "warning" };
}

interface ScoredCardProps {
  title: string;
  icon: "alert" | "shield" | "info";
  rows: IssueRow[];
  cardClass: string;
  countClass: string;
  onFix: (id: string, name: string) => void;
}

const ScoredCard: Component<ScoredCardProps> = (props) => {
  const [expanded, setExpanded] = createSignal(false);
  const count = () => props.rows.length;

  return (
    <div class={`${styles.card} ${props.cardClass}`}>
      <div
        class={styles.cardHeader}
        role="button"
        tabIndex={0}
        aria-expanded={expanded()}
        onClick={() => setExpanded(!expanded())}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setExpanded(!expanded());
          }
        }}
      >
        <div class={styles.cardInfo}>
          <Icon name={props.icon} size={16} class={styles.cardIcon} />
          <span class={styles.cardTitle}>{props.title}</span>
        </div>
        <div class={styles.cardInfo}>
          <span class={`${styles.cardCount} ${props.countClass}`}>{count()}</span>
          <Icon
            name="chevron-right"
            size={14}
            class={`${styles.chevron} ${expanded() ? styles.chevronOpen : ""}`}
          />
        </div>
      </div>
      <Show when={expanded() && count() > 0}>
        <div class={styles.credentialList}>
          <For each={props.rows}>
            {(row) => (
              <div class={styles.issueRow}>
                <span class={styles.credentialName}>{row.name}</span>
                <div class={styles.itemRight}>
                  <Show when={row.chip}>
                    {(chip) => <Chip text={chip().text} tone={chip().tone} />}
                  </Show>
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => props.onFix(row.id, row.name)}
                    aria-label={t("passwordHealth.fixAria", { name: row.name })}
                    data-testid="health-fix-btn"
                  >
                    <Icon name="key" size={14} /> {t("passwordHealth.fix")}
                  </Button>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
};

// ---------------------------------------------------------------------------
// 2FA coverage — separate, NOT part of the password score
// ---------------------------------------------------------------------------

const TwoFactorCoverage: Component<{
  credentials: CredentialRef[];
  total: number;
}> = (props) => {
  const navigate = useNavigate();
  const view = (id: string) => navigate(`/entries?type=credential&highlight=${id}`);

  return (
    <section class={styles.coverage} aria-labelledby="coverage-title">
      <div class={styles.coverageHead}>
        <div class={styles.cardInfo}>
          <Icon name="shield-check" size={16} class={styles.coverageIcon} />
          <span id="coverage-title" class={styles.sectionTitle}>
            {t("passwordHealth.coverageTitle")}
          </span>
        </div>
        <span class={styles.coverageMeta}>
          {t("passwordHealth.coverageSummary", {
            count: String(props.credentials.length),
            total: String(props.total),
          })}
        </span>
      </div>
      <p class={styles.sectionHint}>{t("passwordHealth.coverageHint")}</p>
      <div class={styles.credentialList}>
        <For each={props.credentials}>
          {(cred) => (
            <div class={styles.issueRow}>
              <span class={styles.credentialName}>{cred.name}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => view(cred.id)}
                aria-label={t("passwordHealth.addTwoFactorAria", { name: cred.name })}
              >
                <Icon name="shield" size={14} /> {t("passwordHealth.addTwoFactor")}
              </Button>
            </div>
          )}
        </For>
      </div>
    </section>
  );
};

// ---------------------------------------------------------------------------
// Loading / empty states
// ---------------------------------------------------------------------------

const LoadingSkeleton: Component = () => (
  <div class={styles.skeleton}>
    <div class={styles.skeletonScore} />
    <div class={styles.skeletonCards}>
      <div class={styles.skeletonCard} />
      <div class={styles.skeletonCard} />
      <div class={styles.skeletonCard} />
    </div>
  </div>
);

const EmptyState: Component<{ hasCredentials: boolean }> = (props) => (
  <div class={styles.emptyState}>
    <Icon
      name={props.hasCredentials ? "shield-check" : "info"}
      size={48}
      class={props.hasCredentials ? styles.emptyIcon : ""}
    />
    <div class={styles.emptyTitle}>
      {props.hasCredentials
        ? t("passwordHealth.allHealthy")
        : t("passwordHealth.noCredentials")}
    </div>
    <div class={styles.emptySubtitle}>
      {props.hasCredentials
        ? t("passwordHealth.noIssues")
        : t("passwordHealth.addCredentials")}
    </div>
  </div>
);

/** Compact "passwords are all strong" note (shown when only 2FA coverage remains). */
const PasswordsHealthyNote: Component = () => (
  <div class={styles.healthyNote}>
    <Icon name="check" size={16} class={styles.healthyNoteIcon} />
    <span>{t("passwordHealth.passwordsAllStrong")}</span>
  </div>
);

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

const HealthDashboard: Component<{
  report: PasswordHealthReport;
  onFix: (id: string, name: string) => void;
}> = (props) => {
  const r = () => props.report;

  // The score reflects PASSWORD hygiene only (reused/weak/old). Missing 2FA is
  // tracked separately below and intentionally excluded — mirrors the backend.
  const passwordIssues = () => r().reusedCount + r().weakCount + r().oldCount;
  const hasPasswordIssues = () => passwordIssues() > 0;
  const hasNoTotp = () => r().noTotpCount > 0;

  // Flatten reused groups into rows, annotated with "shared with N more".
  const reusedRows = (): IssueRow[] =>
    r().reusedGroups.flatMap((group) =>
      group.credentials.map((cred) => ({
        id: cred.id,
        name: cred.name,
        chip: {
          text: t("passwordHealth.reusedSharedWith", {
            count: String(Math.max(1, group.credentials.length - 1)),
          }),
          tone: "danger" as const,
        },
      })),
    );

  const weakRows = (): IssueRow[] =>
    r().weakCredentials.map((cred: WeakCredential) => ({
      id: cred.id,
      name: cred.name,
      chip: {
        text: strengthLabel(cred.strength),
        tone: cred.strength === "weak" ? ("danger" as const) : ("warning" as const),
      },
    }));

  const oldRows = (): IssueRow[] =>
    r().oldCredentials.map((cred: OldCredential) => ({
      id: cred.id,
      name: cred.name,
      chip: {
        text: humanizeAge(cred.daysSinceChange),
        tone: cred.severity === "danger" ? ("danger" as const) : ("warning" as const),
      },
    }));

  return (
    <Show
      when={r().totalCredentials > 0}
      fallback={<EmptyState hasCredentials={false} />}
    >
      {/* Score */}
      <div class={styles.scoreSection}>
        <div class={styles.scoreRing}>
          <svg width="80" height="80" viewBox="0 0 80 80">
            <circle
              cx="40"
              cy="40"
              r={RING_RADIUS}
              fill="none"
              stroke="var(--color-surface-3)"
              stroke-width="6"
            />
            <circle
              cx="40"
              cy="40"
              r={RING_RADIUS}
              fill="none"
              stroke={scoreCssVar(r().overallScore)}
              stroke-width="6"
              stroke-linecap="round"
              stroke-dasharray={String(RING_CIRCUMFERENCE)}
              stroke-dashoffset={String(RING_CIRCUMFERENCE * (1 - r().overallScore / 100))}
            />
          </svg>
          <span class={`${styles.scoreValue} ${scoreColor(r().overallScore)}`}>
            {r().overallScore}
          </span>
        </div>
        <div class={styles.scoreDetails}>
          <span class={styles.scoreLabel}>{scoreLabel(r().overallScore)}</span>
          <span class={styles.scoreSummary}>
            {hasPasswordIssues()
              ? t("passwordHealth.issuesSummary", {
                  total: String(passwordIssues()),
                  credentials: String(r().totalCredentials),
                })
              : t("passwordHealth.allCredentialsHealthy", {
                  count: String(r().totalCredentials),
                })}
          </span>
          <ScoreExplainer />
        </div>
      </div>

      {/* Scored password categories, or a healthy state */}
      <Show
        when={hasPasswordIssues()}
        fallback={
          <Show when={hasNoTotp()} fallback={<EmptyState hasCredentials={true} />}>
            <PasswordsHealthyNote />
          </Show>
        }
      >
        <div class={styles.categories}>
          <Show when={r().reusedCount > 0}>
            <ScoredCard
              title={t("passwordHealth.reusedPasswords")}
              icon="alert"
              rows={reusedRows()}
              cardClass={styles.cardReused}
              countClass={styles.countDanger}
              onFix={props.onFix}
            />
          </Show>
          <Show when={r().weakCount > 0}>
            <ScoredCard
              title={t("passwordHealth.weakPasswords")}
              icon="shield"
              rows={weakRows()}
              cardClass={styles.cardWeak}
              countClass={styles.countWarning}
              onFix={props.onFix}
            />
          </Show>
          <Show when={r().oldCount > 0}>
            <ScoredCard
              title={t("passwordHealth.oldPasswords")}
              icon="info"
              rows={oldRows()}
              cardClass={styles.cardOld}
              countClass={styles.countWarning}
              onFix={props.onFix}
            />
          </Show>
        </div>
      </Show>

      {/* 2FA coverage — separate, non-scored */}
      <Show when={hasNoTotp()}>
        <TwoFactorCoverage
          credentials={r().noTotpCredentials}
          total={r().totalCredentials}
        />
      </Show>
    </Show>
  );
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export const PasswordHealthPage: Component = () => {
  const toast = useToast();
  const [report, { refetch }] = createResource(getPasswordHealth);

  // Inline remediation: the credential being "fixed" (password rotation) via
  // the canonical EditCredentialModal — which preserves every other field.
  const [fixEntry, setFixEntry] = createSignal<{ id: string; name: string } | null>(null);

  const handleRefresh = () => {
    refetch();
    toast.info(t("passwordHealth.toastAnalyzing"));
  };

  const handleFixSuccess = () => {
    setFixEntry(null);
    refetch();
  };

  return (
    <div class={styles.page}>
      <div class={styles.header}>
        <h2 class={styles.title}>{t("passwordHealth.title")}</h2>
        <Button
          variant="ghost"
          onClick={handleRefresh}
          disabled={report.loading}
          aria-label={t("passwordHealth.ariaRefresh")}
        >
          <Icon name="refresh" size={16} />
        </Button>
      </div>

      <Show when={!report.loading} fallback={<LoadingSkeleton />}>
        <Show when={report()}>
          {(data) => (
            <HealthDashboard
              report={data()}
              onFix={(id, name) => setFixEntry({ id, name })}
            />
          )}
        </Show>
        <Show when={report.error}>
          <div class={styles.emptyState}>
            <Icon name="alert" size={48} />
            <div class={styles.emptyTitle}>{t("passwordHealth.analysisFailed")}</div>
            <div class={styles.emptySubtitle}>
              {typeof report.error === "string"
                ? report.error
                : t("passwordHealth.analysisFailedDescription")}
            </div>
          </div>
        </Show>
      </Show>

      {/* Remediation modal — rotates the password (old → history), keeps the rest. */}
      <EditCredentialModal
        open={fixEntry() !== null}
        entryId={fixEntry()?.id ?? ""}
        onClose={() => setFixEntry(null)}
        onSuccess={handleFixSuccess}
      />
    </div>
  );
};
