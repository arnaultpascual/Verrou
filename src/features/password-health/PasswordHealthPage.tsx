import type { Component } from "solid-js";
import { createResource, createSignal, Show, For } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Icon, Button, useToast } from "../../components";
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
// Score ring SVG
// ---------------------------------------------------------------------------

const RING_RADIUS = 32;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function scoreColor(score: number): string {
  if (score >= 90) return styles.excellent;
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
  if (score >= 90) return "var(--color-success)";
  if (score >= 70) return "var(--color-success)";
  if (score >= 50) return "var(--color-warning)";
  return "var(--color-danger)";
}

// ---------------------------------------------------------------------------
// Category card
// ---------------------------------------------------------------------------

interface CategoryCardProps {
  title: string;
  icon: "alert" | "shield" | "lock" | "info";
  count: number;
  cardClass: string;
  countClass: string;
  children: any;
}

const CategoryCard: Component<CategoryCardProps> = (props) => {
  const [expanded, setExpanded] = createSignal(false);

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
          <span class={`${styles.cardCount} ${props.countClass}`}>
            {props.count}
          </span>
          <Icon
            name="chevron-right"
            size={14}
            class={`${styles.chevron} ${expanded() ? styles.chevronOpen : ""}`}
          />
        </div>
      </div>
      <Show when={expanded() && props.count > 0}>
        <div class={styles.credentialList}>{props.children}</div>
      </Show>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Credential list item
// ---------------------------------------------------------------------------

interface CredentialItemProps {
  id: string;
  name: string;
  meta?: string;
}

const CredentialItem: Component<CredentialItemProps> = (props) => {
  const navigate = useNavigate();
  const target = () => `/entries?type=credential&highlight=${props.id}`;

  return (
    <div
      class={styles.credentialItem}
      role="button"
      tabIndex={0}
      onClick={() => navigate(target())}
      onKeyDown={(e) => {
        if (e.key === "Enter") navigate(target());
      }}
    >
      <span class={styles.credentialName}>{props.name}</span>
      <Show when={props.meta}>
        <span class={styles.credentialMeta}>{props.meta}</span>
      </Show>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Loading skeleton
// ---------------------------------------------------------------------------

const LoadingSkeleton: Component = () => (
  <div class={styles.skeleton}>
    <div class={styles.skeletonScore} />
    <div class={styles.skeletonCards}>
      <div class={styles.skeletonCard} />
      <div class={styles.skeletonCard} />
      <div class={styles.skeletonCard} />
      <div class={styles.skeletonCard} />
    </div>
  </div>
);

// ---------------------------------------------------------------------------
// Empty state
// ---------------------------------------------------------------------------

const EmptyState: Component<{ hasCredentials: boolean }> = (props) => (
  <div class={styles.emptyState}>
    <Icon
      name={props.hasCredentials ? "shield" : "info"}
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

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export const PasswordHealthPage: Component = () => {
  const toast = useToast();
  const [report, { refetch }] = createResource(getPasswordHealth);

  const handleRefresh = () => {
    refetch();
    toast.info(t("passwordHealth.toastAnalyzing"));
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
          {(data) => <HealthDashboard report={data()} />}
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
    </div>
  );
};

// ---------------------------------------------------------------------------
// Dashboard content
// ---------------------------------------------------------------------------

const HealthDashboard: Component<{ report: PasswordHealthReport }> = (
  props,
) => {
  const r = () => props.report;
  const totalIssues = () =>
    r().reusedCount + r().weakCount + r().oldCount + r().noTotpCount;
  const hasIssues = () => totalIssues() > 0;

  return (
    <>
      <Show
        when={r().totalCredentials > 0}
        fallback={<EmptyState hasCredentials={false} />}
      >
        {/* Score section */}
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
                stroke-dashoffset={String(
                  RING_CIRCUMFERENCE * (1 - r().overallScore / 100)
                )}
              />
            </svg>
            <span class={`${styles.scoreValue} ${scoreColor(r().overallScore)}`}>
              {r().overallScore}
            </span>
          </div>
          <div class={styles.scoreDetails}>
            <span class={styles.scoreLabel}>
              {scoreLabel(r().overallScore)}
            </span>
            <span class={styles.scoreSummary}>
              {hasIssues()
                ? t("passwordHealth.issuesSummary", { total: String(totalIssues()), credentials: String(r().totalCredentials) })
                : t("passwordHealth.allCredentialsHealthy", { count: String(r().totalCredentials) })}
            </span>
          </div>
        </div>

        <Show
          when={hasIssues()}
          fallback={<EmptyState hasCredentials={true} />}
        >
          <div class={styles.categories}>
            {/* Reused passwords */}
            <CategoryCard
              title={t("passwordHealth.reusedPasswords")}
              icon="alert"
              count={r().reusedCount}
              cardClass={r().reusedCount > 0 ? styles.cardReused : ""}
              countClass={
                r().reusedCount > 0 ? styles.countDanger : styles.countSuccess
              }
            >
              <For each={r().reusedGroups}>
                {(group) => (
                  <For each={group.credentials}>
                    {(cred) => <CredentialItem id={cred.id} name={cred.name} />}
                  </For>
                )}
              </For>
            </CategoryCard>

            {/* Weak passwords */}
            <CategoryCard
              title={t("passwordHealth.weakPasswords")}
              icon="shield"
              count={r().weakCount}
              cardClass={r().weakCount > 0 ? styles.cardWeak : ""}
              countClass={
                r().weakCount > 0 ? styles.countWarning : styles.countSuccess
              }
            >
              <For each={r().weakCredentials}>
                {(cred: WeakCredential) => (
                  <CredentialItem
                    id={cred.id}
                    name={cred.name}
                    meta={cred.strength}
                  />
                )}
              </For>
            </CategoryCard>

            {/* Old passwords */}
            <CategoryCard
              title={t("passwordHealth.oldPasswords")}
              icon="info"
              count={r().oldCount}
              cardClass={r().oldCount > 0 ? styles.cardOld : ""}
              countClass={
                r().oldCount > 0 ? styles.countWarning : styles.countSuccess
              }
            >
              <For each={r().oldCredentials}>
                {(cred: OldCredential) => (
                  <CredentialItem
                    id={cred.id}
                    name={cred.name}
                    meta={`${cred.daysSinceChange}d`}
                  />
                )}
              </For>
            </CategoryCard>

            {/* Missing 2FA */}
            <CategoryCard
              title={t("passwordHealth.no2fa")}
              icon="lock"
              count={r().noTotpCount}
              cardClass={r().noTotpCount > 0 ? styles.cardNoTotp : ""}
              countClass={
                r().noTotpCount > 0 ? styles.countMuted : styles.countSuccess
              }
            >
              <For each={r().noTotpCredentials}>
                {(cred: CredentialRef) => (
                  <CredentialItem id={cred.id} name={cred.name} />
                )}
              </For>
            </CategoryCard>
          </div>
        </Show>
      </Show>
    </>
  );
};
