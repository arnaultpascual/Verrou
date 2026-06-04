import type { Component } from "solid-js";
import { For } from "solid-js";
import { Button, Icon, Logo } from "../../components";
import type { IconName } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./WelcomeStep.module.css";

export interface WelcomeStepProps {
  /** Advance into the wizard (password step). */
  onStart: () => void;
}

const POINTS: { icon: IconName; text: string }[] = [
  { icon: "lock", text: "onboarding.welcome.offline" },
  { icon: "user", text: "onboarding.welcome.noAccounts" },
  { icon: "shield-check", text: "onboarding.welcome.postQuantum" },
];

/**
 * First-run welcome / value screen. Establishes what Verrou is before asking
 * for anything: offline, accountless, post-quantum. A single "Get started"
 * CTA leads into the wizard.
 */
export const WelcomeStep: Component<WelcomeStepProps> = (props) => {
  return (
    <div class={styles.step}>
      <div class={styles.brand} aria-hidden="true">
        <Logo size={56} />
      </div>

      <h1 class={styles.heading}>{t("onboarding.welcome.heading")}</h1>
      <p class={styles.subheading}>{t("onboarding.welcome.subheading")}</p>

      <ul class={styles.points}>
        <For each={POINTS}>
          {(point) => (
            <li class={styles.point}>
              <Icon name={point.icon} size={18} class={styles.pointIcon} />
              <span>{t(point.text)}</span>
            </li>
          )}
        </For>
      </ul>

      <Button variant="primary" fullWidth onClick={props.onStart} data-testid="welcome-start">
        {t("onboarding.welcome.cta")}
      </Button>
    </div>
  );
};
