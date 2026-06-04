import type { Component } from "solid-js";
import { createSignal, Show, Switch, Match } from "solid-js";
import { StepIndicator } from "./StepIndicator";
import { WelcomeStep } from "./WelcomeStep";
import { PasswordStep } from "./PasswordStep";
import { KdfPresetStep } from "./KdfPresetStep";
import { RecoveryKeyStep } from "./RecoveryKeyStep";
import { ImportStep } from "./ImportStep";
import { wizardStore } from "./stores";
import { Button } from "../../components";
import { t } from "../../stores/i18nStore";
import styles from "./OnboardingWizard.module.css";

// Step 0 is the welcome gateway; steps 1-4 are the numbered wizard.
const TOTAL_STEPS = 4;

export const OnboardingWizard: Component = () => {
  const [step, setStep] = createSignal(0);
  const [canProceed, setCanProceed] = createSignal(false);

  const next = () => {
    if (step() < TOTAL_STEPS && canProceed()) {
      setCanProceed(false);
      setStep((s) => s + 1);
    }
  };

  const back = () => {
    if (step() > 1) {
      setCanProceed(true);
      setStep((s) => s - 1);
    }
  };

  return (
    <div class={styles.backdrop}>
      <div class={styles.card}>
        <Show when={step() >= 1}>
          <StepIndicator
            currentStep={step()}
            labels={[
              t("onboarding.steps.password"),
              t("onboarding.steps.security"),
              t("onboarding.steps.recovery"),
              t("onboarding.steps.import"),
            ]}
          />
        </Show>

        <Switch>
          <Match when={step() === 0}>
            <WelcomeStep onStart={() => setStep(1)} />
          </Match>
          <Match when={step() === 1}>
            <PasswordStep onValidChange={setCanProceed} />
          </Match>
          <Match when={step() === 2}>
            <KdfPresetStep onValidChange={setCanProceed} />
          </Match>
          <Match when={step() === 3}>
            <RecoveryKeyStep onValidChange={setCanProceed} />
          </Match>
          <Match when={step() === 4}>
            <ImportStep />
          </Match>
        </Switch>

        {step() >= 1 && step() < TOTAL_STEPS && !wizardStore.isCreating && (
          <div class={styles.navigation}>
            {step() > 1 && (
              <Button variant="ghost" onClick={back}>
                {t("common.back")}
              </Button>
            )}
            <Button variant="primary" onClick={next} disabled={!canProceed()}>
              {t("common.next")}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};
