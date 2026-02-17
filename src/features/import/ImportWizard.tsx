import type { Component } from "solid-js";
import { createSignal, Show, Switch, Match } from "solid-js";
import { createStore } from "solid-js/store";
import { StepIndicator } from "../onboarding/StepIndicator";
import { Button } from "../../components";
import { t } from "../../stores/i18nStore";
import { SourceSelectionStep } from "./SourceSelectionStep";
import { ExportGuideStep } from "./ExportGuideStep";
import { ValidationReportStep } from "./ValidationReportStep";
import { ImportProgressStep } from "./ImportProgressStep";
import type { ImportSource, ValidationReportDto, ImportSummaryDto } from "./types";
import styles from "./ImportWizard.module.css";

const STEP_LABELS_KEYS = [
  "import.wizard.steps.source",
  "import.wizard.steps.export",
  "import.wizard.steps.review",
  "import.wizard.steps.import",
];

export interface ImportWizardProps {
  onComplete: (importedCount?: number) => void;
  onCancel: () => void;
  embedded?: boolean;
}

export interface WizardState {
  source: ImportSource | null;
  fileData: string | null;
  password: string | null;
  report: ValidationReportDto | null;
  skipIndices: number[];
  isImporting: boolean;
  summary: ImportSummaryDto | null;
  error: string | null;
}

const INITIAL_STATE: WizardState = {
  source: null,
  fileData: null,
  password: null,
  report: null,
  skipIndices: [],
  isImporting: false,
  summary: null,
  error: null,
};

export const ImportWizard: Component<ImportWizardProps> = (props) => {
  const [step, setStep] = createSignal(1);
  const [state, setState] = createStore<WizardState>({ ...INITIAL_STATE });

  const handleSourceSelect = (source: ImportSource) => {
    setState("source", source);
    setStep(2);
  };

  const handleValidated = (
    report: ValidationReportDto,
    fileData: string,
    password?: string,
  ) => {
    setState({
      report,
      fileData,
      password: password ?? null,
    });
    setStep(3);
  };

  const handleConfirm = (skipIndices: number[]) => {
    setState("skipIndices", skipIndices);
    setStep(4);
  };

  const handleImportComplete = (summary: ImportSummaryDto) => {
    setState("summary", summary);
  };

  const handleImportError = (error: string) => {
    setState("error", error);
  };

  const handleRetry = () => {
    setState({ ...INITIAL_STATE });
    setStep(1);
  };

  const back = () => {
    if (step() > 1 && step() < 4) {
      setStep((s) => s - 1);
    }
  };

  const showNavigation = () => step() < 4;
  const showBack = () => step() > 1;

  return (
    <div class={styles.container}>
      <StepIndicator currentStep={step()} labels={STEP_LABELS_KEYS.map((k) => t(k))} />

      <div class={styles.content}>
        <Switch>
          <Match when={step() === 1}>
            <SourceSelectionStep onSelect={handleSourceSelect} />
          </Match>
          <Match when={step() === 2}>
            <ExportGuideStep
              source={state.source!}
              onValidated={handleValidated}
            />
          </Match>
          <Match when={step() === 3}>
            <ValidationReportStep
              report={state.report!}
              onConfirm={handleConfirm}
            />
          </Match>
          <Match when={step() === 4}>
            <ImportProgressStep
              source={state.source!}
              fileData={state.fileData!}
              password={state.password}
              skipIndices={state.skipIndices}
              report={state.report!}
              onComplete={handleImportComplete}
              onError={handleImportError}
              onRetry={handleRetry}
              onDone={() => props.onComplete(state.summary?.imported)}
              summary={state.summary}
              error={state.error}
            />
          </Match>
        </Switch>
      </div>

      <Show when={showNavigation()}>
        <div class={styles.navigation}>
          <div>
            <Show when={showBack()}>
              <Button variant="ghost" onClick={back}>
                {t("common.back")}
              </Button>
            </Show>
          </div>
          <div class={styles.navigationEnd}>
            <Button variant="ghost" onClick={props.onCancel}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      </Show>
    </div>
  );
};
