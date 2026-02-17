import type { Component } from "solid-js";
import { createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Icon, useToast } from "../../components";
import { setVaultState } from "../../stores/vaultStore";
import { ImportWizard } from "../import/ImportWizard";
import { t } from "../../stores/i18nStore";
import styles from "./ImportStep.module.css";

export const ImportStep: Component = () => {
  const navigate = useNavigate();
  const toast = useToast();
  const [showImport, setShowImport] = createSignal(false);

  const handleStartEmpty = () => {
    setVaultState("unlocked");
    toast.success(t("onboarding.import.toastCreated"));
    navigate("/entries", { replace: true });
  };

  const handleImportComplete = (importedCount?: number) => {
    setVaultState("unlocked");
    const count = importedCount ?? 0;
    if (count > 0) {
      toast.success(
        t("onboarding.import.toastImported", { count: String(count) }),
      );
    } else {
      toast.success(t("onboarding.import.toastReady"));
    }
    navigate("/entries", { replace: true });
  };

  const handleImportCancel = () => {
    setShowImport(false);
  };

  return (
    <div class={styles.step}>
      <Show when={!showImport()}>
        <h2 class={styles.heading}>{t("onboarding.import.heading")}</h2>
        <p class={styles.description}>
          {t("onboarding.import.description")}
        </p>

        <div class={styles.options}>
          <button type="button" class={styles.optionCard} onClick={() => setShowImport(true)}>
            <Icon name="folder" size={24} aria-hidden="true" />
            <span class={styles.optionLabel}>{t("onboarding.import.optionImport")}</span>
            <span class={styles.optionNote}>{t("onboarding.import.optionImportNote")}</span>
          </button>

          <button type="button" class={styles.optionCard} onClick={handleStartEmpty}>
            <Icon name="shield" size={24} aria-hidden="true" />
            <span class={styles.optionLabel}>{t("onboarding.import.optionEmpty")}</span>
            <span class={styles.optionNote}>{t("onboarding.import.optionEmptyNote")}</span>
          </button>
        </div>
      </Show>

      <Show when={showImport()}>
        <ImportWizard
          embedded
          onComplete={handleImportComplete}
          onCancel={handleImportCancel}
        />
      </Show>
    </div>
  );
};
