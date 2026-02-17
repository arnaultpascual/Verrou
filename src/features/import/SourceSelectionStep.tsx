import type { Component } from "solid-js";
import { createSignal, For } from "solid-js";
import { Icon, type IconName } from "../../components";
import type { ImportSource } from "./types";
import { t } from "../../stores/i18nStore";
import styles from "./SourceSelectionStep.module.css";

export interface SourceSelectionStepProps {
  onSelect: (source: ImportSource) => void;
}

interface SourceOption {
  id: ImportSource;
  name: string;
  description: string;
  icon: IconName;
}

const SOURCES: SourceOption[] = [
  {
    id: "google-auth",
    name: "import.sourceSelection.sources.googleAuth.name",
    description: "import.sourceSelection.sources.googleAuth.description",
    icon: "lock",
  },
  {
    id: "aegis",
    name: "import.sourceSelection.sources.aegis.name",
    description: "import.sourceSelection.sources.aegis.description",
    icon: "shield",
  },
  {
    id: "twofas",
    name: "import.sourceSelection.sources.twofas.name",
    description: "import.sourceSelection.sources.twofas.description",
    icon: "info",
  },
];

export const SourceSelectionStep: Component<SourceSelectionStepProps> = (props) => {
  const [selected, setSelected] = createSignal<ImportSource | null>(null);

  const handleSelect = (source: ImportSource) => {
    setSelected(source);
    props.onSelect(source);
  };

  const handleKeyDown = (source: ImportSource, e: KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      handleSelect(source);
    }
  };

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>{t("import.sourceSelection.heading")}</h2>
      <p class={styles.description}>
        {t("import.sourceSelection.description")}
      </p>

      <div class={styles.sources} role="radiogroup" aria-label={t("import.sourceSelection.ariaLabel")}>
        <For each={SOURCES}>
          {(source) => {
            const isSelected = () => selected() === source.id;

            return (
              <button
                type="button"
                role="radio"
                aria-checked={isSelected()}
                class={`${styles.sourceCard} ${isSelected() ? styles.sourceCardSelected : ""}`}
                onClick={() => handleSelect(source.id)}
                onKeyDown={(e) => handleKeyDown(source.id, e)}
              >
                <Icon name={source.icon} size={24} aria-hidden="true" />
                <div class={styles.sourceInfo}>
                  <span class={styles.sourceName}>{t(source.name)}</span>
                  <span class={styles.sourceDescription}>{t(source.description)}</span>
                </div>
              </button>
            );
          }}
        </For>
      </div>
    </div>
  );
};
