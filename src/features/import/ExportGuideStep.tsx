import type { Component } from "solid-js";
import { createSignal, Show, For } from "solid-js";
import { Button, Input, PasswordInput, Spinner } from "../../components";
import {
  pickImportFile,
  readImportFile,
  validateGoogleAuthImport,
  validateAegisImport,
  validateTwofasImport,
} from "./ipc";
import type { ImportSource, ValidationReportDto } from "./types";
import { t } from "../../stores/i18nStore";
import styles from "./ExportGuideStep.module.css";

export interface ExportGuideStepProps {
  source: ImportSource;
  onValidated: (
    report: ValidationReportDto,
    fileData: string,
    password?: string,
  ) => void;
}

interface SourceGuide {
  title: string;
  steps: string[];
  usesFilePicker: boolean;
}

const GUIDES: Record<ImportSource, SourceGuide> = {
  "google-auth": {
    title: "import.exportGuide.googleAuth.title",
    steps: [
      "import.exportGuide.googleAuth.step1",
      "import.exportGuide.googleAuth.step2",
      "import.exportGuide.googleAuth.step3",
      "import.exportGuide.googleAuth.step4",
      "import.exportGuide.googleAuth.step5",
    ],
    usesFilePicker: false,
  },
  aegis: {
    title: "import.exportGuide.aegis.title",
    steps: [
      "import.exportGuide.aegis.step1",
      "import.exportGuide.aegis.step2",
      "import.exportGuide.aegis.step3",
      "import.exportGuide.aegis.step4",
      "import.exportGuide.aegis.step5",
    ],
    usesFilePicker: true,
  },
  twofas: {
    title: "import.exportGuide.twofas.title",
    steps: [
      "import.exportGuide.twofas.step1",
      "import.exportGuide.twofas.step2",
      "import.exportGuide.twofas.step3",
      "import.exportGuide.twofas.step4",
    ],
    usesFilePicker: true,
  },
};

export const ExportGuideStep: Component<ExportGuideStepProps> = (props) => {
  const [filePath, setFilePath] = createSignal<string | null>(null);
  const [fileData, setFileData] = createSignal<string | null>(null);
  const [migrationUri, setMigrationUri] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [needsPassword, setNeedsPassword] = createSignal(false);
  const [isParsing, setIsParsing] = createSignal(false);
  const [error, setError] = createSignal<{
    title: string;
    detail: string;
    action: string;
  } | null>(null);

  const guide = () => GUIDES[props.source];

  const handlePickFile = async () => {
    setError(null);
    const path = await pickImportFile(props.source);
    if (!path) return;

    setFilePath(path);
    try {
      const content = await readImportFile(path);
      setFileData(content);

      // Check if encrypted
      const encrypted = checkEncrypted(content, props.source);
      setNeedsPassword(encrypted);

      if (!encrypted) {
        await doParse(content);
      }
    } catch (err) {
      setError({
        title: t("import.exportGuide.errors.readTitle"),
        detail: t("import.exportGuide.errors.readDetail"),
        action: t("import.exportGuide.errors.readAction"),
      });
    }
  };

  const checkEncrypted = (data: string, source: ImportSource): boolean => {
    if (source === "aegis") {
      try {
        const parsed = JSON.parse(data);
        return typeof parsed.db === "string";
      } catch {
        return false;
      }
    }
    if (source === "twofas") {
      try {
        const parsed = JSON.parse(data);
        return (
          parsed.servicesEncrypted != null &&
          parsed.servicesEncrypted !== ""
        );
      } catch {
        return false;
      }
    }
    return false;
  };

  const doParse = async (data?: string, pw?: string) => {
    setIsParsing(true);
    setError(null);

    const content = data ?? fileData() ?? migrationUri();
    const pass = pw ?? (needsPassword() ? password() : undefined);

    try {
      let report: ValidationReportDto;

      if (props.source === "google-auth") {
        report = await validateGoogleAuthImport(content);
      } else if (props.source === "aegis") {
        report = await validateAegisImport(content, pass);
      } else {
        report = await validateTwofasImport(content, pass);
      }

      props.onValidated(report, content, pass);
    } catch (err) {
      const message = typeof err === "string" ? err : t("import.exportGuide.errors.parseFallback");

      if (message.includes("version") || message.includes("unsupported format")) {
        setError({
          title: t("import.exportGuide.errors.unsupportedTitle"),
          detail: message,
          action: t("import.exportGuide.errors.unsupportedAction"),
        });
      } else if (message.includes("encrypted") || message.includes("password")) {
        setNeedsPassword(true);
        setError({
          title: t("import.exportGuide.errors.encryptedTitle"),
          detail: message,
          action: t("import.exportGuide.errors.encryptedAction"),
        });
      } else {
        setError({
          title: t("import.exportGuide.errors.parseTitle"),
          detail: message,
          action: t("import.exportGuide.errors.parseAction"),
        });
      }
    } finally {
      setIsParsing(false);
    }
  };

  const handleParseClick = () => {
    if (props.source === "google-auth") {
      doParse(migrationUri());
    } else {
      doParse();
    }
  };

  const canParse = () => {
    if (isParsing()) return false;
    if (props.source === "google-auth") return migrationUri().trim().length > 0;
    if (!fileData()) return false;
    if (needsPassword()) return password().trim().length > 0;
    return true;
  };

  const fileName = () => {
    const path = filePath();
    if (!path) return null;
    return path.split("/").pop() ?? path.split("\\").pop() ?? path;
  };

  return (
    <div class={styles.step}>
      <h2 class={styles.heading}>{t(guide().title)}</h2>

      <div class={styles.instructions}>
        <For each={guide().steps}>
          {(instruction, i) => (
            <p class={styles.instructionStep}>
              {i() + 1}. {t(instruction)}
            </p>
          )}
        </For>
      </div>

      <Show
        when={guide().usesFilePicker}
        fallback={
          <div class={styles.fileSection}>
            <Input
              label={t("import.exportGuide.migrationLabel")}
              value={migrationUri()}
              onInput={(v) => setMigrationUri(v)}
              placeholder="otpauth-migration://offline?data=..."
            />
          </div>
        }
      >
        <div class={styles.fileSection}>
          <div class={styles.fileRow}>
            <Button variant="ghost" onClick={handlePickFile}>
              {t("import.exportGuide.chooseFile")}
            </Button>
            <Show when={fileName()}>
              <span class={styles.fileName}>{fileName()}</span>
            </Show>
          </div>
        </div>
      </Show>

      <Show when={needsPassword()}>
        <div class={styles.passwordSection}>
          <PasswordInput
            label={t("import.exportGuide.passwordLabel")}
            mode="unlock"
            value={password()}
            onInput={(v) => setPassword(v)}
            placeholder={t("import.exportGuide.passwordPlaceholder")}
          />
        </div>
      </Show>

      <Show when={error()}>
        {(err) => (
          <div class={styles.errorBlock}>
            <span class={styles.errorTitle}>{err().title}</span>
            <span class={styles.errorDetail}>{err().detail}</span>
            <span class={styles.errorAction}>{err().action}</span>
          </div>
        )}
      </Show>

      <div class={styles.parseRow}>
        <Button
          variant="primary"
          onClick={handleParseClick}
          disabled={!canParse()}
          loading={isParsing()}
        >
          {isParsing() ? t("import.exportGuide.parsing") : t("import.exportGuide.parseExport")}
        </Button>
        <Show when={isParsing()}>
          <Spinner size={16} />
        </Show>
      </div>
    </div>
  );
};
