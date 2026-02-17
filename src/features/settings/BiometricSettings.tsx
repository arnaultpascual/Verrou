import type { Component } from "solid-js";
import { createSignal, createResource, Show, onCleanup } from "solid-js";
import { Switch } from "@kobalte/core/switch";
import {
  PasswordInput,
  Button,
  Spinner,
  useToast,
} from "../../components";
import {
  isBiometricAvailable as platformBiometricAvailable,
  biometricProviderName as platformBiometricProvider,
} from "../../stores/platformStore";
import {
  checkBiometricAvailability,
  enrollBiometric,
  revokeBiometric,
} from "../vault/biometricIpc";
import { parseUnlockError } from "../vault/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./BiometricSettings.module.css";

type BiometricPhase =
  | "idle"
  | "reauth-enroll"   // Re-auth before enrollment
  | "enrolling"        // Enrollment in progress
  | "reauth-revoke"   // Re-auth before revocation
  | "revoking";        // Revocation in progress

export const BiometricSettings: Component = () => {
  const toast = useToast();

  // Enrollment status is queried live (can change during session).
  const [enrollment, { refetch }] = createResource(checkBiometricAvailability);
  const [phase, setPhase] = createSignal<BiometricPhase>("idle");
  const [password, setPassword] = createSignal("");
  const [errorMessage, setErrorMessage] = createSignal("");
  const [shake, setShake] = createSignal(false);

  onCleanup(() => {
    setPassword("");
  });

  const triggerShake = () => {
    setShake(true);
    setTimeout(() => setShake(false), 200);
  };

  const resetFlow = () => {
    setPhase("idle");
    setPassword("");
    setErrorMessage("");
  };

  const handleToggle = (checked: boolean) => {
    if (phase() !== "idle") return;
    if (checked) {
      setPhase("reauth-enroll");
    } else {
      setPhase("reauth-revoke");
    }
    setPassword("");
    setErrorMessage("");
  };

  const handleEnrollSubmit = async (e: Event) => {
    e.preventDefault();
    if (!password() || phase() !== "reauth-enroll") return;

    setPhase("enrolling");
    setErrorMessage("");

    try {
      await enrollBiometric(password());
      await refetch();
      toast.success(t("settings.biometric.enableSuccess"));
      resetFlow();
    } catch (err) {
      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setErrorMessage(parsed.message);

      if (parsed.code === "RATE_LIMITED") {
        setPhase("reauth-enroll");
      } else if (parsed.code === "INVALID_PASSWORD") {
        setPhase("reauth-enroll");
        triggerShake();
      } else {
        // BIOMETRIC_CANCELLED, BIOMETRIC_FAILED, etc. — revert
        toast.error(parsed.message);
        resetFlow();
      }
    }
  };

  const handleRevokeSubmit = async (e: Event) => {
    e.preventDefault();
    if (!password() || phase() !== "reauth-revoke") return;

    setPhase("revoking");
    setErrorMessage("");

    try {
      await revokeBiometric(password());
      await refetch();
      toast.success(t("settings.biometric.disableSuccess"));
      resetFlow();
    } catch (err) {
      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setErrorMessage(parsed.message);

      if (parsed.code === "RATE_LIMITED") {
        setPhase("reauth-revoke");
      } else if (parsed.code === "INVALID_PASSWORD") {
        setPhase("reauth-revoke");
        triggerShake();
      } else {
        toast.error(parsed.message);
        resetFlow();
      }
    }
  };

  // Hardware availability from platform store (instant, no IPC).
  const isAvailable = () => platformBiometricAvailable();
  const isEnrolled = () => enrollment()?.enrolled ?? false;
  const providerName = () => platformBiometricProvider();
  const isOperating = () =>
    phase() === "enrolling" || phase() === "revoking";
  const isLoading = () => enrollment.loading;

  return (
    <div class={styles.biometricSection} data-testid="biometric-settings">
      <div class={styles.header}>
        <div class={styles.headerInfo}>
          <h3 class={styles.title} id="biometric-switch-label">{t("settings.biometric.title")}</h3>
          <Show when={!isLoading()} fallback={
            <p class={styles.status}>{t("settings.biometric.checkingAvailability")}</p>
          }>
            <Show
              when={isAvailable()}
              fallback={
                <p class={styles.unavailableMessage}>
                  {t("settings.biometric.unavailable")}
                </p>
              }
            >
              <p
                class={`${styles.status} ${isEnrolled() ? styles.statusEnabled : ""}`}
                data-testid="biometric-status"
              >
                {isEnrolled()
                  ? t("settings.biometric.enrolledStatus", { provider: providerName() })
                  : t("settings.biometric.notEnrolled")}
              </p>
            </Show>
          </Show>
        </div>

        <div title={!isAvailable() && !isLoading() ? t("settings.biometric.unavailable") : undefined}>
          <Switch
            checked={isEnrolled()}
            onChange={handleToggle}
            disabled={!isAvailable() || isOperating() || isLoading()}
            class={styles.switchRoot}
            data-testid="biometric-toggle"
            aria-labelledby="biometric-switch-label"
          >
            <Switch.Input />
            <Switch.Control class={styles.switchControl}>
              <Switch.Thumb class={styles.switchThumb} />
            </Switch.Control>
          </Switch>
        </div>
      </div>

      {/* Re-auth for enrollment */}
      <Show when={phase() === "reauth-enroll"}>
        <div class={`${styles.reAuthFlow} ${shake() ? styles.shake : ""}`}>
          <h4 class={styles.reAuthHeading}>{t("settings.biometric.enableHeading", { provider: providerName() })}</h4>
          <p class={styles.reAuthDescription}>
            {t("settings.biometric.enableDescription")}
          </p>

          <form class={styles.form} onSubmit={handleEnrollSubmit}>
            <PasswordInput
              label={t("settings.biometric.passwordLabel")}
              mode="unlock"
              value={password()}
              onInput={setPassword}
              placeholder={t("settings.biometric.passwordPlaceholder")}
              id="biometric-enroll-password"
            />

            <Show when={errorMessage()}>
              <p class={styles.error} role="alert" data-testid="biometric-error">
                {errorMessage()}
              </p>
            </Show>

            <div class={styles.formActions}>
              <Button variant="ghost" onClick={resetFlow}>
                {t("settings.biometric.cancel")}
              </Button>
              <Button
                type="submit"
                disabled={!password()}
                data-testid="biometric-enroll-btn"
              >
                {t("settings.biometric.enableButton", { provider: providerName() })}
              </Button>
            </div>
          </form>
        </div>
      </Show>

      {/* Re-auth for revocation */}
      <Show when={phase() === "reauth-revoke"}>
        <div class={`${styles.reAuthFlow} ${shake() ? styles.shake : ""}`}>
          <h4 class={styles.reAuthHeading}>{t("settings.biometric.disableHeading", { provider: providerName() })}</h4>
          <p class={styles.reAuthDescription}>
            {t("settings.biometric.disableDescription")}
          </p>

          <form class={styles.form} onSubmit={handleRevokeSubmit}>
            <PasswordInput
              label={t("settings.biometric.passwordLabel")}
              mode="unlock"
              value={password()}
              onInput={setPassword}
              placeholder={t("settings.biometric.passwordPlaceholder")}
              id="biometric-revoke-password"
            />

            <Show when={errorMessage()}>
              <p class={styles.error} role="alert" data-testid="biometric-error">
                {errorMessage()}
              </p>
            </Show>

            <div class={styles.formActions}>
              <Button variant="ghost" onClick={resetFlow}>
                {t("settings.biometric.cancel")}
              </Button>
              <Button
                type="submit"
                disabled={!password()}
                data-testid="biometric-revoke-btn"
              >
                {t("settings.biometric.disableButton", { provider: providerName() })}
              </Button>
            </div>
          </form>
        </div>
      </Show>

      {/* Operation in progress */}
      <Show when={isOperating()}>
        <div class={styles.operationStatus}>
          <Spinner size={14} />
          <span>
            {phase() === "enrolling" ? t("settings.biometric.enrolling") : t("settings.biometric.revoking")}
          </span>
        </div>
      </Show>
    </div>
  );
};
