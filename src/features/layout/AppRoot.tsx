import type { Component, JSX } from "solid-js";
import { onMount, Show } from "solid-js";
import { ToastProvider } from "../../components";
import { initPlatformCapabilities } from "../../stores/platformStore";
import { initPreferences, currentLanguage } from "../../stores/preferencesStore";
import { initI18n } from "../../stores/i18nStore";
import { initVaultState, isVaultInitialized } from "../../stores/vaultStore";

export const AppRoot: Component<{ children?: JSX.Element }> = (props) => {
  onMount(() => {
    initPlatformCapabilities();
    initVaultState();
    // i18n needs saved language from preferences — chain after init
    initPreferences().then(() => {
      initI18n(currentLanguage());
    });
  });

  return (
    <ToastProvider>
      <Show when={isVaultInitialized()}>
        {props.children}
      </Show>
    </ToastProvider>
  );
};
