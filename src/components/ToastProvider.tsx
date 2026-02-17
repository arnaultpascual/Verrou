import type { Component, JSX } from "solid-js";
import { Region, List } from "@kobalte/core/toast";
import styles from "./Toast.module.css";

export interface ToastProviderProps {
  children: JSX.Element;
}

/**
 * ToastProvider — wraps the app root.
 * Renders Kobalte Toast.Region + Toast.List at bottom-center.
 * Default duration: 3000ms (overridden per-toast for success=1000ms, error=persistent).
 * Max 3 visible toasts.
 */
export const ToastProvider: Component<ToastProviderProps> = (props) => {
  return (
    <>
      {props.children}
      <Region duration={3000} limit={3} topLayer>
        <List class={styles.list} />
      </Region>
    </>
  );
};
