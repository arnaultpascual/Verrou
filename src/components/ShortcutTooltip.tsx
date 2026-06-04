import type { Component, JSX } from "solid-js";
import { For } from "solid-js";
import {
  Root as TooltipRoot,
  Trigger as TooltipTrigger,
  Portal as TooltipPortal,
  Content as TooltipContent,
  Arrow as TooltipArrow,
} from "@kobalte/core/tooltip";
import styles from "./ShortcutTooltip.module.css";

export interface ShortcutTooltipProps {
  /** Keyboard shortcut text to display (e.g. "Ctrl+B") */
  shortcut: string;
  /** The trigger element */
  children: JSX.Element;
}

export const ShortcutTooltip: Component<ShortcutTooltipProps> = (props) => {
  // Split "Ctrl+Shift+L" into individual keycaps, keeping the "+" as a
  // visible separator between them.
  const keys = () => props.shortcut.split("+");

  return (
    <TooltipRoot>
      <TooltipTrigger as="span" class={styles.trigger}>
        {props.children}
      </TooltipTrigger>
      <TooltipPortal>
        <TooltipContent class={styles.tooltipContent}>
          <span class={styles.keys}>
            <For each={keys()}>
              {(key, index) => (
                <>
                  {index() > 0 && <span class={styles.separator}>+</span>}
                  <kbd class={styles.key}>{key}</kbd>
                </>
              )}
            </For>
          </span>
          <TooltipArrow />
        </TooltipContent>
      </TooltipPortal>
    </TooltipRoot>
  );
};
