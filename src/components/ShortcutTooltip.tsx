import type { Component, JSX } from "solid-js";
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
  return (
    <TooltipRoot>
      <TooltipTrigger as="span" class={styles.trigger}>
        {props.children}
      </TooltipTrigger>
      <TooltipPortal>
        <TooltipContent class={styles.tooltipContent}>
          {props.shortcut}
          <TooltipArrow />
        </TooltipContent>
      </TooltipPortal>
    </TooltipRoot>
  );
};
