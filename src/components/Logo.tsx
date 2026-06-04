import type { Component } from "solid-js";
import { Show } from "solid-js";
import styles from "./Logo.module.css";

export interface LogoProps {
  /** Mark size in px (default 24). */
  size?: number;
  /** Render the "Verrou" wordmark beside the mark. */
  wordmark?: boolean;
  /** Extra class on the wrapper. */
  class?: string;
}

/**
 * Verrou brand logo — the "Lattice Vault" mark (honeycomb of 7 hexagons +
 * central keyhole, an authentic nod to the lattice math behind ML-KEM/ML-DSA),
 * in the electric-blue Cipher accent. Optionally followed by the wordmark.
 *
 * The hex cells follow the surface and the keyhole follows the brand accent,
 * so the mark reads correctly in both dark and light themes.
 */
export const Logo: Component<LogoProps> = (props) => {
  const size = () => props.size ?? 24;
  return (
    <span class={`${styles.logo} ${props.class ?? ""}`}>
      <svg
        width={size()}
        height={size()}
        viewBox="0 0 512 512"
        fill="none"
        role="img"
        aria-label="Verrou"
        class={styles.mark}
      >
        <defs>
          <radialGradient id="verrouGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#3B82F6" stop-opacity="0.40" />
            <stop offset="100%" stop-color="#3B82F6" stop-opacity="0" />
          </radialGradient>
          <linearGradient id="verrouBevel" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#8FB8FF" />
            <stop offset="52%" stop-color="#3B82F6" />
            <stop offset="100%" stop-color="#1E4FB0" />
          </linearGradient>
        </defs>
        <circle cx="256" cy="256" r="220" fill="url(#verrouGlow)" />
        <polygon
          points="476,347 347,476 165,476 36,347 36,165 165,36 347,36 476,165"
          stroke="#3B82F6"
          stroke-width="2.5"
          stroke-opacity="0.28"
          fill="none"
          stroke-linejoin="round"
        />
        <circle
          cx="256"
          cy="256"
          r="158"
          stroke="#3B82F6"
          stroke-width="3"
          stroke-opacity="0.22"
          fill="none"
          stroke-dasharray="4 11"
        />
        <g fill="var(--color-surface-1)" stroke="url(#verrouBevel)" stroke-width="7" stroke-linejoin="round">
          <polygon points="330,110 293,174 219,174 182,110 219,46 293,46" />
          <polygon points="456,183 419,247 345,247 308,183 345,119 419,119" />
          <polygon points="456,329 419,393 345,393 308,329 345,265 419,265" />
          <polygon points="330,402 293,466 219,466 182,402 219,338 293,338" />
          <polygon points="204,329 167,393 93,393 56,329 93,265 167,265" />
          <polygon points="204,183 167,247 93,247 56,183 93,119 167,119" />
          <polygon points="330,256 293,320 219,320 182,256 219,192 293,192" />
        </g>
        <g fill="none" stroke="#2E5AA8" stroke-width="2.5" stroke-opacity="0.7" stroke-linejoin="round">
          <polygon points="318,110 287,164 225,164 194,110 225,56 287,56" />
          <polygon points="444,183 413,237 351,237 320,183 351,129 413,129" />
          <polygon points="444,329 413,383 351,383 320,329 351,275 413,275" />
          <polygon points="318,402 287,456 225,456 194,402 225,348 287,348" />
          <polygon points="192,329 161,383 99,383 68,329 99,275 161,275" />
          <polygon points="192,183 161,237 99,237 68,183 99,129 161,129" />
          <polygon points="318,256 287,310 225,310 194,256 225,202 287,202" />
        </g>
        <circle cx="256" cy="256" r="44" fill="#3B82F6" opacity="0.20" />
        <g fill="var(--color-primary)">
          <circle cx="256" cy="248" r="19" />
          <path d="M248 257 L244 284 L268 284 L264 257 Z" />
        </g>
      </svg>
      <Show when={props.wordmark}>
        <span class={styles.wordmark}>Verrou</span>
      </Show>
    </span>
  );
};
