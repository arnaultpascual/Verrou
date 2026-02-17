import { createSignal, onCleanup, type Accessor } from "solid-js";

export function useMediaQuery(query: string): Accessor<boolean> {
  const mql = window.matchMedia(query);
  const [matches, setMatches] = createSignal(mql.matches);

  const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
  mql.addEventListener("change", handler);
  onCleanup(() => mql.removeEventListener("change", handler));

  return matches;
}
