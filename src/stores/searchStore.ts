import { createSignal } from "solid-js";

const [query, setQuery] = createSignal("");

export function searchQuery(): string {
  return query();
}

export function setSearchQuery(value: string): void {
  setQuery(value);
}

export function clearSearch(): void {
  setQuery("");
}
