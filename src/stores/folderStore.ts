import { createSignal } from "solid-js";

const [selectedFolderId, setSelectedFolderId] = createSignal<string | null>(null);

export { selectedFolderId, setSelectedFolderId };
