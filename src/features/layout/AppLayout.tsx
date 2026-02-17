import type { Component, JSX } from "solid-js";
import { onMount, onCleanup, createEffect } from "solid-js";
import { Header } from "./Header";
import { Sidebar } from "./Sidebar";
import { Footer } from "./Footer";
import { sidebarCollapsed, setSidebarCollapsed, toggleSidebar } from "../../stores/sidebarStore";
import { useMediaQuery } from "../../hooks/useMediaQuery";
import styles from "./AppLayout.module.css";

export const AppLayout: Component<{ children?: JSX.Element }> = (props) => {
  const isNarrow = useMediaQuery("(max-width: 959px)");
  // Tech debt: plain JS variable outside reactivity. Resets on re-mount.
  // Acceptable for current scope; revisit in Epic 4 if responsive behavior grows.
  let userOverride = false;

  createEffect(() => {
    if (isNarrow()) {
      if (!userOverride) {
        setSidebarCollapsed(true);
      }
    } else {
      userOverride = false;
    }
  });

  const handleToggle = () => {
    if (isNarrow()) {
      userOverride = true;
    }
    toggleSidebar();
  };

  const handleKeydown = (e: KeyboardEvent) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "b") {
      e.preventDefault();
      handleToggle();
    }
  };

  onMount(() => window.addEventListener("keydown", handleKeydown));
  onCleanup(() => window.removeEventListener("keydown", handleKeydown));

  return (
    <div
      class={styles.shell}
      data-collapsed={sidebarCollapsed() ? "true" : undefined}
    >
      <a href="#main-content" class={styles.skipLink}>
        Skip to main content
      </a>
      <Header />
      <Sidebar collapsed={sidebarCollapsed()} onToggle={handleToggle} />
      <main id="main-content" class={styles.main}>
        <div class={styles.content}>{props.children}</div>
      </main>
      <Footer />
    </div>
  );
};
