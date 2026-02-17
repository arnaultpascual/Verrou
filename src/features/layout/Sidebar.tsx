import type { Component } from "solid-js";
import { For, Show } from "solid-js";
import { A, useLocation } from "@solidjs/router";
import { Icon, type IconName, ShortcutTooltip } from "../../components";
import { FolderSection } from "../folders/FolderSection";
import { selectedFolderId, setSelectedFolderId } from "../../stores/folderStore";
import { t } from "../../stores/i18nStore";
import styles from "./Sidebar.module.css";

interface NavItem {
  labelKey: string;
  href: string;
  icon: IconName;
}

const NAV_ITEMS: NavItem[] = [
  { labelKey: "sidebar.all", href: "/entries", icon: "list" },
  { labelKey: "sidebar.totp", href: "/entries?type=totp", icon: "lock" },
  { labelKey: "sidebar.seeds", href: "/entries?type=seed", icon: "shield" },
  { labelKey: "sidebar.recovery", href: "/entries?type=recovery", icon: "shield" },
  { labelKey: "sidebar.notes", href: "/entries?type=note", icon: "info" },
  { labelKey: "sidebar.passwords", href: "/entries?type=credential", icon: "key" },
  { labelKey: "sidebar.health", href: "/password-health", icon: "heart" },
  { labelKey: "sidebar.import", href: "/import", icon: "plus" },
];

export interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
}

export const Sidebar: Component<SidebarProps> = (props) => {
  const location = useLocation();

  const isActive = (href: string): boolean => {
    if (href === "/entries") {
      return location.pathname === "/entries" && !location.search;
    }
    return location.pathname + location.search === href;
  };

  return (
    <nav
      class={styles.sidebar}
      data-collapsed={props.collapsed ? "true" : undefined}
      aria-label={t("sidebar.navigation")}
    >
      <div class={styles.header}>
        <Show when={!props.collapsed}>
          <span class={styles.sectionLabel}>{t("sidebar.navigation")}</span>
        </Show>
        <ShortcutTooltip shortcut="Ctrl+B">
          <button
            class={styles.collapseBtn}
            onClick={props.onToggle}
            aria-label={props.collapsed ? t("sidebar.expandSidebar") : t("sidebar.collapseSidebar")}
            type="button"
          >
            <Icon
              name="chevron-right"
              size={16}
              class={props.collapsed ? styles.chevronCollapsed : styles.chevronExpanded}
            />
          </button>
        </ShortcutTooltip>
      </div>

      <ul class={styles.navList} role="list">
        <For each={NAV_ITEMS}>
          {(item) => (
            <li>
              <A
                href={item.href}
                class={`${styles.navItem} ${isActive(item.href) ? styles.active : ""}`}
                title={props.collapsed ? t(item.labelKey) : undefined}
                aria-current={isActive(item.href) ? "page" : undefined}
              >
                <Icon name={item.icon} size={18} />
                <Show when={!props.collapsed}>
                  <span class={styles.navLabel}>{t(item.labelKey)}</span>
                </Show>
              </A>
            </li>
          )}
        </For>
      </ul>

      <div class={styles.foldersSection}>
        <Show when={!props.collapsed}>
          <span class={styles.sectionLabel}>{t("sidebar.folders")}</span>
        </Show>
        <FolderSection
          selectedFolderId={selectedFolderId()}
          onSelectFolder={setSelectedFolderId}
          collapsed={props.collapsed}
        />
      </div>
    </nav>
  );
};
