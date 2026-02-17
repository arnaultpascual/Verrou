import type { Component } from "solid-js";
import { Show } from "solid-js";
import { Modal } from "../../components/Modal";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { t } from "../../stores/i18nStore";
import styles from "./ConfirmDeleteModal.module.css";

export interface ConfirmDeleteModalProps {
  open: boolean;
  entryName: string;
  loading?: boolean;
  linkedRecoveryCount?: number;
  onConfirm: () => void;
  onCancel: () => void;
}

export const ConfirmDeleteModal: Component<ConfirmDeleteModalProps> = (props) => {
  return (
    <Modal
      open={props.open}
      onClose={props.onCancel}
      title={t("entries.delete.title")}
      closeOnOverlayClick={false}
      actions={
        <>
          <Button variant="ghost" onClick={props.onCancel} disabled={props.loading}>
            {t("common.cancel")}
          </Button>
          <Button variant="danger" onClick={props.onConfirm} loading={props.loading}>
            {t("common.delete")}
          </Button>
        </>
      }
    >
      <p class={styles.body}>
        {t("entries.delete.message", { name: props.entryName })}
      </p>
      <Show when={(props.linkedRecoveryCount ?? 0) > 0}>
        <div class={styles.cascadeWarning} role="alert">
          <Icon name="alert-triangle" size={16} />
          <span>
            {t("entries.delete.cascadeMessage", { count: String(props.linkedRecoveryCount) })}
          </span>
        </div>
      </Show>
    </Modal>
  );
};
