import type { Component } from "solid-js";
import { Show, createSignal } from "solid-js";
import { Modal } from "../../components/Modal";
import { ReAuthPrompt } from "../../components/ReAuthPrompt";
import { Button } from "../../components/Button";
import { useToast } from "../../components/useToast";
import { deleteSeedPhrase } from "./ipc";
import { t } from "../../stores/i18nStore";
import styles from "./ConfirmDeleteSeedModal.module.css";

export interface ConfirmDeleteSeedModalProps {
  open: boolean;
  entryId: string;
  walletName: string;
  onDeleted: () => void;
  onCancel: () => void;
}

export const ConfirmDeleteSeedModal: Component<ConfirmDeleteSeedModalProps> = (props) => {
  const toast = useToast();
  const [showReAuth, setShowReAuth] = createSignal(false);
  const [isDeleting, setIsDeleting] = createSignal(false);

  const handleDeleteClick = () => {
    setShowReAuth(true);
  };

  const handleVerified = async (password: string) => {
    setShowReAuth(false);
    setIsDeleting(true);
    try {
      await deleteSeedPhrase(props.entryId, password);
      toast.success(t("seed.delete.success", { name: props.walletName }));
      props.onDeleted();
    } catch (err) {
      const msg = typeof err === "string" ? err : t("seed.delete.error");
      toast.error(msg);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleCancel = () => {
    setShowReAuth(false);
    props.onCancel();
  };

  return (
    <>
      <Modal
        open={props.open}
        onClose={handleCancel}
        title={t("seed.delete.title")}
        closeOnOverlayClick={false}
        actions={
          <>
            <Button variant="ghost" onClick={handleCancel} disabled={isDeleting()}>
              {t("seed.delete.cancel")}
            </Button>
            <Button
              variant="danger"
              onClick={handleDeleteClick}
              loading={isDeleting()}
              data-testid="confirm-delete-seed-btn"
            >
              {t("seed.delete.confirm")}
            </Button>
          </>
        }
      >
        <p class={styles.body} data-testid="confirm-delete-seed-body">
          {t("seed.delete.bodyPrefix")}{" "}
          <span class={styles.walletName}>{props.walletName}</span>?{" "}
          {t("seed.delete.bodyMessage")}{" "}
          <span class={styles.warning}>{t("seed.delete.cannotUndo")}</span>
        </p>
      </Modal>

      <ReAuthPrompt
        open={showReAuth()}
        onClose={() => setShowReAuth(false)}
        onVerified={handleVerified}
      />
    </>
  );
};
