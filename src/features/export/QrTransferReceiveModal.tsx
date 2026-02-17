import type { Component } from "solid-js";
import {
  Show,
  createSignal,
  createEffect,
  on,
  onCleanup,
} from "solid-js";
import jsQR from "jsqr";
import { Modal } from "../../components/Modal";
import { SecurityCeremony } from "../../components/SecurityCeremony";
import { Button } from "../../components/Button";
import { Icon } from "../../components/Icon";
import { useToast } from "../../components/useToast";
import { receiveQrTransfer, loadTransferFile } from "./qrTransferIpc";
import { parseUnlockError } from "../vault/ipc";
import { t } from "../../stores/i18nStore";
import styles from "./QrTransferReceiveModal.module.css";

export interface QrTransferReceiveModalProps {
  open: boolean;
  onClose: () => void;
}

type Phase = "code" | "scanning" | "importing" | "complete" | "error" | "camera-denied";

/** Target FPS for QR scanning (~10 FPS). */
const SCAN_INTERVAL_MS = 100;

/** Validate 4 space-separated words. */
function isValidCode(code: string): boolean {
  const words = code.trim().split(/\s+/);
  return words.length === 4 && words.every((w) => w.length > 0);
}

export const QrTransferReceiveModal: Component<QrTransferReceiveModalProps> = (
  props,
) => {
  const toast = useToast();

  // State
  const [phase, setPhase] = createSignal<Phase>("code");
  const [errorMessage, setErrorMessage] = createSignal("");
  const [shake, setShake] = createSignal(false);

  // Code phase
  const [verificationCode, setVerificationCode] = createSignal("");

  // Scanning phase
  const [receivedChunks, setReceivedChunks] = createSignal<Map<number, string>>(new Map());
  const [totalChunks, setTotalChunks] = createSignal(0);
  const [lastChunkIndex, setLastChunkIndex] = createSignal(-1);

  // Importing phase
  const [progress, setProgress] = createSignal(0);

  // Complete phase
  const [importedCount, setImportedCount] = createSignal(0);

  // Refs
  let videoRef: HTMLVideoElement | undefined;
  let canvasRef: HTMLCanvasElement | undefined;
  let mediaStream: MediaStream | null = null;
  let scanRafId: number | undefined;
  let progressInterval: ReturnType<typeof setInterval> | undefined;

  // Start scanning when phase changes to "scanning"
  createEffect(
    on(
      () => phase() === "scanning",
      (active) => {
        if (active) {
          startCamera();
        }
      },
    ),
  );

  onCleanup(() => {
    cleanup();
  });

  function resetState() {
    setPhase("code");
    setErrorMessage("");
    setShake(false);
    setVerificationCode("");
    setReceivedChunks(new Map());
    setTotalChunks(0);
    setLastChunkIndex(-1);
    setProgress(0);
    setImportedCount(0);
    stopCamera();
    if (progressInterval) clearInterval(progressInterval);
  }

  function cleanup() {
    stopCamera();
    if (progressInterval) clearInterval(progressInterval);
  }

  function handleClose() {
    cleanup();
    resetState();
    props.onClose();
  }

  function stopCamera() {
    if (scanRafId != null) {
      cancelAnimationFrame(scanRafId);
      scanRafId = undefined;
    }
    if (mediaStream) {
      for (const track of mediaStream.getTracks()) {
        track.stop();
      }
      mediaStream = null;
    }
  }

  async function startCamera() {
    try {
      mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment", width: { ideal: 640 }, height: { ideal: 480 } },
      });

      if (videoRef) {
        videoRef.srcObject = mediaStream;
        await videoRef.play();
        startScanning();
      }
    } catch {
      setPhase("camera-denied");
    }
  }

  function startScanning() {
    if (!videoRef || !canvasRef) return;

    const canvas = canvasRef;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return;

    let lastScanTime = 0;

    function scanFrame(timestamp: number) {
      if (phase() !== "scanning") return;

      if (timestamp - lastScanTime >= SCAN_INTERVAL_MS) {
        lastScanTime = timestamp;

        if (videoRef && videoRef.readyState === videoRef.HAVE_ENOUGH_DATA) {
          canvas.width = videoRef.videoWidth;
          canvas.height = videoRef.videoHeight;
          ctx!.drawImage(videoRef, 0, 0, canvas.width, canvas.height);

          const imageData = ctx!.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, canvas.width, canvas.height, {
            inversionAttempts: "dontInvert",
          });

          if (code?.data) {
            handleQrData(code.data);
          }
        }
      }

      scanRafId = requestAnimationFrame(scanFrame);
    }

    scanRafId = requestAnimationFrame(scanFrame);
  }

  function handleQrData(data: string) {
    // Each QR code contains a base64-encoded encrypted chunk.
    // The chunk index/total are embedded in the binary header and
    // will be parsed by the Rust backend. Here we use a simple
    // approach: track chunks by their data hash to avoid duplicates.
    // Since we can't parse the binary header in JS, we store chunks
    // by insertion order and rely on the total from the first QR
    // that provides it.

    // Actually, the chunks are base64-encoded. The first 4 bytes of
    // the decoded binary are [index_hi, index_lo, total_hi, total_lo].
    // We can decode enough to get index and total.
    try {
      const binary = atob(data);
      if (binary.length < 4) return;

      const index = (binary.charCodeAt(0) << 8) | binary.charCodeAt(1);
      const total = (binary.charCodeAt(2) << 8) | binary.charCodeAt(3);

      if (total === 0 || index >= total) return;

      setTotalChunks(total);

      setReceivedChunks((prev) => {
        if (prev.has(index)) return prev;
        const next = new Map(prev);
        next.set(index, data);
        return next;
      });
      setLastChunkIndex(index);
    } catch {
      // Invalid base64 or corrupt data — skip this frame
    }
  }

  // Watch for all chunks being received — single reactive trigger point.
  createEffect(
    on(
      () => [receivedChunks().size, totalChunks()] as const,
      ([received, total]) => {
        if (total > 0 && received >= total && phase() === "scanning") {
          stopCamera();
          startImport();
        }
      },
    ),
  );

  function handleCodeSubmit(e: Event) {
    e.preventDefault();
    if (!isValidCode(verificationCode())) return;
    setPhase("scanning");
  }

  function handleDoneScanning() {
    const received = receivedChunks().size;
    const total = totalChunks();

    if (total > 0 && received >= total) {
      stopCamera();
      startImport();
    } else if (total > 0) {
      stopCamera();
      setErrorMessage(
        t("export.qrTransfer.receive.incompleteTransfer", { received: String(received), total: String(total) }),
      );
      setPhase("error");
      setShake(true);
      setTimeout(() => setShake(false), 200);
    } else {
      stopCamera();
      setErrorMessage(t("export.qrTransfer.receive.noQrScanned"));
      setPhase("error");
      setShake(true);
      setTimeout(() => setShake(false), 200);
    }
  }

  async function handleLoadFromFile() {
    if (!isValidCode(verificationCode())) return;

    try {
      const chunks = await loadTransferFile();
      if (!chunks) return; // User cancelled dialog

      startImportWithChunks(chunks);
    } catch (err) {
      const errorStr = typeof err === "string" ? err : String(err);
      setErrorMessage(errorStr);
      setPhase("error");
      setShake(true);
      setTimeout(() => setShake(false), 200);
    }
  }

  async function startImport() {
    // Order chunks by index from the receivedChunks map
    const chunks = receivedChunks();
    const ordered: string[] = [];
    for (let i = 0; i < totalChunks(); i++) {
      const chunk = chunks.get(i);
      if (!chunk) {
        setErrorMessage(t("export.qrTransfer.receive.missingChunk", { index: String(i + 1), total: String(totalChunks()) }));
        setPhase("error");
        setShake(true);
        setTimeout(() => setShake(false), 200);
        return;
      }
      ordered.push(chunk);
    }

    startImportWithChunks(ordered);
  }

  async function startImportWithChunks(ordered: string[]) {
    setPhase("importing");
    setProgress(0);

    progressInterval = setInterval(() => {
      setProgress((prev) => (prev >= 90 ? prev : prev + 5));
    }, 100);

    try {
      const result = await receiveQrTransfer({
        chunks: ordered,
        verificationCode: verificationCode().trim(),
      });

      if (progressInterval) clearInterval(progressInterval);
      setProgress(100);
      await new Promise((r) => setTimeout(r, 300));

      setImportedCount(result.importedCount);
      setPhase("complete");
      toast.success(t("export.qrTransfer.receive.toastImported", { count: String(result.importedCount) }));
    } catch (err) {
      if (progressInterval) clearInterval(progressInterval);
      setProgress(0);

      const errorStr = typeof err === "string" ? err : String(err);
      const parsed = parseUnlockError(errorStr);
      setErrorMessage(parsed.message);
      setPhase("error");
      setShake(true);
      setTimeout(() => setShake(false), 200);
    }
  }

  function handleRetry() {
    resetState();
  }

  return (
    <Modal
      open={props.open}
      onClose={handleClose}
      title={t("export.qrTransfer.receive.title")}
      closeOnOverlayClick={false}
    >
      {/* Phase: Verification code entry */}
      <Show when={phase() === "code"}>
        <form onSubmit={handleCodeSubmit} class={styles.codeForm}>
          <p class={styles.description}>
            {t("export.qrTransfer.receive.codeDescription")}
          </p>
          <input
            type="text"
            class={styles.codeInput}
            value={verificationCode()}
            onInput={(e) => setVerificationCode(e.currentTarget.value)}
            placeholder="word word word word"
            autocomplete="off"
            spellcheck={false}
            data-testid="qr-receive-code-input"
          />
          <p class={styles.codeHint}>
            {t("export.qrTransfer.receive.codeHint")}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button
              variant="ghost"
              disabled={!isValidCode(verificationCode())}
              onClick={handleLoadFromFile}
              data-testid="qr-receive-load-file"
            >
              <Icon name="upload" size={16} /> {t("export.qrTransfer.receive.loadFromFile")}
            </Button>
            <Button
              type="submit"
              disabled={!isValidCode(verificationCode())}
              data-testid="qr-receive-start-scan"
            >
              <Icon name="camera" size={16} /> {t("export.qrTransfer.receive.scanQr")}
            </Button>
          </div>
        </form>
      </Show>

      {/* Phase: Camera scanning */}
      <Show when={phase() === "scanning"}>
        <div class={styles.scanningContent}>
          <div class={styles.videoWrapper}>
            <video ref={videoRef} class={styles.video} playsinline muted aria-label={t("export.qrTransfer.receive.ariaCameraFeed")} />
            <div class={styles.scanOverlay}>
              <div class={styles.scanFrame} />
            </div>
          </div>

          {/* Hidden canvas for frame extraction */}
          <canvas ref={canvasRef} style={{ display: "none" }} />

          <Show when={totalChunks() > 0}>
            <p class={styles.chunkProgress} aria-live="polite">
              {t("export.qrTransfer.receive.chunksReceived", { received: String(receivedChunks().size), total: String(totalChunks()) })}
            </p>
            <div class={styles.progressBar}>
              <div
                class={styles.progressFill}
                style={{
                  width: `${totalChunks() > 0 ? (receivedChunks().size / totalChunks()) * 100 : 0}%`,
                }}
              />
            </div>
          </Show>

          <Show when={totalChunks() === 0}>
            <p class={styles.chunkProgress}>{t("export.qrTransfer.receive.scanning")}</p>
          </Show>

          <Show when={lastChunkIndex() >= 0}>
            <p class={styles.lastScanned}>
              {t("export.qrTransfer.receive.chunkScanned", { index: String(lastChunkIndex() + 1) })}
            </p>
          </Show>

          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button
              onClick={handleDoneScanning}
              data-testid="qr-receive-done-scanning"
            >
              {t("export.qrTransfer.receive.doneScanning")}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: Importing with ceremony */}
      <Show when={phase() === "importing"}>
        <div class={styles.ceremonyWrapper}>
          <SecurityCeremony
            progress={progress()}
            onComplete={() => {}}
          />
        </div>
      </Show>

      {/* Phase: Complete */}
      <Show when={phase() === "complete"}>
        <div class={styles.completeContent}>
          <div class={styles.successIcon}>
            <Icon name="check" size={48} />
          </div>
          <p class={styles.successMessage} data-testid="qr-receive-success">
            {t("export.qrTransfer.receive.transferComplete", { count: String(importedCount()) })}
          </p>
          <div class={styles.actions}>
            <Button onClick={handleClose} data-testid="qr-receive-close">
              {t("common.done")}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: Error */}
      <Show when={phase() === "error"}>
        <div
          class={`${styles.errorContent} ${shake() ? styles.shake : ""}`}
        >
          <p class={styles.error} role="alert" data-testid="qr-receive-error">
            {errorMessage()}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleRetry} data-testid="qr-receive-retry">
              {t("common.tryAgain")}
            </Button>
          </div>
        </div>
      </Show>

      {/* Phase: Camera permission denied */}
      <Show when={phase() === "camera-denied"}>
        <div class={styles.cameraError}>
          <div class={styles.cameraErrorIcon}>
            <Icon name="video-off" size={48} />
          </div>
          <p class={styles.cameraErrorMessage}>
            {t("export.qrTransfer.receive.cameraDenied")}
          </p>
          <div class={styles.actions}>
            <Button variant="ghost" onClick={handleClose}>
              {t("common.cancel")}
            </Button>
            <Button onClick={handleRetry} data-testid="qr-receive-retry-camera">
              {t("common.tryAgain")}
            </Button>
          </div>
        </div>
      </Show>
    </Modal>
  );
};
