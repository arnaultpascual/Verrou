import type { Component } from "solid-js";
import { createEffect, onCleanup } from "solid-js";
import QRCode from "qrcode";
import styles from "./QrCode.module.css";

export interface QrCodeProps {
  data: string;
  size?: number;
}

export const QrCode: Component<QrCodeProps> = (props) => {
  let canvasRef: HTMLCanvasElement | undefined;

  createEffect(() => {
    const text = props.data;
    const width = props.size ?? 200;

    if (canvasRef && text) {
      QRCode.toCanvas(canvasRef, text, {
        width,
        margin: 2,
        color: { dark: "#1a1a2e", light: "#ffffff" },
      });
    } else if (canvasRef) {
      const ctx = canvasRef.getContext("2d");
      if (ctx) {
        ctx.clearRect(0, 0, canvasRef.width, canvasRef.height);
      }
    }
  });

  onCleanup(() => {
    if (canvasRef) {
      const ctx = canvasRef.getContext("2d");
      if (ctx) {
        ctx.clearRect(0, 0, canvasRef.width, canvasRef.height);
      }
    }
  });

  return <canvas ref={canvasRef} class={styles.canvas} />;
};
