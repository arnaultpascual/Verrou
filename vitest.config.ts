import { defineConfig } from "vitest/config";
import solid from "vite-plugin-solid";

export default defineConfig({
  plugins: [solid()],
  test: {
    environment: "jsdom",
    globals: true,
    css: true,
    setupFiles: ["./src/test-setup.ts"],
  },
  resolve: {
    conditions: ["development", "browser"],
  },
});
