import { defineConfig } from "vite";

// Tauri dev server contract: fixed port, no auto-open, ignore src-tauri.
export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
  },
  build: { target: "es2022", sourcemap: true },
});
