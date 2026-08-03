// Throwaway config: build the desktop frontend against mock Tauri APIs so a
// plain browser can drive it (see scratchpad/harness/). Not used by the app.
import { defineConfig } from "vite";

const HARNESS =
  "/tmp/claude-1002/-home-development-sites-holdfast/a4077691-813a-4939-b413-81d891c0b3a7/scratchpad/harness";

export default defineConfig({
  resolve: {
    alias: {
      "@tauri-apps/api/core": `${HARNESS}/mock-tauri-core.ts`,
      "@tauri-apps/api/event": `${HARNESS}/mock-tauri-event.ts`,
    },
  },
  build: {
    outDir: `${HARNESS}/dist`,
    emptyOutDir: true,
  },
});
