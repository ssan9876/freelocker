import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build output is embedded into the Go server (internal/server/webui/dist).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/server/webui/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/agent": "http://localhost:8080",
    },
  },
});
