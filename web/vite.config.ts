import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

const outDir = "../internal/server/webui/dist";

// emptyOutDir wipes the tracked .gitkeep that keeps the go:embed path valid
// on a fresh checkout; recreate it after the bundle is written.
function keepEmbedPlaceholder(): Plugin {
  return {
    name: "keep-embed-placeholder",
    closeBundle() {
      writeFileSync(resolve(__dirname, outDir, ".gitkeep"), "");
    },
  };
}

// Build output is embedded into the Go server (internal/server/webui/dist).
export default defineConfig({
  plugins: [react(), keepEmbedPlaceholder()],
  build: {
    outDir,
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/agent": "http://localhost:8080",
    },
  },
});
