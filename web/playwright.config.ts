import { defineConfig, devices } from "@playwright/test";

// E2E runs against a live FreeLocker server (Go binary + Postgres), not a
// mock. Point it with E2E_BASE_URL; see e2e/README.md for the runner that
// spins up a throwaway server. The suite assumes a freshly-initialized DB.
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:8080",
    headless: true,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
