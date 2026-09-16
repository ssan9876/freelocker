import { defineConfig, devices } from "@playwright/test";

/*
 * Config for the demo-instance setup tool (e2e/demo.setup.ts).
 *
 * Separate from playwright.config.ts so CI never collects it: it is not a
 * test, it seeds an instance for a human to look at.
 */
export default defineConfig({
  testDir: "./e2e",
  testMatch: /demo\.setup\.ts/,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:8080",
    headless: true,
    viewport: { width: 1440, height: 900 },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
