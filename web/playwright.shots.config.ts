import { defineConfig, devices } from "@playwright/test";

/*
 * Separate config for the screenshot capture, which is a design-review tool
 * rather than a test: it asserts nothing about behaviour and there are no
 * reference images.
 *
 * It lives outside the default config on purpose. The capture file is named
 * .capture.ts so playwright.config.ts never collects it, and CI keeps running
 * only the real suite -- a capture running in CI would burn a minute and could
 * fail on TOTP timing without telling anyone anything useful.
 *
 * Driven by e2e/capture-shots.ps1, which owns the throwaway database and
 * server the capture needs.
 */
export default defineConfig({
  testDir: "./e2e",
  testMatch: /shots\.capture\.ts/,
  fullyParallel: false,
  retries: 0,
  timeout: 120_000,
  reporter: [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:8080",
    headless: true,
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
