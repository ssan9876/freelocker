import { test, expect } from "@playwright/test";
import { totp } from "./totp";

/*
 * Prepares a demo instance to look at by hand: completes first-run setup,
 * enrols MFA, and seeds enough content that the tables are not empty.
 *
 * Prints the TOTP secret at the end, because whoever wants to sign in needs
 * to put it in an authenticator (or generate a code from it). Run through
 * start-demo.ps1, which owns the database and leaves the server up.
 *
 * This is a setup tool, not a test. It lives outside the default Playwright
 * config so CI never collects it.
 */
test("prepare the demo instance", async ({ page }) => {
  const email = "owner@example.com";
  const password = "owner-password-123";

  await page.goto("/");
  await expect(page.getByText("Create your organization")).toBeVisible();
  await page.getByLabel("Organization name").fill("Acme Corp");
  await page.getByLabel("Owner email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create organization" }).click();

  await expect(page.getByText("Sign in to the management console")).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByText("Set up two-factor authentication")).toBeVisible();
  const secret = await page.getByLabel("Setup key").inputValue();
  await page.getByLabel("Authentication code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();

  // Seed by clicking through the nav rather than page.goto: goto resolves on
  // navigation, not on the view being ready, and filling a form immediately
  // after races the render. The smoke suite navigates this way for the same
  // reason.
  await page.getByRole("link", { name: "Groups" }).click();
  await expect(page.getByRole("heading", { name: "Groups" })).toBeVisible();
  for (const name of ["Workstations", "Kiosks", "Finance laptops"]) {
    await page.getByLabel("New group name").fill(name);
    await page.getByRole("button", { name: "Add group" }).click();
    await expect(page.getByRole("cell", { name })).toBeVisible();
  }

  await page.getByRole("link", { name: "Application Control" }).click();
  await expect(page.getByRole("heading", { name: "Application Control" })).toBeVisible();
  for (const name of ["Baseline allowlist", "Finance lockdown"]) {
    await page.getByLabel("New policy name").fill(name);
    await page.getByRole("button", { name: "Create policy" }).click();
    await expect(page.getByRole("cell", { name })).toBeVisible();
  }

  await page.getByRole("link", { name: "Ringfencing" }).click();
  await expect(page.getByRole("heading", { name: "Ringfencing" })).toBeVisible();
  for (const name of ["Office macros", "Browser containment"]) {
    await page.getByLabel("Ringfence name").fill(name);
    await page.getByRole("button", { name: "Create ringfence" }).click();
    await expect(page.getByRole("cell", { name })).toBeVisible();
  }

  await page.getByRole("link", { name: "Alerts" }).click();
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
  const ruleName = page.getByLabel("Rule name");
  if (await ruleName.isVisible().catch(() => false)) {
    await ruleName.fill("High CPU");
    await page.getByRole("button", { name: "Add rule" }).click();
    await expect(page.getByRole("cell", { name: "High CPU" })).toBeVisible();
  }

  console.log("\n================ DEMO READY ================");
  console.log("  URL:      http://localhost:8080");
  console.log(`  Email:    ${email}`);
  console.log(`  Password: ${password}`);
  console.log(`  TOTP key: ${secret}`);
  console.log(`  Code now: ${totp(secret)}  (valid for the current 30s window)`);
  console.log("============================================\n");
});
