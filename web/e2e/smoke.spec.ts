import { test, expect } from "@playwright/test";

// Drives the real console served by the Go server against a fresh database:
// first-run setup → sign in → the MFA-enrollment screen. This exercises the
// SPA load, client routing, and the setup/login API round-trips end to end.
// Stops before the TOTP code (that needs a shared secret; covered by the
// server's Go tests).
test("first-run setup, sign in, reach MFA enrollment", async ({ page }) => {
  const email = "owner@example.com";
  const password = "owner-password-123";

  // Setup screen.
  await page.goto("/");
  await expect(page.getByText("Create your organization")).toBeVisible();
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByLabel("Owner email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create organization" }).click();

  // After setup the app routes to the sign-in screen.
  await expect(page.getByText("Sign in to the management console")).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Continue" }).click();

  // First login with MFA not yet enrolled shows the setup key.
  await expect(page.getByText("Set up two-factor authentication")).toBeVisible();
  await expect(page.getByLabel("Setup key")).toBeVisible();
});
