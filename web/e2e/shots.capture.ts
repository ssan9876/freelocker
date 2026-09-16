import { test, expect } from "@playwright/test";
import { totp } from "./totp";

/*
 * Screenshot pass for reviewing the console's visual design.
 *
 * Not part of the regression suite and not run in CI: it asserts nothing about
 * behaviour, it just drives a fresh install and captures each screen so the
 * design can be looked at rather than assumed.
 *
 * Run it with: npx playwright test e2e/shots.spec.ts --grep @shots
 * against a server on a freshly created database.
 */
test("@shots capture console screens", async ({ page }) => {
  const email = "owner@example.com";
  const password = "owner-password-123";
  const dir = "e2e/__shots__";

  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/");

  // The database may already be initialised from an earlier run, in which
  // case setup is skipped and we land straight on sign-in.
  // waitFor, not isVisible: isVisible checks instantly and would race the
  // navigation, silently skipping the branch we are here to capture.
  const seen = async (l: ReturnType<typeof page.getByText>) =>
    await l
      .waitFor({ state: "visible", timeout: 6000 })
      .then(() => true)
      .catch(() => false);

  const setup = page.getByText("Create your organization");
  if (await seen(setup)) {
    await page.screenshot({ path: `${dir}/01-setup.png` });
    await page.getByLabel("Organization name").fill("Acme");
    await page.getByLabel("Owner email").fill(email);
    await page.getByLabel("Password").fill(password);
    await page.getByRole("button", { name: "Create organization" }).click();
  }

  await expect(page.getByText("Sign in to the management console")).toBeVisible();
  await page.screenshot({ path: `${dir}/02-signin.png` });

  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Continue" }).click();

  const enrol = page.getByText("Set up two-factor authentication");
  let secret = "";
  if (await seen(enrol)) {
    await page.screenshot({ path: `${dir}/03-mfa.png` });
    secret = await page.getByLabel("Setup key").inputValue();
    await page.getByLabel("Authentication code").fill(totp(secret));
    await page.getByRole("button", { name: "Verify" }).click();
  }

  // Verify either lands us in the console or bounces to a sign-in code
  // prompt. Wait for the console FIRST: checking for the prompt first matches
  // the enrolment page's own wording before it navigates away, and then waits
  // on a field that is already gone.
  const devicesHeading = page.getByRole("heading", { name: "Devices" });
  const inConsole = await devicesHeading
    .waitFor({ state: "visible", timeout: 8000 })
    .then(() => true)
    .catch(() => false);

  if (!inConsole && secret) {
    // Reusing the enrolment code is refused -- the server will not accept the
    // same TOTP twice, which is replay protection doing its job -- so wait for
    // the next 30-second window and compute a fresh one.
    const msIntoStep = Date.now() % 30000;
    await page.waitForTimeout(30000 - msIntoStep + 1000);
    await page.getByLabel("Authentication code").fill(totp(secret));
    await page.getByRole("button", { name: /Verify|Continue|Sign in/ }).click();
  }

  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();

  // Deliberately NOT seeding content through the UI here. Driving the create
  // forms made this spec fail for reasons that had nothing to do with the
  // design it exists to show, and the smoke suite already covers those flows.
  // Empty states are worth reviewing on their own account anyway.

  const screens: [string, string][] = [
    ["04-devices", "/devices"],
    ["05-policies", "/policies"],
    ["06-ringfences", "/ringfences"],
    ["07-blocks", "/blocks"],
    ["08-approvals", "/approvals"],
    ["09-alerts", "/alerts"],
    ["10-activity", "/activity"],
    ["11-groups", "/groups"],
    ["12-notifications", "/notifications"],
    ["13-audit", "/audit"],
  ];

  for (const [name, path] of screens) {
    await page.goto(path);
    // The pages poll on an interval; a short settle avoids catching a
    // half-rendered loading state in the shot.
    await page.waitForTimeout(400);
    await page.screenshot({ path: `${dir}/${name}.png` });
  }

  // And the light theme, which has to stand on its own.
  await page.goto("/devices");
  await page.getByRole("button", { name: /Light|Dark/ }).click();
  await page.waitForTimeout(300);
  await page.screenshot({ path: `${dir}/14-devices-light.png` });
});
