import { test, expect } from "@playwright/test";
import { totp } from "./totp";

// Drives the real console served by the Go server against a fresh database:
// first-run setup → sign in → MFA enrollment (the setup key is on screen, so
// the test computes the code itself — see totp.ts) → the console itself,
// exercising the group, alert-rule and admin management screens.
//
// Device-scoped screens (device controls, observed applications with their
// publisher column) need an enrolled agent reporting data, so they stay in
// the Go tests.
test("first-run setup, sign in with MFA, manage groups, rules and admins", async ({ page }) => {
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

  // First login with MFA not yet enrolled shows the setup key; read it and
  // enter the matching code.
  await expect(page.getByText("Set up two-factor authentication")).toBeVisible();
  const secret = await page.getByLabel("Setup key").inputValue();
  expect(secret).not.toBe("");
  await page.getByLabel("Authentication code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();

  // We are in the console.
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();

  // Groups: create, rename, delete.
  await page.getByRole("link", { name: "Groups" }).click();
  await expect(page.getByRole("heading", { name: "Groups" })).toBeVisible();
  await page.getByLabel("New group name").fill("Workstations");
  await page.getByRole("button", { name: "Add group" }).click();
  await expect(page.getByRole("cell", { name: "Workstations" })).toBeVisible();

  await page.getByRole("button", { name: "Rename" }).click();
  await page.getByLabel("Group name", { exact: true }).fill("Laptops");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name: "Laptops" })).toBeVisible();

  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("Delete group")).toBeVisible(); // confirmation
  await page.getByRole("button", { name: "Delete" }).last().click();
  await expect(page.getByRole("cell", { name: "Laptops" })).toHaveCount(0);

  // Alert rules: create, edit, disable.
  await page.getByRole("link", { name: "Alerts" }).click();
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
  await page.getByLabel("Name", { exact: true }).fill("High CPU");
  await page.getByLabel("Threshold %", { exact: true }).fill("90");
  await page.getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByRole("cell", { name: "High CPU" })).toBeVisible();

  await page.getByRole("button", { name: "Edit" }).click();
  await page.getByLabel("Rule name").fill("CPU saturated");
  await page.getByLabel("Threshold", { exact: true }).fill("80");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("cell", { name: "CPU saturated" })).toBeVisible();
  await expect(page.getByText("cpu > 80%")).toBeVisible();

  await page.getByLabel("Rule CPU saturated state").selectOption("off");
  await expect(page.getByLabel("Rule CPU saturated state")).toHaveValue("off");

  // Admins: add one, change its role, disable and re-enable it.
  await page.getByRole("link", { name: "Admins" }).click();
  await expect(page.getByRole("heading", { name: "Admins" })).toBeVisible();
  await page.getByLabel("Email", { exact: true }).fill("ops@example.com");
  await page.getByLabel("Temporary password").fill("ops-password-1234");
  await page.getByLabel("Role", { exact: true }).selectOption("readonly");
  await page.getByRole("button", { name: "Add admin" }).click();
  await expect(page.getByRole("cell", { name: "ops@example.com" })).toBeVisible();

  const roleSelect = page.getByLabel("Role for ops@example.com");
  await roleSelect.selectOption("admin");
  await expect(roleSelect).toHaveValue("admin");

  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByRole("button", { name: "Enable" })).toBeVisible();
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByRole("button", { name: "Disable" })).toBeVisible();

  // Approvals loads (empty until an agent reports a block).
  await page.getByRole("link", { name: "Approvals" }).click();
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible();
  await expect(page.getByText("No pending requests.")).toBeVisible();
});
