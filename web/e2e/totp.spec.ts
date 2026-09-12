import { test, expect } from "@playwright/test";
import { base32Decode, totp } from "./totp";

// RFC 6238 test vector: the ASCII secret "12345678901234567890" (base32
// below) at T = 59s produces 94287082 with SHA-1. If this fails, a failing
// sign-in in the smoke test is this helper's fault, not the console's.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("base32 decodes the RFC 6238 secret", () => {
  expect(base32Decode(RFC_SECRET).toString()).toBe("12345678901234567890");
});

test("totp matches the RFC 6238 vector", () => {
  expect(totp(RFC_SECRET, 59 * 1000, 30, 8)).toBe("94287082");
});

test("totp produces six digits and changes across a step boundary", () => {
  const a = totp(RFC_SECRET, 0);
  const b = totp(RFC_SECRET, 60 * 1000);
  expect(a).toMatch(/^\d{6}$/);
  expect(b).toMatch(/^\d{6}$/);
  expect(a).not.toBe(b);
});
