import { createHmac } from "node:crypto";

// RFC 4648 base32 (no padding needed), as authenticator secrets use.
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(secret: string): Buffer {
  const clean = secret.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

// totp generates the RFC 6238 code for a base32 secret (SHA-1, 6 digits,
// 30-second step) — what the console's authenticator field expects.
export function totp(secret: string, atMs: number = Date.now(), stepSeconds = 30, digits = 6): string {
  const counter = Math.floor(atMs / 1000 / stepSeconds);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  msg.writeUInt32BE(counter % 2 ** 32, 4);

  const digest = createHmac("sha1", base32Decode(secret)).update(msg).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const bin =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return (bin % 10 ** digits).toString().padStart(digits, "0");
}
