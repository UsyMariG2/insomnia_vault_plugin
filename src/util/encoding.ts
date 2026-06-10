/**
 * Tiny encoding helpers shared by the auth and vault layers.
 *
 * All functions are pure; they exist mainly so the rest of the code uses
 * consistent base64url semantics (no padding, URL-safe alphabet).
 */

export function toBase64Url(buf: Buffer): string {
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function fromBase64Url(value: string): Buffer {
  const pad = value.length % 4 === 0 ? 0 : 4 - (value.length % 4);
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(normalized, "base64");
}

export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i += 1) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}
