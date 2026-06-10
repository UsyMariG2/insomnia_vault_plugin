/**
 * Legacy vault decryption + migration round-trip.
 *
 * Synthesizes a legacy vault file using the original algorithm
 * (HMAC-SHA256 key derivation + AES-256-CTR) so we don't need an actual
 * fixture from disk, and verifies our reader recovers the entries.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createCipheriv, createHmac, randomBytes } from "node:crypto";
import { decryptLegacy, legacyToEntries } from "../src/migrate/legacy-vault";

function legacyEncrypt(plaintext: string, password: string): string {
  const key = createHmac("sha256", password).digest();
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return `${iv.toString("hex")}:${enc.toString("hex")}`;
}

const legacyJson = JSON.stringify({
  "you": { ac1: "MY-AC1", ac2: "MY-AC2", oidcServer: "https://oidc.example.com" },
  "bot": { ac1: "BOT-AC1", ac2: "BOT-AC2" },
});

test("decryptLegacy reads back what legacyEncrypt wrote", () => {
  const file = legacyEncrypt(legacyJson, "old-password");
  const out = decryptLegacy(file, "old-password");
  assert.equal(out.you?.ac1, "MY-AC1");
  assert.equal(out.you?.ac2, "MY-AC2");
  assert.equal(out.bot?.ac1, "BOT-AC1");
});

test("decryptLegacy with wrong password produces invalid JSON and throws", () => {
  const file = legacyEncrypt(legacyJson, "right-password");
  assert.throws(
    () => decryptLegacy(file, "wrong-password"),
    /invalid JSON/i,
  );
});

test("legacyToEntries normalizes missing oidcServer to the default Plus4U URL", () => {
  const legacy = {
    user1: { ac1: "1", ac2: "2" },
    user2: { ac1: "a", ac2: "b", oidcServer: "https://custom.example/oidc" },
  };
  const entries = legacyToEntries(legacy);
  const byId = new Map(entries.map((e) => [e.identification, e.entry]));
  assert.equal(byId.get("user1")?.oidcServer.startsWith("https://uuidentity.plus4u.net/"), true);
  assert.equal(byId.get("user2")?.oidcServer, "https://custom.example/oidc");
  assert.equal(byId.get("user1")?.meta?.migratedFrom, "oidc-plus4u-vault");
});

test("malformed legacy file is rejected with a clear error", () => {
  assert.throws(() => decryptLegacy("no-colon-here", "pw"), /malformed/i);
});
