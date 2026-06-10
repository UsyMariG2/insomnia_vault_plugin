/**
 * KDF parameter handling and floor checks.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  DEFAULT_PBKDF2_PARAMS,
  DEFAULT_SCRYPT_PARAMS,
  deriveKey,
  headerToParams,
  paramsToHeader,
} from "../src/vault/kdf";

test("scrypt derives a stable 32-byte key for the same password and salt", async () => {
  const salt = randomBytes(32);
  const a = await deriveKey("hunter2-correct-horse", salt, DEFAULT_SCRYPT_PARAMS);
  const b = await deriveKey("hunter2-correct-horse", salt, DEFAULT_SCRYPT_PARAMS);
  assert.equal(a.length, 32);
  assert.deepEqual(a, b);
});

test("scrypt produces different keys for the same password and different salts", async () => {
  const a = await deriveKey("same-password", randomBytes(32), DEFAULT_SCRYPT_PARAMS);
  const b = await deriveKey("same-password", randomBytes(32), DEFAULT_SCRYPT_PARAMS);
  assert.notDeepEqual(a, b);
});

test("scrypt produces different keys for different passwords and the same salt", async () => {
  const salt = randomBytes(32);
  const a = await deriveKey("password-one", salt, DEFAULT_SCRYPT_PARAMS);
  const b = await deriveKey("password-two", salt, DEFAULT_SCRYPT_PARAMS);
  assert.notDeepEqual(a, b);
});

test("pbkdf2 floor is enforced at 600,000 iterations", async () => {
  const salt = randomBytes(32);
  await assert.rejects(
    () => deriveKey("pw", salt, { algorithm: "pbkdf2-sha256", iterations: 100_000 }),
    /at least 600000/,
  );
});

test("empty password is rejected", async () => {
  await assert.rejects(() => deriveKey("", randomBytes(32), DEFAULT_SCRYPT_PARAMS));
});

test("short salt is rejected", async () => {
  await assert.rejects(() => deriveKey("pw", Buffer.alloc(8), DEFAULT_SCRYPT_PARAMS));
});

test("paramsToHeader round-trips for scrypt", () => {
  const header = paramsToHeader(DEFAULT_SCRYPT_PARAMS);
  const round = headerToParams(header as Record<string, unknown>);
  assert.equal(round.algorithm, "scrypt");
  assert.equal(round.logN, DEFAULT_SCRYPT_PARAMS.logN);
  assert.equal(round.r, DEFAULT_SCRYPT_PARAMS.r);
  assert.equal(round.p, DEFAULT_SCRYPT_PARAMS.p);
});

test("paramsToHeader round-trips for pbkdf2", () => {
  const header = paramsToHeader(DEFAULT_PBKDF2_PARAMS);
  const round = headerToParams(header as Record<string, unknown>);
  assert.equal(round.algorithm, "pbkdf2-sha256");
  assert.equal(round.iterations, DEFAULT_PBKDF2_PARAMS.iterations);
});
