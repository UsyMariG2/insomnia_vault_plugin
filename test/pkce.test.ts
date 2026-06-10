/**
 * PKCE helper guarantees.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { generateFlowSecrets } from "../src/auth/pkce";
import { toBase64Url } from "../src/util/encoding";

test("code_challenge is the base64url(sha256(code_verifier))", () => {
  const secrets = generateFlowSecrets();
  const expected = toBase64Url(createHash("sha256").update(secrets.codeVerifier).digest());
  assert.equal(secrets.codeChallenge, expected);
  assert.equal(secrets.codeChallengeMethod, "S256");
});

test("each call produces fresh state, nonce, and verifier", () => {
  const a = generateFlowSecrets();
  const b = generateFlowSecrets();
  assert.notEqual(a.codeVerifier, b.codeVerifier);
  assert.notEqual(a.state, b.state);
  assert.notEqual(a.nonce, b.nonce);
});

test("verifier has enough entropy for RFC 7636 minimum", () => {
  const { codeVerifier } = generateFlowSecrets();
  assert.ok(codeVerifier.length >= 43, `code_verifier length ${codeVerifier.length} < 43`);
  assert.ok(codeVerifier.length <= 128, `code_verifier length ${codeVerifier.length} > 128`);
  assert.match(codeVerifier, /^[A-Za-z0-9_-]+$/);
});
