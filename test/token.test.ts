/**
 * id_token validation tests — replay protection (nonce), expiry, issuer, audience.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { exchangeCodeForToken, validateIdToken } from "../src/auth/token";
import { toBase64Url } from "../src/util/encoding";

function makeJwt(payload: Record<string, unknown>): string {
  const header = toBase64Url(Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body = toBase64Url(Buffer.from(JSON.stringify(payload)));
  const sig = toBase64Url(createHmac("sha256", "test-secret").update(`${header}.${body}`).digest());
  return `${header}.${body}.${sig}`;
}

const NOW = 1_700_000_000;

test("accepts a fresh, well-formed token with matching nonce", () => {
  const jwt = makeJwt({ nonce: "N", iss: "https://example.com", aud: "client-1", exp: NOW + 600 });
  const result = validateIdToken(jwt, {
    expectedNonce: "N",
    expectedIssuer: "https://example.com",
    expectedAudience: "client-1",
    nowEpochSeconds: NOW,
  });
  assert.equal(result.expiresAt.getTime(), (NOW + 600) * 1000);
});

test("rejects nonce mismatch (replay protection)", () => {
  const jwt = makeJwt({ nonce: "ATTACKER", exp: NOW + 600 });
  assert.throws(
    () => validateIdToken(jwt, { expectedNonce: "MINE", nowEpochSeconds: NOW }),
    /nonce did not match/i,
  );
});

test("rejects expired token (beyond clock skew)", () => {
  const jwt = makeJwt({ nonce: "N", exp: NOW - 3600 });
  assert.throws(
    () => validateIdToken(jwt, { expectedNonce: "N", nowEpochSeconds: NOW }),
    /already expired/i,
  );
});

test("accepts token within clock skew window", () => {
  const jwt = makeJwt({ nonce: "N", exp: NOW - 10 });
  const result = validateIdToken(jwt, { expectedNonce: "N", nowEpochSeconds: NOW, clockSkewSeconds: 60 });
  assert.ok(result.expiresAt instanceof Date);
});

test("rejects issuer mismatch when expectedIssuer provided", () => {
  const jwt = makeJwt({ nonce: "N", exp: NOW + 600, iss: "https://evil.example.com" });
  assert.throws(
    () => validateIdToken(jwt, { expectedNonce: "N", expectedIssuer: "https://example.com", nowEpochSeconds: NOW }),
    /iss .* does not match/i,
  );
});

test("rejects audience mismatch when expectedAudience provided", () => {
  const jwt = makeJwt({ nonce: "N", exp: NOW + 600, aud: ["other-client"] });
  assert.throws(
    () => validateIdToken(jwt, { expectedNonce: "N", expectedAudience: "my-client", nowEpochSeconds: NOW }),
    /aud does not contain/i,
  );
});

test("rejects token missing the exp claim", () => {
  const jwt = makeJwt({ nonce: "N" });
  assert.throws(
    () => validateIdToken(jwt, { expectedNonce: "N", nowEpochSeconds: NOW }),
    /missing the `exp` claim/i,
  );
});

test("exchangeCodeForToken: client_id sentinel round-trips into the URL-encoded body", async () => {
  let capturedBody = "";
  const fakeFetch: typeof fetch = async (_input, init) => {
    capturedBody = String((init as RequestInit).body ?? "");
    return new Response(JSON.stringify({ id_token: "x.y.z", token_type: "Bearer" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const response = await exchangeCodeForToken({
    tokenEndpoint: "https://oidc.example.com/oidc/token",
    code: "AUTH_CODE",
    codeVerifier: "VERIFIER",
    redirectUri: "http://127.0.0.1:54321/",
    clientId: "00000000000000000000000000000000",
    fetchImpl: fakeFetch,
  });
  assert.equal(response.id_token, "x.y.z");
  assert.ok(capturedBody.length > 0, "fakeFetch should have captured a body");
  const params = new URLSearchParams(capturedBody);
  assert.equal(params.get("grant_type"), "authorization_code");
  assert.equal(params.get("code"), "AUTH_CODE");
  assert.equal(params.get("code_verifier"), "VERIFIER");
  assert.equal(params.get("redirect_uri"), "http://127.0.0.1:54321/");
  assert.equal(params.get("client_id"), "00000000000000000000000000000000");
});

test("exchangeCodeForToken: omits client_id when caller passes none", async () => {
  let capturedBody = "";
  const fakeFetch: typeof fetch = async (_input, init) => {
    capturedBody = String((init as RequestInit).body ?? "");
    return new Response(JSON.stringify({ id_token: "x.y.z" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  await exchangeCodeForToken({
    tokenEndpoint: "https://oidc.example.com/oidc/token",
    code: "AUTH_CODE",
    codeVerifier: "VERIFIER",
    redirectUri: "http://127.0.0.1:54321/",
    fetchImpl: fakeFetch,
  });
  const params = new URLSearchParams(capturedBody);
  assert.equal(params.has("client_id"), false);
});
