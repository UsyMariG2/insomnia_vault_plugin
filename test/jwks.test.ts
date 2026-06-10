/**
 * JWKS fetch cache + id_token signature verification.
 */

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { sign as signJws } from "jws";
import {
  __clearJwksCache,
  fetchJwks,
  jwkToPem,
  verifyIdTokenSignature,
} from "../src/auth/jwks";
import { __testReset as resetTokenCache, storeOk } from "../src/util/token-cache";

const NOW = 1_700_000_000;
const JWKS_URI = "https://oidc.example.com/jwks";

interface TestKeyMaterial {
  privateKey: KeyObject;
  publicJwk: Record<string, string>;
  kid: string;
}

function createTestKey(kid = "test-rsa-1"): TestKeyMaterial {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const exported = publicKey.export({ format: "jwk" }) as Record<string, string>;
  return { privateKey, publicJwk: exported, kid };
}

function makeRs256Token(
  key: TestKeyMaterial,
  payload: Record<string, unknown>,
  signatureOverride?: string,
): string {
  const token = signJws({
    header: { alg: "RS256", typ: "JWT", kid: key.kid },
    payload,
    privateKey: key.privateKey,
    encoding: "utf8",
  });
  if (!signatureOverride) return token;
  const parts = token.split(".");
  parts[2] = signatureOverride;
  return parts.join(".");
}

function jwksResponseFor(key: TestKeyMaterial): { keys: Record<string, string>[] } {
  return {
    keys: [
      {
        kty: "RSA",
        kid: key.kid,
        use: "sig",
        alg: "RS256",
        n: key.publicJwk.n,
        e: key.publicJwk.e,
      },
    ],
  };
}

function mockJwksFetch(body: unknown, fail = false): typeof fetch {
  return async (input) => {
    assert.equal(String(input), JWKS_URI);
    if (fail) {
      return new Response("upstream error", { status: 503 });
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

afterEach(() => {
  __clearJwksCache();
  resetTokenCache();
});

test("verifyIdTokenSignature accepts a valid RS256 token", async () => {
  const key = createTestKey();
  const token = makeRs256Token(key, { exp: NOW + 600, nonce: "N" });
  await verifyIdTokenSignature(token, JWKS_URI, {
    fetchImpl: mockJwksFetch(jwksResponseFor(key)),
  });
});

test("verifyIdTokenSignature rejects a tampered signature", async () => {
  const key = createTestKey();
  const token = makeRs256Token(key, { exp: NOW + 600 }, "invalidsignature");
  await assert.rejects(
    () =>
      verifyIdTokenSignature(token, JWKS_URI, {
        fetchImpl: mockJwksFetch(jwksResponseFor(key)),
      }),
    /signature verification failed/i,
  );
});

test("verifyIdTokenSignature rejects unknown kid", async () => {
  const key = createTestKey("expected-kid");
  const other = createTestKey("other-kid");
  const token = makeRs256Token(key, { exp: NOW + 600 });
  await assert.rejects(
    () =>
      verifyIdTokenSignature(token, JWKS_URI, {
        fetchImpl: mockJwksFetch(jwksResponseFor(other)),
      }),
    /no matching rsa signing key/i,
  );
});

test("verifyIdTokenSignature treats JWKS network failure as verification failure", async () => {
  const key = createTestKey();
  const token = makeRs256Token(key, { exp: NOW + 600 });
  await assert.rejects(
    () =>
      verifyIdTokenSignature(token, JWKS_URI, {
        fetchImpl: mockJwksFetch(null, true),
      }),
    /failed to fetch jwks/i,
  );
});

test("fetchJwks caches responses for repeated lookups", async () => {
  const key = createTestKey();
  let calls = 0;
  const fetchImpl: typeof fetch = async () => {
    calls++;
    return new Response(JSON.stringify(jwksResponseFor(key)), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await fetchJwks(JWKS_URI, { fetchImpl });
  await fetchJwks(JWKS_URI, { fetchImpl });
  assert.equal(calls, 1);
});

test("jwkToPem exports a PEM public key from RSA JWK", () => {
  const key = createTestKey();
  const pem = jwkToPem({
    kty: "RSA",
    n: key.publicJwk.n,
    e: key.publicJwk.e,
  });
  assert.match(pem, /BEGIN RSA PUBLIC KEY/);
});

test("storeOk caches token only after successful signature verification", async () => {
  const key = createTestKey();
  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  const token = makeRs256Token(key, { exp: futureExp });
  const stored = await storeOk("cache:test", token, {
    jwksUri: JWKS_URI,
    fetchImpl: mockJwksFetch(jwksResponseFor(key)),
  });
  assert.equal(stored, true);
});

test("storeOk throws and does not cache when signature verification fails", async () => {
  const key = createTestKey();
  const token = makeRs256Token(key, { exp: NOW + 600 }, "badsignature");
  await assert.rejects(
    () =>
      storeOk("cache:test", token, {
        jwksUri: JWKS_URI,
        fetchImpl: mockJwksFetch(jwksResponseFor(key)),
      }),
    /signature verification failed/i,
  );
});
