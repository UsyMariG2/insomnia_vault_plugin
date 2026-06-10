/**
 * `buildAuthzUrl` / `DEFAULT_OIDC_CLIENT_ID` unit tests.
 *
 * The full `authorize()` flow is integration-heavy (browser + callback
 * server + token endpoint), so we test the URL builder directly. The
 * builder is the single source of truth for the query string sent to
 * `/oidc/auth`, so verifying it covers the sentinel-default behavior
 * without spinning up a localhost server.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildAuthzUrl, DEFAULT_OIDC_CLIENT_ID } from "../src/auth/authorize";

const BASE_ARGS = {
  base: "https://oidc.example.com/oidc/auth",
  redirectUri: "http://127.0.0.1:54321/",
  scope: "openid",
  challenge: "CHALLENGE",
  challengeMethod: "S256" as const,
  state: "STATE",
  nonce: "NONCE",
};

test("DEFAULT_OIDC_CLIENT_ID is the 32-zero sentinel string", () => {
  assert.equal(DEFAULT_OIDC_CLIENT_ID, "00000000000000000000000000000000");
  assert.equal(DEFAULT_OIDC_CLIENT_ID.length, 32);
});

test("buildAuthzUrl: caller-supplied sentinel default lands in client_id query param", () => {
  const url = new URL(buildAuthzUrl({ ...BASE_ARGS, clientId: DEFAULT_OIDC_CLIENT_ID }));
  assert.equal(url.searchParams.get("client_id"), "00000000000000000000000000000000");
  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(url.searchParams.get("scope"), "openid");
  assert.equal(url.searchParams.get("redirect_uri"), "http://127.0.0.1:54321/");
});

test("buildAuthzUrl: an explicit client_id wins over the sentinel default", () => {
  const url = new URL(buildAuthzUrl({ ...BASE_ARGS, clientId: "my-real-client" }));
  assert.equal(url.searchParams.get("client_id"), "my-real-client");
});

test("buildAuthzUrl: omitting client_id leaves it absent (orchestrator is responsible for defaulting)", () => {
  const url = new URL(buildAuthzUrl({ ...BASE_ARGS }));
  assert.equal(url.searchParams.has("client_id"), false);
});
