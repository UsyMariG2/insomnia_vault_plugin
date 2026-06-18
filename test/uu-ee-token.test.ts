/**
 * uuEePlus4uOidcToken — Insomnia v13 prompt / renderPurpose regressions.
 */

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { __testReset as resetAuthDebounce } from "../src/util/auth-debounce";
import { __testReset as resetTokenCache } from "../src/util/token-cache";
import {
  ENV_ACCESS_CODE_1,
  ENV_ACCESS_CODE_2,
} from "../src/util/insomnia-prompt";
import { __testReset as resetEeToken, uuEePlus4uOidcToken } from "../src/tags/uu-ee-token";
import type { InsomniaContext } from "../src/tags/types";

function makeContext(
  overrides: Partial<InsomniaContext> & { scope?: Record<string, unknown> } = {},
): InsomniaContext {
  const { scope, ...rest } = overrides;
  return {
    app: { prompt: async () => undefined },
    meta: { workspaceId: "ws-test" },
    context: scope as InsomniaContext["context"],
    ...rest,
  };
}

const RUN_ARGS = ["bot-id", "https://oidc.example.com/oidc", "openid", true, false, true] as const;

afterEach(() => {
  resetEeToken();
  resetAuthDebounce();
  resetTokenCache();
});

test("renderPurpose general returns token-in-progress without prompting", async () => {
  let promptCalls = 0;
  const context = makeContext({
    renderPurpose: "general",
    app: {
      prompt: async () => {
        promptCalls++;
        return "should-not-ask";
      },
    },
  });

  const result = await uuEePlus4uOidcToken.run(context, ...RUN_ARGS);
  assert.match(result, /-- plus4u-oidc-v2 token-in-progress:/);
  assert.equal(promptCalls, 0);
});

test("renderPurpose send with no credentials returns missing-config with diag, not generic access-code error", async () => {
  const context = makeContext({ renderPurpose: "send" });
  const result = await uuEePlus4uOidcToken.run(context, ...RUN_ARGS);
  assert.match(result, /-- plus4u-oidc-v2 missing-config:/);
  assert.match(result, /Insomnia Secret variable/);
  assert.match(result, /diag: renderPurpose=send/);
  assert.doesNotMatch(result, /Both access codes are required/);
});

test("renderPurpose send with access codes from Insomnia secret vault reaches ROPC (network error)", async () => {
  const context = makeContext({
    renderPurpose: "send",
    scope: {
      vault: {
        [ENV_ACCESS_CODE_1]: "ac1-secret",
        [ENV_ACCESS_CODE_2]: "ac2-secret",
      },
    },
  });

  const result = await uuEePlus4uOidcToken.run(context, ...RUN_ARGS);
  assert.match(result, /-- plus4u-oidc-v2 token-error:/);
  assert.doesNotMatch(result, /Both access codes are required/);
  assert.doesNotMatch(result, /Could not obtain access codes/);
});

test("renderPurpose send with access codes from plain Insomnia env reaches ROPC (network error)", async () => {
  const context = makeContext({
    renderPurpose: "send",
    scope: {
      [ENV_ACCESS_CODE_1]: "ac1-plain",
      [ENV_ACCESS_CODE_2]: "ac2-plain",
    },
  });

  const result = await uuEePlus4uOidcToken.run(context, ...RUN_ARGS);
  assert.match(result, /-- plus4u-oidc-v2 token-error:/);
  assert.doesNotMatch(result, /Could not obtain access codes/);
});
