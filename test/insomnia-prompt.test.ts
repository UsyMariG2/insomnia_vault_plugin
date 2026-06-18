/**
 * Insomnia credential resolution — secret/env render context and render purpose.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ENV_ACCESS_CODE_1,
  ENV_ACCESS_CODE_2,
  ENV_VAULT_PASSWORD,
  accessCodeEnvKeys,
  getRenderPurpose,
  identificationEnvKey,
  promptSecret,
  resolveFromInsomnia,
  scopeKeyNames,
  secretDiagnostics,
} from "../src/util/insomnia-prompt";
import type { InsomniaContext } from "../src/tags/types";

function makeContext(
  overrides: Partial<InsomniaContext> & { scope?: Record<string, unknown> } = {},
): InsomniaContext {
  const { scope, ...rest } = overrides;
  return {
    app: { prompt: async () => undefined },
    context: scope as InsomniaContext["context"],
    ...rest,
  };
}

test("identificationEnvKey strips non-alphanumeric and uppercases", () => {
  assert.equal(identificationEnvKey("6-804-1"), "68041");
  assert.equal(identificationEnvKey("my-bot"), "MYBOT");
});

test("accessCodeEnvKeys prefers per-identification keys", () => {
  assert.deepEqual(accessCodeEnvKeys("6-804-1", 1), ["PLUS4U_OIDC_V2_68041_AC1", ENV_ACCESS_CODE_1]);
  assert.deepEqual(accessCodeEnvKeys("6-804-1", 2), ["PLUS4U_OIDC_V2_68041_AC2", ENV_ACCESS_CODE_2]);
});

test("getRenderPurpose reads renderPurpose then context.getPurpose", () => {
  assert.equal(getRenderPurpose({ app: { prompt: async () => "" }, renderPurpose: "send" }), "send");
  assert.equal(
    getRenderPurpose({
      app: { prompt: async () => "" },
      context: { getPurpose: () => "general" },
    }),
    "general",
  );
});

test("resolveFromInsomnia reads the vault secret namespace first", () => {
  const context = makeContext({
    scope: {
      vault: { [ENV_VAULT_PASSWORD]: "secret-pw" },
      [ENV_VAULT_PASSWORD]: "plain-pw",
    },
  });
  const resolved = resolveFromInsomnia(context, ENV_VAULT_PASSWORD);
  assert.equal(resolved.value, "secret-pw");
  assert.equal(resolved.source, "insomnia-secret");
});

test("resolveFromInsomnia falls back to plain env (top-level then _ global)", () => {
  const top = makeContext({ scope: { [ENV_VAULT_PASSWORD]: "plain-top" } });
  assert.deepEqual(resolveFromInsomnia(top, ENV_VAULT_PASSWORD), {
    value: "plain-top",
    source: "insomnia-env",
  });

  const underscore = makeContext({ scope: { _: { [ENV_VAULT_PASSWORD]: "plain-underscore" } } });
  assert.deepEqual(resolveFromInsomnia(underscore, ENV_VAULT_PASSWORD), {
    value: "plain-underscore",
    source: "insomnia-env",
  });
});

test("resolveFromInsomnia ignores the masked secret sentinel", () => {
  const context = makeContext({ scope: { vault: { [ENV_VAULT_PASSWORD]: "••••••" } } });
  assert.equal(resolveFromInsomnia(context, ENV_VAULT_PASSWORD).source, "none");
});

test("promptSecret order: secret > prompt > plain env", async () => {
  let promptCalls = 0;
  const base = (scope: Record<string, unknown>): InsomniaContext =>
    makeContext({
      scope,
      app: {
        prompt: async () => {
          promptCalls++;
          return "from-prompt";
        },
      },
    });

  const secretCtx = base({ vault: { [ENV_VAULT_PASSWORD]: "secret" }, [ENV_VAULT_PASSWORD]: "plain" });
  assert.equal(await promptSecret(secretCtx, "t", {}, [ENV_VAULT_PASSWORD]), "secret");
  assert.equal(promptCalls, 0);

  const promptCtx = base({ [ENV_VAULT_PASSWORD]: "plain" });
  assert.equal(await promptSecret(promptCtx, "t", {}, [ENV_VAULT_PASSWORD]), "from-prompt");
  assert.equal(promptCalls, 1);

  const envCtx = makeContext({ scope: { [ENV_VAULT_PASSWORD]: "plain-last" } });
  assert.equal(await promptSecret(envCtx, "t", {}, [ENV_VAULT_PASSWORD]), "plain-last");
});

test("secretDiagnostics reports sources only, never values", () => {
  const context = makeContext({
    scope: { vault: { [ENV_VAULT_PASSWORD]: "VALUE_AAA" }, [ENV_ACCESS_CODE_1]: "VALUE_BBB" },
  });
  const diag = secretDiagnostics(context, [ENV_VAULT_PASSWORD, ENV_ACCESS_CODE_1, ENV_ACCESS_CODE_2]);
  assert.deepEqual(diag, {
    [ENV_VAULT_PASSWORD]: "insomnia-secret",
    [ENV_ACCESS_CODE_1]: "insomnia-env",
    [ENV_ACCESS_CODE_2]: "none",
  });
  const serialized = JSON.stringify(diag);
  assert.doesNotMatch(serialized, /VALUE_AAA/);
  assert.doesNotMatch(serialized, /VALUE_BBB/);
});

test("scopeKeyNames lists key names only", () => {
  const context = makeContext({
    scope: { vault: { [ENV_VAULT_PASSWORD]: "secret" }, base_url: "https://x" },
  });
  const names = scopeKeyNames(context);
  assert.ok(names.top.includes("base_url"));
  assert.ok(names.top.includes("vault"));
  assert.deepEqual(names.vault, [ENV_VAULT_PASSWORD]);
});
