/**
 * Credential resolution for Insomnia template tags.
 *
 * Insomnia v13 runs user-installed plugin tags in the main process where
 * `context.app.prompt` silently returns an empty string, and GUI-launched
 * Insomnia never inherits OS environment variables. Credentials are therefore
 * resolved from Insomnia's own render context: encrypted secret variables (the
 * `vault` namespace) are preferred, with a plain Insomnia environment variable
 * as a last resort.
 */

import type { InsomniaContext, InsomniaPromptOptions } from "../tags/types";

export const ENV_VAULT_PASSWORD = "PLUS4U_OIDC_V2_VAULT_PASSWORD";
export const ENV_ACCESS_CODE_1 = "PLUS4U_OIDC_V2_ACCESS_CODE_1";
export const ENV_ACCESS_CODE_2 = "PLUS4U_OIDC_V2_ACCESS_CODE_2";

/** Insomnia masks secret values with this sentinel when not decrypting. */
const VAULT_MASK_SENTINEL = "••••••";

export type SecretSource = "insomnia-secret" | "insomnia-env" | "none";

const V13_PROMPT_HINT =
  "Store credentials in an Insomnia Secret variable (Preferences → Security → " +
  "Generate Vault Key, then add the variable as type Secret in a private global " +
  "sub-environment and select it in the collection). Recommended name: " +
  "PLUS4U_OIDC_V2_VAULT_PASSWORD (vault) or PLUS4U_OIDC_V2_ACCESS_CODE_1 / " +
  "PLUS4U_OIDC_V2_ACCESS_CODE_2 (interactive), or per-identification " +
  "PLUS4U_OIDC_V2_<IDENT>_AC1 / _AC2 where <IDENT> is the identification label " +
  "with non-alphanumeric characters removed and uppercased (e.g. 6-804-1 → 68041). " +
  "A plain (non-secret) Insomnia environment variable of the same name also " +
  "works as a last resort but is stored in plaintext.";

export class VaultPasswordRequiredError extends Error {
  constructor(diagnostic = "") {
    super(`Could not obtain vault password. ${V13_PROMPT_HINT}${diagnostic ? ` ${diagnostic}` : ""}`);
    this.name = "VaultPasswordRequiredError";
  }
}

export class AccessCodesRequiredError extends Error {
  constructor(identification: string, diagnostic = "") {
    const identKey = identificationEnvKey(identification);
    super(
      `Could not obtain access codes for '${identification}'. ${V13_PROMPT_HINT} ` +
        `Per-identification keys: PLUS4U_OIDC_V2_${identKey}_AC1 / _AC2.${diagnostic ? ` ${diagnostic}` : ""}`,
    );
    this.name = "AccessCodesRequiredError";
  }
}

export function identificationEnvKey(identification: string): string {
  return identification.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
}

function cleanValue(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed === VAULT_MASK_SENTINEL) return undefined;
  return trimmed;
}

function renderScope(context: InsomniaContext): Record<string, unknown> | undefined {
  const scope = context.context;
  return scope && typeof scope === "object" ? (scope as Record<string, unknown>) : undefined;
}

function vaultNamespace(context: InsomniaContext): Record<string, unknown> | undefined {
  const scope = renderScope(context);
  const vault = scope?.vault;
  return vault && typeof vault === "object" ? (vault as Record<string, unknown>) : undefined;
}

function nunjucksGlobal(context: InsomniaContext): Record<string, unknown> | undefined {
  const scope = renderScope(context);
  const underscore = scope?._;
  return underscore && typeof underscore === "object" ? (underscore as Record<string, unknown>) : undefined;
}

/**
 * Resolve a single key from Insomnia's render context: encrypted secret
 * (`vault` namespace) first, then a plain environment variable.
 */
export function resolveFromInsomnia(
  context: InsomniaContext,
  key: string,
): { value?: string; source: SecretSource } {
  const secret = cleanValue(vaultNamespace(context)?.[key]);
  if (secret) return { value: secret, source: "insomnia-secret" };

  const plain = cleanValue(renderScope(context)?.[key]) ?? cleanValue(nunjucksGlobal(context)?.[key]);
  if (plain) return { value: plain, source: "insomnia-env" };

  return { source: "none" };
}

/**
 * Resolve a secret value, preferring Insomnia secret variables, then an
 * interactive prompt (pre-v13 only), then a plain Insomnia environment
 * variable as a last resort.
 */
export async function promptSecret(
  context: InsomniaContext,
  title: string,
  options: InsomniaPromptOptions,
  keys: string[],
): Promise<string | undefined> {
  for (const key of keys) {
    const secret = cleanValue(vaultNamespace(context)?.[key]);
    if (secret) return secret;
  }

  const fromPrompt = cleanValue(await context.app.prompt(title, options));
  if (fromPrompt) return fromPrompt;

  for (const key of keys) {
    const plain = cleanValue(renderScope(context)?.[key]) ?? cleanValue(nunjucksGlobal(context)?.[key]);
    if (plain) return plain;
  }

  return undefined;
}

export function accessCodeEnvKeys(identification: string, slot: 1 | 2): string[] {
  const identKey = identificationEnvKey(identification);
  if (slot === 1) {
    return [`PLUS4U_OIDC_V2_${identKey}_AC1`, ENV_ACCESS_CODE_1];
  }
  return [`PLUS4U_OIDC_V2_${identKey}_AC2`, ENV_ACCESS_CODE_2];
}

/** Where each key was found, sources only — never the values. */
export function secretDiagnostics(context: InsomniaContext, keys: string[]): Record<string, SecretSource> {
  const out: Record<string, SecretSource> = {};
  for (const key of keys) {
    out[key] = resolveFromInsomnia(context, key).source;
  }
  return out;
}

/** Top-level and vault key names visible in the render scope — names only. */
export function scopeKeyNames(context: InsomniaContext): { top: string[]; vault: string[] } {
  const scope = renderScope(context);
  const vault = vaultNamespace(context);
  return {
    top: scope ? Object.keys(scope) : [],
    vault: vault ? Object.keys(vault) : [],
  };
}

export function getRenderPurpose(context: InsomniaContext): string | undefined {
  if (context.renderPurpose) {
    return context.renderPurpose;
  }
  return context.context?.getPurpose?.();
}
