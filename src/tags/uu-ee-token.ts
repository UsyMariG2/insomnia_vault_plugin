/**
 * `uuEePlus4uOidcToken` — service-account (uuEE) authentication.
 *
 * Default and recommended: prompt the user for access codes interactively
 * (they're held in plugin process memory only for the running Insomnia
 * session). Opt-in: load access codes from the encrypted vault written by
 * the migration tool / vault CLI.
 *
 * ROPC (`grant_type=password`) is the only OIDC grant uuOIDC currently
 * supports for service accounts. It is gated behind the explicit
 * "Use ROPC (legacy password grant)" toggle so users have to consciously
 * accept the deprecated flow before it runs. See THREAT_MODEL.md §"ROPC".
 */

import { ropc } from "../auth/ropc";
import { entryStorageKey, normalizeOidcServer, oidcServersMatch } from "../vault/keys";
import {
  defaultVaultPath,
  findEntryInContents,
  readVault,
  vaultExists,
  type VaultContents,
} from "../vault/store";
import { scheduleInteractiveAuth } from "../util/auth-debounce";
import { lookup, storeErr, storeOk } from "../util/token-cache";
import { format, formatIsoDate } from "../util/messages";
import { debug, info, error as logError } from "../util/log";
import {
  AccessCodesRequiredError,
  ENV_ACCESS_CODE_1,
  ENV_ACCESS_CODE_2,
  ENV_VAULT_PASSWORD,
  VaultPasswordRequiredError,
  accessCodeEnvKeys,
  getRenderPurpose,
  promptSecret,
  resolveFromInsomnia,
  scopeKeyNames,
} from "../util/insomnia-prompt";
import type { InsomniaContext, TemplateTag } from "./types";

interface CachedCreds {
  accessCode1: string;
  accessCode2: string;
  oidcServer: string;
}

const sessionCreds = new Map<string, CachedCreds>();
let vaultPassword: string | null = null;
let vaultContentsCache: VaultContents | null = null;

function clearVaultSession(): void {
  vaultPassword = null;
  vaultContentsCache = null;
}

const DEFAULT_OIDC_SERVER = "https://uuidentity.plus4u.net/uu-oidc-maing02/bb977a99f4cc4c37a2afce3fd599d0a7/oidc";
const DEFAULT_SCOPE = "openid";

async function loadVaultContents(context: InsomniaContext): Promise<VaultContents | null> {
  const filePath = defaultVaultPath();
  const exists = await vaultExists(filePath);
  debug("loadVaultContents", { filePath, vaultFileExists: exists });
  if (!exists) {
    return null;
  }
  if (vaultContentsCache) {
    debug("loadVaultContents: using cached vault contents");
    return vaultContentsCache;
  }
  if (!vaultPassword) {
    const source = resolveFromInsomnia(context, ENV_VAULT_PASSWORD).source;
    info("Resolving vault password", { [ENV_VAULT_PASSWORD]: source });
    const pw = await promptSecret(
      context,
      "OIDC vault password",
      { label: "Encrypted vault password", inputType: "password" },
      [ENV_VAULT_PASSWORD],
    );
    if (!pw) {
      throw new VaultPasswordRequiredError(diagSuffix(context, [ENV_VAULT_PASSWORD]));
    }
    vaultPassword = pw;
  }
  try {
    vaultContentsCache = await readVault(vaultPassword);
    return vaultContentsCache;
  } catch (err) {
    clearVaultSession();
    throw err;
  }
}

async function loadCredsFromVault(
  identification: string,
  oidcServer: string,
  context: InsomniaContext,
): Promise<CachedCreds | null> {
  const contents = await loadVaultContents(context);
  if (!contents) return null;

  const entry = findEntryInContents(contents.entries, identification, oidcServer);
  if (!entry) return null;
  if (!oidcServersMatch(entry.oidcServer, oidcServer)) {
    return null;
  }
  return {
    accessCode1: entry.accessCode1,
    accessCode2: entry.accessCode2,
    oidcServer,
  };
}

async function gatherCreds(
  context: InsomniaContext,
  identification: string,
  oidcServerOverride: string,
  preferVault: boolean,
): Promise<CachedCreds> {
  const sessionKey = entryStorageKey(identification, oidcServerOverride);
  const sessionHit = sessionCreds.get(sessionKey);
  if (sessionHit) {
    debug("gatherCreds: using session-cached credentials");
    return sessionHit;
  }

  if (preferVault) {
    const fromVault = await loadCredsFromVault(identification, oidcServerOverride, context);
    if (fromVault) {
      debug("gatherCreds: credentials loaded from plugin file vault");
      sessionCreds.set(sessionKey, fromVault);
      return fromVault;
    }
  }

  const ac1Keys = accessCodeEnvKeys(identification, 1);
  const ac2Keys = accessCodeEnvKeys(identification, 2);
  info("Resolving access codes", {
    ac1: resolveFromInsomnia(context, ac1Keys[0]!).source,
    ac2: resolveFromInsomnia(context, ac2Keys[0]!).source,
  });
  const ac1 = await promptSecret(
    context,
    `Access code 1 (${identification})`,
    { label: `Access Code 1 for ${identification}`, inputType: "password" },
    ac1Keys,
  );
  const ac2 = await promptSecret(
    context,
    `Access code 2 (${identification})`,
    { label: `Access Code 2 for ${identification}`, inputType: "password" },
    ac2Keys,
  );
  if (!ac1 || !ac2) {
    throw new AccessCodesRequiredError(
      identification,
      diagSuffix(context, [...ac1Keys, ...ac2Keys, ENV_ACCESS_CODE_1, ENV_ACCESS_CODE_2]),
    );
  }
  const creds: CachedCreds = { accessCode1: ac1, accessCode2: ac2, oidcServer: oidcServerOverride };
  sessionCreds.set(sessionKey, creds);
  return creds;
}

/** Build a non-secret diagnostic suffix for inline error messages. */
function diagSuffix(context: InsomniaContext, keys: string[]): string {
  const renderPurpose = getRenderPurpose(context) ?? "unknown";
  const uniqueKeys = [...new Set(keys)];
  const sources = uniqueKeys.map((key) => `${key}=${resolveFromInsomnia(context, key).source}`).join(", ");
  const names = scopeKeyNames(context);
  return `(diag: renderPurpose=${renderPurpose}; ${sources}; vault keys seen: [${names.vault.join(", ")}])`;
}

async function run(context: InsomniaContext, ...args: unknown[]): Promise<string> {
  const [
    identificationArg,
    oidcServerArg,
    scopeArg,
    useRopcArg,
    useVaultArg,
    validateArg,
  ] = args as [
    string | undefined,
    string | undefined,
    string | undefined,
    boolean | undefined,
    boolean | undefined,
    boolean | undefined,
  ];

  const identification = (identificationArg ?? "").trim();
  if (!identification) {
    return format("missing-config", "Prompt user identification is required.");
  }
  const oidcServer = normalizeOidcServer((oidcServerArg ?? "").trim() || DEFAULT_OIDC_SERVER);
  const scope = (scopeArg ?? "").trim() || DEFAULT_SCOPE;
  const useRopc = Boolean(useRopcArg);
  const useVault = Boolean(useVaultArg);
  const validate = validateArg ?? true;

  if (!useRopc) {
    return format(
      "missing-config",
      "uuEE login uses the deprecated ROPC grant. Tick 'Use ROPC (legacy password grant)' to enable it for this tag.",
    );
  }

  const renderPurpose = getRenderPurpose(context);
  if (renderPurpose && renderPurpose !== "send") {
    return format("token-in-progress", "Credentials are collected when you send the request.");
  }

  const workspaceId = context.meta?.workspaceId ?? "default";
  const cacheKey = `uuEePlus4uOidcToken:${identification}:${oidcServer}:${scope}:${workspaceId}`;
  const scopeNames = scopeKeyNames(context);
  info("uuEePlus4uOidcToken run", {
    identification,
    oidcServer,
    useVault,
    renderPurpose: renderPurpose ?? "unknown",
    topKeys: scopeNames.top,
    vaultKeys: scopeNames.vault,
  });

  const hit = lookup(cacheKey);
  if (hit.kind === "ok-fresh" && hit.token) return hit.token;
  if (hit.kind === "err") {
    return format("token-error-cached", `${hit.errorMessage} (cached ${formatIsoDate(hit.errorCachedAt ?? 0)}; toggle Disabled or restart Insomnia to refresh)`);
  }

  try {
    return await scheduleInteractiveAuth(
      `uuEePlus4uOidcToken:${workspaceId}:${identification}`,
      cacheKey,
      async () => {
        const creds = await gatherCreds(context, identification, oidcServer, useVault);
        const result = await ropc({
          oidcServer,
          scope,
          accessCode1: creds.accessCode1,
          accessCode2: creds.accessCode2,
          shape: "uu-oidc",
          validateTls: validate,
        });
        await storeOk(cacheKey, result.idToken, {
          jwksUri: result.jwksUri,
          validateTls: validate,
        });
        return result.idToken;
      },
    );
  } catch (err) {
    if (err instanceof VaultPasswordRequiredError) {
      return format("vault-locked", err.message);
    }
    if (err instanceof AccessCodesRequiredError) {
      return format("missing-config", err.message);
    }
    const message = (err as Error).message;
    logError(`uuEePlus4uOidcToken failed: ${message}`);
    storeErr(cacheKey, message);
    return format("token-error", message);
  }
}

export const uuEePlus4uOidcToken: TemplateTag = {
  name: "uuEePlus4uOidcToken",
  displayName: "Token from oidc.plus4u.net for uuEE",
  description: "Service-account (uuEE) login via ROPC. Opt-in only; vault-backed credentials supported.",
  args: [
    {
      displayName: "Prompt user identification",
      type: "string",
      defaultValue: "",
      help: "Free-form label (e.g. uuIdentity). The same label may be used with different OIDC Server URLs; pair both fields with environment variables.",
    },
    {
      displayName: "OIDC Server",
      type: "string",
      defaultValue: DEFAULT_OIDC_SERVER,
      help: "Base URL of the OIDC server (no trailing slash). Must match the --uri used in `vault add` for that entry; use {{ env_var }} so prod/dev differ.",
    },
    {
      displayName: "Token scope",
      type: "string",
      defaultValue: DEFAULT_SCOPE,
      help: "Scope to request. Default is 'openid'.",
    },
    {
      displayName: "Use ROPC (legacy password grant) — REQUIRED for this tag",
      type: "boolean",
      defaultValue: false,
      help: "ROPC is deprecated by OAuth 2.1. Tick this only after you have read THREAT_MODEL.md §ROPC and understand the trade-off.",
    },
    {
      displayName: "Load access codes from vault",
      type: "boolean",
      defaultValue: true,
      help: "If checked, the plugin reads credentials from the encrypted vault before prompting. Vault password is asked once per Insomnia session.",
    },
    {
      displayName: "Validate TLS certificates",
      type: "boolean",
      defaultValue: true,
      help: "Disable only for trusted local development with self-signed certificates.",
    },
  ],
  run,
};

export const __testReset = (): void => {
  sessionCreds.clear();
  clearVaultSession();
};
