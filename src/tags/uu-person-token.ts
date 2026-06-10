/**
 * `uuPersonPlus4uOidcToken` — interactive login against oidc.plus4u.net.
 *
 * Backward-compatible name with the legacy plugin so existing Insomnia
 * environments / collections referring to this tag continue to work.
 *
 * No client_id / client_secret is shipped; PKCE is the only proof of
 * possession. See THREAT_MODEL.md §"Public client".
 */

import { authorize } from "../auth/authorize";
import { scheduleInteractiveAuth } from "../util/auth-debounce";
import { lookup, storeErr, storeOk } from "../util/token-cache";
import { format, formatIsoDate } from "../util/messages";
import { error as logError } from "../util/log";
import type { InsomniaContext, TemplateTag } from "./types";

const ENVIRONMENTS = {
  production: {
    oidcServer: "https://uuidentity.plus4u.net/uu-oidc-maing02/bb977a99f4cc4c37a2afce3fd599d0a7/oidc",
    infoPage: "https://uuidentity.plus4u.net/uu-identitymanagement-maing01/a9b105aff2744771be4daa8361954677/showAuthorizationCode",
  },
  development: {
    oidcServer: "https://uuidentity-dev.plus4u.net/uu-oidc-maing02/eca71064ecce44b0a25ce940eb8f053d/oidc",
    infoPage: "https://uuidentity-dev.plus4u.net/uu-identitymanagement-maing01/58ceb15c275c4b31bfe0fc9768aa6a9c/showAuthorizationCode",
  },
} as const;

type Mode = keyof typeof ENVIRONMENTS;

const DEFAULT_SCOPE = "openid";

function isMode(value: string): value is Mode {
  return value === "production" || value === "development";
}

async function run(_context: InsomniaContext, ...args: unknown[]): Promise<string> {
  const [modeArg, disabledArg, scopeArg] = args as [
    string | undefined,
    boolean | undefined,
    string | undefined,
  ];
  const mode: Mode = modeArg && isMode(modeArg) ? modeArg : "production";
  const disabled = Boolean(disabledArg);
  const scope = (scopeArg ?? "").trim() || DEFAULT_SCOPE;
  const cacheKey = `uuPersonPlus4uOidcToken:${mode}:${scope}`;

  if (disabled) {
    return format("token-disabled");
  }

  const hit = lookup(cacheKey);
  if (hit.kind === "ok-fresh" && hit.token) {
    return hit.token;
  }
  if (hit.kind === "err") {
    return format("token-error-cached", `${hit.errorMessage} (cached ${formatIsoDate(hit.errorCachedAt ?? 0)}; toggle Disabled to refresh)`);
  }

  try {
    return await scheduleInteractiveAuth(
      `uuPersonPlus4uOidcToken:${mode}`,
      cacheKey,
      async () => {
        const env = ENVIRONMENTS[mode];
        const result = await authorize({
          oidcServer: env.oidcServer,
          infoPage: env.infoPage,
          scope,
          validateTls: true,
        });
        await storeOk(cacheKey, result.idToken, {
          jwksUri: result.metadata.jwks_uri,
          validateTls: true,
        });
        return result.idToken;
      },
    );
  } catch (err) {
    const message = (err as Error).message;
    logError(`uuPersonPlus4uOidcToken failed: ${message}`);
    storeErr(cacheKey, message);
    return format("token-error", message);
  }
}

export const uuPersonPlus4uOidcToken: TemplateTag = {
  name: "uuPersonPlus4uOidcToken",
  displayName: "Token from oidc.plus4u.net",
  description: "Get an id_token from oidc.plus4u.net via PKCE-protected browser login.",
  args: [
    {
      displayName: "Mode",
      type: "enum",
      defaultValue: "production",
      options: [
        { displayName: "Production", value: "production" },
        { displayName: "Development", value: "development" },
      ],
      help: "Select the Plus4U environment to authenticate against.",
    },
    {
      displayName: "Disabled (toggle to refresh)",
      type: "boolean",
      defaultValue: false,
      help: "Check to return a no-op message; uncheck to force a fresh login.",
    },
    {
      displayName: "Token scope",
      type: "string",
      defaultValue: DEFAULT_SCOPE,
      help: "Scope to request. Default is 'openid'. For uuApp calls, add the target scope (e.g. openid uu-oidc:unregistered-client:<awid>).",
    },
  ],
  run,
};
