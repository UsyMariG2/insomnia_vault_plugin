/**
 * `uuPersonCustomOidcToken` — interactive login against a user-supplied OIDC
 * server. PKCE-only (no client_secret is requested or accepted).
 *
 * TLS certificate validation defaults to true and uses Insomnia's UI default
 * AND a `?? true` fallback in the run signature so a missing argument can
 * never silently disable validation (regression-proof against issue 3.5 of
 * the legacy plugin).
 */

import { authorize } from "../auth/authorize";
import { scheduleInteractiveAuth } from "../util/auth-debounce";
import { lookup, storeErr, storeOk } from "../util/token-cache";
import { format, formatIsoDate } from "../util/messages";
import { error as logError } from "../util/log";
import type { InsomniaContext, TemplateTag } from "./types";

async function run(_context: InsomniaContext, ...args: unknown[]): Promise<string> {
  const [
    disabledArg,
    cacheTagArg,
    oidcServerArg,
    infoPageArg,
    clientIdArg,
    validateArg,
  ] = args as [
    boolean | undefined,
    string | undefined,
    string | undefined,
    string | undefined,
    string | undefined,
    boolean | undefined,
  ];

  const disabled = Boolean(disabledArg);
  const cacheTag = cacheTagArg && cacheTagArg.trim().length > 0 ? cacheTagArg.trim() : "default";
  const oidcServer = (oidcServerArg ?? "").trim();
  const infoPage = (infoPageArg ?? "").trim();
  const clientId = (clientIdArg ?? "").trim();
  const validate = validateArg ?? true;

  if (disabled) {
    return format("token-disabled");
  }
  if (!oidcServer || oidcServer.includes("--fill-in--")) {
    return format("missing-config", "OIDC Server is required.");
  }

  const cacheKey = `uuPersonCustomOidcToken:${cacheTag}:${oidcServer}:${clientId}:${validate ? "tls" : "no-tls"}`;

  const hit = lookup(cacheKey);
  if (hit.kind === "ok-fresh" && hit.token) {
    return hit.token;
  }
  if (hit.kind === "err") {
    return format("token-error-cached", `${hit.errorMessage} (cached ${formatIsoDate(hit.errorCachedAt ?? 0)}; toggle Disabled to refresh)`);
  }

  try {
    return await scheduleInteractiveAuth(
      `uuPersonCustomOidcToken:${cacheTag}`,
      cacheKey,
      async () => {
        const result = await authorize({
          oidcServer,
          clientId: clientId || undefined,
          infoPage: infoPage || null,
          validateTls: validate,
        });
        await storeOk(cacheKey, result.idToken, {
          jwksUri: result.metadata.jwks_uri,
          validateTls: validate,
        });
        return result.idToken;
      },
    );
  } catch (err) {
    const message = (err as Error).message;
    logError(`uuPersonCustomOidcToken failed: ${message}`);
    storeErr(cacheKey, message);
    return format("token-error", message);
  }
}

export const uuPersonCustomOidcToken: TemplateTag = {
  name: "uuPersonCustomOidcToken",
  displayName: "Token from a custom uuOIDC server",
  description: "Get an id_token from a user-configured OIDC server (PKCE, no client_secret).",
  args: [
    {
      displayName: "Disabled (toggle to refresh)",
      type: "boolean",
      defaultValue: false,
      help: "Check to return a no-op message; uncheck to force a fresh login.",
    },
    {
      displayName: "Cache Tag",
      type: "string",
      defaultValue: "default",
      help: "Free-form label that lets you keep several distinct cached tokens against the same server.",
    },
    {
      displayName: "OIDC Server",
      type: "string",
      defaultValue: "--fill-in--",
      placeholder: "https:// /uu-oidc-maing02/ /oidc",
      help: "Base URL of the OIDC server (no trailing slash).",
    },
    {
      displayName: "OIDC Info Page (optional)",
      type: "string",
      defaultValue: "",
      placeholder: "https:// /uu-identitymanagement-maing01/ /showAuthorizationCode",
      help: "URL the browser is redirected to after a successful login. Leave empty for a plain text confirmation page.",
    },
    {
      displayName: "Client ID (optional)",
      type: "string",
      defaultValue: "",
      help: "OIDC client_id. Leave empty to send the Plus4U public-client sentinel `00000000000000000000000000000000`, which most uuOIDC servers accept for the PKCE flow. Fill in only if your OIDC server rejects the sentinel and requires a registered client_id. PKCE is always used; no client_secret is ever sent.",
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
