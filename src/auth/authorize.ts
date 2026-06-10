/**
 * Orchestrates the Authorization Code + PKCE flow against an OIDC server.
 *
 * Steps:
 *   1. Generate fresh PKCE / state / nonce values (per-flow, never persisted).
 *   2. Discover the OIDC metadata so we know the authorization_endpoint and
 *      token_endpoint.
 *   3. Start the hardened localhost callback server, bound to 127.0.0.1.
 *   4. Open the user's default browser at the /authorize URL with
 *      response_type=code, code_challenge, state, nonce, scope=openid.
 *   5. Wait for the callback; the server validates `state` itself.
 *   6. Exchange the code at /token with the matching `code_verifier`.
 *   7. Validate the returned id_token (nonce, exp, optional iss/aud).
 *
 * Returns the raw id_token (and the metadata that was used) on success.
 */

import { setTimeout as wait } from "node:timers/promises";
import openModule from "open";
import { generateFlowSecrets } from "./pkce";
import { discoverMetadata, type OidcMetadata } from "./discovery";
import { startCallbackServer } from "./callback-server";
import { exchangeCodeForToken, validateIdToken } from "./token";
import { debug, info } from "../util/log";

export interface AuthorizeRequest {
  oidcServer: string;
  clientId?: string;
  scope?: string;
  /** URL to redirect the browser to after a successful callback. */
  infoPage?: string | null;
  /** TLS cert validation toggle. Default: true. */
  validateTls?: boolean;
  /** Expected issuer for id_token validation. Defaults to metadata.issuer. */
  expectedIssuer?: string;
  /** Hard timeout for the whole flow (ms). Default: 5 minutes. */
  timeoutMs?: number;
}

export interface AuthorizeResult {
  idToken: string;
  metadata: OidcMetadata;
  /** Approximate token expiration time, derived from the id_token `exp` claim. */
  expiresAt: Date;
}

const DEFAULT_SCOPE = "openid";

/**
 * Sentinel `client_id` used when the caller does not supply one. Plus4U's
 * `/oidc/auth` endpoint rejects requests without a `client_id` even for
 * public clients; this 32-zero value is the well-known placeholder for the
 * anonymous public-client case. The same effective value is sent on the
 * matching `/oidc/token` PKCE exchange to satisfy RFC 6749 §4.1.3 (public
 * clients must include `client_id` at the token endpoint).
 *
 * The sentinel is deliberately NOT used as `expectedAudience` for id_token
 * validation — see `authorize()` below — because the server's actual `aud`
 * claim is almost always the resolved user/client identity, not `0…0`.
 */
export const DEFAULT_OIDC_CLIENT_ID = "00000000000000000000000000000000";

export async function authorize(request: AuthorizeRequest): Promise<AuthorizeResult> {
  const validateTls = request.validateTls ?? true;
  const scope = request.scope?.includes("openid") ? request.scope : `${DEFAULT_SCOPE}${request.scope ? ` ${request.scope}` : ""}`;
  const secrets = generateFlowSecrets();
  const metadata = await discoverMetadata(request.oidcServer, { validateTls });

  // Treat both `undefined` and empty/whitespace strings as "no explicit
  // client_id". The custom-token tag defaults the user-facing field to ""
  // (empty), and we must fall back to the sentinel in that case too.
  const explicitClientId = request.clientId?.trim() ? request.clientId.trim() : undefined;
  const effectiveClientId = explicitClientId ?? DEFAULT_OIDC_CLIENT_ID;

  const server = await startCallbackServer({
    expectedState: secrets.state,
    redirectAfterSuccess: buildRedirect(request.infoPage, explicitClientId),
    timeoutMs: request.timeoutMs,
  });

  try {
    const redirectUri = `http://127.0.0.1:${server.port}/`;
    const authzUrl = buildAuthzUrl({
      base: metadata.authorization_endpoint,
      clientId: effectiveClientId,
      redirectUri,
      scope,
      challenge: secrets.codeChallenge,
      challengeMethod: secrets.codeChallengeMethod,
      state: secrets.state,
      nonce: secrets.nonce,
    });

    info(`Opening browser for OIDC login: ${authzUrl.split("?")[0]}`);
    debug(`Full /authorize URL (with redacted query): ${authzUrl}`);

    // Don't await `open` — it resolves on browser-launch, not after login.
    void openModule(authzUrl).catch((err: unknown) => {
      debug(`open() failed (browser may have been opened manually): ${(err as Error).message}`);
    });

    // Race the callback against a generous floor; the server enforces the
    // hard timeout, this just keeps the promise alive.
    const callback = await Promise.race([
      server.waitForCode(),
      wait((request.timeoutMs ?? 5 * 60 * 1000) + 1000).then(() => {
        throw new Error("Authentication did not complete in time.");
      }),
    ]);

    const tokenResponse = await exchangeCodeForToken({
      tokenEndpoint: metadata.token_endpoint,
      code: callback.code,
      codeVerifier: secrets.codeVerifier,
      redirectUri,
      clientId: effectiveClientId,
      validateTls,
    });

    const idToken = tokenResponse.id_token;
    if (!idToken) {
      throw new Error("OIDC server did not return an id_token.");
    }
    const validated = validateIdToken(idToken, {
      expectedNonce: secrets.nonce,
      expectedIssuer: request.expectedIssuer ?? metadata.issuer,
      // Only enforce aud when the caller supplied a real client_id; the
      // sentinel default must never reject a legitimate id_token whose
      // `aud` claim is the resolved identity.
      expectedAudience: explicitClientId,
    });
    return {
      idToken,
      metadata,
      expiresAt: validated.expiresAt,
    };
  } finally {
    server.close();
  }
}

export interface BuildAuthzUrlArgs {
  base: string;
  clientId?: string;
  redirectUri: string;
  scope: string;
  challenge: string;
  challengeMethod: "S256";
  state: string;
  nonce: string;
}

export function buildAuthzUrl(args: BuildAuthzUrlArgs): string {
  const url = new URL(args.base);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", args.redirectUri);
  url.searchParams.set("scope", args.scope);
  url.searchParams.set("code_challenge", args.challenge);
  url.searchParams.set("code_challenge_method", args.challengeMethod);
  url.searchParams.set("state", args.state);
  url.searchParams.set("nonce", args.nonce);
  if (args.clientId) url.searchParams.set("client_id", args.clientId);
  return url.toString();
}

function buildRedirect(infoPage: string | null | undefined, clientId: string | undefined): string | null {
  if (!infoPage) return null;
  try {
    const url = new URL(infoPage);
    if (clientId && !url.searchParams.has("clientId")) {
      url.searchParams.set("clientId", clientId);
    }
    return url.toString();
  } catch {
    return null;
  }
}
