/**
 * Token endpoint exchange + id_token validation.
 *
 * The token exchange uses `application/x-www-form-urlencoded` (the only
 * encoding all OIDC servers accept), sends `code_verifier` (PKCE), and never
 * sends a `client_secret` — the new plugin treats every OIDC client as
 * public; if a particular provider rejects PKCE-only requests, the user
 * should configure a different OIDC client registration.
 *
 * id_token claim validation (nonce, exp, iss, aud) runs synchronously here.
 * Cryptographic signature verification against the issuer JWKS runs
 * asynchronously in {@link storeOk} before a token is cached.
 */

import { decode as decodeJws } from "jws";
import { Agent } from "node:https";
import { fromBase64Url } from "../util/encoding";
import { debug } from "../util/log";

export interface TokenExchangeRequest {
  tokenEndpoint: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  clientId?: string;
  validateTls?: boolean;
  /** Override fetch (tests). */
  fetchImpl?: typeof fetch;
}

export interface TokenResponse {
  id_token?: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  /** Raw JSON for unexpected fields. */
  raw: Record<string, unknown>;
}

export async function exchangeCodeForToken(request: TokenExchangeRequest): Promise<TokenResponse> {
  const params = new URLSearchParams();
  params.set("grant_type", "authorization_code");
  params.set("code", request.code);
  params.set("code_verifier", request.codeVerifier);
  params.set("redirect_uri", request.redirectUri);
  if (request.clientId) params.set("client_id", request.clientId);

  const fetchImpl = request.fetchImpl ?? fetch;
  const agent = (request.validateTls ?? true) ? undefined : new Agent({ rejectUnauthorized: false });

  debug(`Exchanging authorization code at ${request.tokenEndpoint}`);
  const init: RequestInit & { agent?: Agent } = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: params.toString(),
  };
  if (agent) (init as RequestInit & { agent: Agent }).agent = agent;

  const response = await fetchImpl(request.tokenEndpoint, init as RequestInit);

  let payload: Record<string, unknown>;
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    payload = (await response.json()) as Record<string, unknown>;
  } else {
    const text = await response.text();
    throw new Error(`Token endpoint returned non-JSON content-type '${contentType}': ${text.slice(0, 200)}`);
  }

  if (!response.ok) {
    const code = typeof payload.error === "string" ? payload.error : `HTTP ${response.status}`;
    const desc = typeof payload.error_description === "string" ? `: ${payload.error_description}` : "";
    throw new Error(`Token exchange failed (${code})${desc}.`);
  }

  return {
    id_token: typeof payload.id_token === "string" ? payload.id_token : undefined,
    access_token: typeof payload.access_token === "string" ? payload.access_token : undefined,
    refresh_token: typeof payload.refresh_token === "string" ? payload.refresh_token : undefined,
    token_type: typeof payload.token_type === "string" ? payload.token_type : undefined,
    expires_in: typeof payload.expires_in === "number" ? payload.expires_in : undefined,
    scope: typeof payload.scope === "string" ? payload.scope : undefined,
    raw: payload,
  };
}

export interface ValidateIdTokenOptions {
  expectedNonce: string;
  expectedIssuer?: string;
  expectedAudience?: string;
  /** Clock skew tolerance in seconds. Default: 60. */
  clockSkewSeconds?: number;
  /** "Current time" override for tests. */
  nowEpochSeconds?: number;
}

export interface ValidatedIdToken {
  expiresAt: Date;
  issuedAt?: Date;
  payload: Record<string, unknown>;
}

interface IdTokenClaims {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nonce?: string;
}

export function validateIdToken(idToken: string, options: ValidateIdTokenOptions): ValidatedIdToken {
  const decoded = decodeJws(idToken);
  if (!decoded || typeof decoded.payload === "undefined") {
    throw new Error("id_token is not a valid JWT.");
  }

  let claims: IdTokenClaims & Record<string, unknown>;
  if (typeof decoded.payload === "string") {
    try {
      claims = JSON.parse(decoded.payload) as IdTokenClaims & Record<string, unknown>;
    } catch {
      // jws sometimes returns the base64url-decoded string; try one more parse.
      try {
        claims = JSON.parse(fromBase64Url(decoded.payload).toString("utf8")) as IdTokenClaims & Record<string, unknown>;
      } catch {
        throw new Error("id_token payload is not valid JSON.");
      }
    }
  } else {
    claims = decoded.payload as IdTokenClaims & Record<string, unknown>;
  }

  if (claims.nonce !== options.expectedNonce) {
    throw new Error("id_token nonce did not match the value we sent — possible replay.");
  }

  const skew = options.clockSkewSeconds ?? 60;
  const now = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number") {
    throw new Error("id_token is missing the `exp` claim.");
  }
  if (now > claims.exp + skew) {
    throw new Error("id_token is already expired.");
  }

  if (options.expectedIssuer && claims.iss && claims.iss !== options.expectedIssuer) {
    throw new Error(`id_token iss '${claims.iss}' does not match expected issuer '${options.expectedIssuer}'.`);
  }

  if (options.expectedAudience && claims.aud) {
    const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audList.includes(options.expectedAudience)) {
      throw new Error(`id_token aud does not contain expected audience '${options.expectedAudience}'.`);
    }
  }

  return {
    expiresAt: new Date(claims.exp * 1000),
    issuedAt: typeof claims.iat === "number" ? new Date(claims.iat * 1000) : undefined,
    payload: claims,
  };
}
