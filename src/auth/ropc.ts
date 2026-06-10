/**
 * Resource Owner Password Credentials (ROPC) grant for uuEE service accounts.
 *
 * RFC 6749 §4.3 — `grant_type=password`. Deprecated in OAuth 2.1 and never
 * used as the default path in this plugin; the {@link uuEePlus4uOidcToken}
 * template tag exposes an explicit "Use ROPC (legacy)" toggle that must be
 * checked before this function is called.
 *
 * Supported credential shapes:
 *   - uuOIDC (`accessCode1` / `accessCode2`)
 *   - Generic / Azure (`username` / `password`)
 *
 * `client_secret` is intentionally never sent.
 */

import { Agent } from "node:https";
import { discoverMetadata } from "./discovery";

export type RopcCredentialShape = "uu-oidc" | "username-password";

export interface RopcRequest {
  oidcServer: string;
  scope: string;
  accessCode1?: string;
  accessCode2?: string;
  username?: string;
  password?: string;
  clientId?: string;
  /** Force a particular credential shape. Default: auto-detect. */
  shape?: RopcCredentialShape;
  validateTls?: boolean;
  /** Override fetch (tests). */
  fetchImpl?: typeof fetch;
}

export interface RopcResult {
  idToken: string;
  jwksUri?: string;
  raw: Record<string, unknown>;
}

export async function ropc(request: RopcRequest): Promise<RopcResult> {
  const validateTls = request.validateTls ?? true;
  const shape = request.shape ?? autoDetectShape(request);

  const metadata = await discoverMetadata(request.oidcServer, { validateTls, fetchImpl: request.fetchImpl });
  const params = new URLSearchParams();
  params.set("grant_type", "password");
  params.set("scope", request.scope);
  if (request.clientId) params.set("client_id", request.clientId);

  if (shape === "uu-oidc") {
    if (!request.accessCode1 || !request.accessCode2) {
      throw new Error("uuOIDC ROPC requires both accessCode1 and accessCode2.");
    }
    params.set("accessCode1", request.accessCode1);
    params.set("accessCode2", request.accessCode2);
  } else {
    if (!request.username || !request.password) {
      throw new Error("Username/password ROPC requires both username and password.");
    }
    params.set("username", request.username);
    params.set("password", request.password);
  }

  const fetchImpl = request.fetchImpl ?? fetch;
  const init: RequestInit & { agent?: Agent } = {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: params.toString(),
  };
  if (!validateTls) (init as RequestInit & { agent: Agent }).agent = new Agent({ rejectUnauthorized: false });

  const response = await fetchImpl(metadata.token_endpoint, init as RequestInit);
  const contentType = response.headers.get("content-type") ?? "";
  let payload: Record<string, unknown> = {};
  if (contentType.includes("application/json")) {
    payload = (await response.json()) as Record<string, unknown>;
  } else {
    const text = await response.text();
    throw new Error(`Token endpoint returned non-JSON: ${text.slice(0, 200)}`);
  }

  if (!response.ok || payload.error) {
    const errCode = typeof payload.error === "string" ? payload.error : `HTTP ${response.status}`;
    const desc = typeof payload.error_description === "string" ? `: ${payload.error_description}` : "";
    throw new Error(`ROPC token request failed (${errCode})${desc}.`);
  }

  // uuOIDC may return uuAppErrorMap with errors instead of HTTP status.
  if (payload.uuAppErrorMap && typeof payload.uuAppErrorMap === "object" && Object.keys(payload.uuAppErrorMap as Record<string, unknown>).length > 0) {
    throw new Error("ROPC token request failed: uuOIDC server returned non-empty uuAppErrorMap.");
  }

  const idToken = payload.id_token;
  if (typeof idToken !== "string") {
    throw new Error("ROPC response did not contain an id_token.");
  }
  return { idToken, jwksUri: metadata.jwks_uri, raw: payload };
}

function autoDetectShape(request: RopcRequest): RopcCredentialShape {
  if (request.accessCode1 || request.accessCode2) return "uu-oidc";
  if (request.username || request.password) return "username-password";
  // Default to uuOIDC since this plugin's primary target is oidc.plus4u.net.
  return "uu-oidc";
}
