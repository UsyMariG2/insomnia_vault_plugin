/**
 * OIDC discovery — fetches `.well-known/openid-configuration` for an issuer
 * and caches the result for a short window.
 *
 * Two error styles supported:
 *   - Standard OIDC (HTTP 200 with valid JSON containing endpoints).
 *   - uuOIDC-style (HTTP 200 with a `uuAppErrorMap` — non-empty means failure).
 *
 * Caching is per-issuer URL with a 5-minute TTL. Discovery responses are
 * small and immutable in practice; without caching we'd re-fetch on every
 * tag render which Insomnia does aggressively.
 */

import { Agent } from "node:https";
import { debug, warn } from "../util/log";

export interface OidcMetadata {
  issuer?: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri?: string;
  end_session_endpoint?: string;
  /** Raw response — useful for tests and forward-compat. */
  raw: Record<string, unknown>;
}

interface CacheEntry {
  fetchedAt: number;
  metadata: OidcMetadata;
}

const DISCOVERY_TTL_MS = 5 * 60 * 1000;
const cache = new Map<string, CacheEntry>();

export interface DiscoveryOptions {
  /** When `false`, TLS validation is disabled (custom OIDC servers only). */
  validateTls?: boolean;
  /** Skip the cache (for tests / forced refresh). */
  forceRefresh?: boolean;
  /** Override the global fetch (tests). */
  fetchImpl?: typeof fetch;
}

function buildAgent(validateTls: boolean): Agent | undefined {
  if (validateTls) return undefined;
  return new Agent({ rejectUnauthorized: false });
}

function isUuOidcError(payload: Record<string, unknown>): boolean {
  const map = payload.uuAppErrorMap;
  return Boolean(map && typeof map === "object" && Object.keys(map as Record<string, unknown>).length > 0);
}

export async function discoverMetadata(issuer: string, options: DiscoveryOptions = {}): Promise<OidcMetadata> {
  const validateTls = options.validateTls ?? true;
  if (!validateTls) {
    warn(`TLS validation disabled for OIDC discovery on ${issuer}. Use only for trusted local/self-signed servers.`);
  }

  const cacheKey = `${issuer}|${validateTls ? "tls" : "no-tls"}`;
  if (!options.forceRefresh) {
    const hit = cache.get(cacheKey);
    if (hit && Date.now() - hit.fetchedAt < DISCOVERY_TTL_MS) {
      return hit.metadata;
    }
  }

  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  debug(`Discovering OIDC metadata at ${url}`);

  const fetchImpl = options.fetchImpl ?? fetch;
  const agent = buildAgent(validateTls);
  // The Node fetch types don't include the `agent` option but the runtime does
  // pass it through to undici. We allow it here for the legacy self-signed case.
  const init = agent ? ({ dispatcher: undefined, agent } as unknown as RequestInit) : undefined;
  const response = await fetchImpl(url, init);
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`OIDC discovery failed: ${response.status} ${response.statusText} from ${url}${body ? ` — ${body.slice(0, 200)}` : ""}`);
  }

  const payload = (await response.json()) as Record<string, unknown>;
  if (isUuOidcError(payload)) {
    throw new Error(`OIDC discovery failed: uuOIDC server returned non-empty uuAppErrorMap from ${url}.`);
  }
  if (typeof payload.authorization_endpoint !== "string" || typeof payload.token_endpoint !== "string") {
    throw new Error(`OIDC discovery at ${url} missing required endpoint URLs.`);
  }

  const metadata: OidcMetadata = {
    issuer: typeof payload.issuer === "string" ? payload.issuer : undefined,
    authorization_endpoint: payload.authorization_endpoint,
    token_endpoint: payload.token_endpoint,
    jwks_uri: typeof payload.jwks_uri === "string" ? payload.jwks_uri : undefined,
    end_session_endpoint: typeof payload.end_session_endpoint === "string" ? payload.end_session_endpoint : undefined,
    raw: payload,
  };
  cache.set(cacheKey, { fetchedAt: Date.now(), metadata });
  return metadata;
}

export function __clearDiscoveryCache(): void {
  cache.clear();
}
