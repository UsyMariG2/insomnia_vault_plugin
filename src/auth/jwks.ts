/**
 * JWKS fetch + id_token signature verification (RS256/RS384/RS512).
 *
 * Uses only `jws` and Node.js built-ins (`node:crypto`, `fetch`). JWKS
 * documents are cached in memory per `jwks_uri` for 24 hours.
 */

import { createPublicKey } from "node:crypto";
import { Agent } from "node:https";
import { decode as decodeJws, verify as verifyJws, type Algorithm } from "jws";
import { debug, warn } from "../util/log";

const JWKS_TTL_MS = 24 * 60 * 60 * 1000;
const SUPPORTED_ALGORITHMS = new Set(["RS256", "RS384", "RS512"]);

export interface JsonWebKey {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  [key: string]: unknown;
}

interface JwksCacheEntry {
  fetchedAt: number;
  keys: JsonWebKey[];
}

const jwksCache = new Map<string, JwksCacheEntry>();

export interface JwksOptions {
  validateTls?: boolean;
  fetchImpl?: typeof fetch;
}

function buildFetchInit(validateTls: boolean): RequestInit | undefined {
  if (validateTls) return undefined;
  const agent = new Agent({ rejectUnauthorized: false });
  return { agent } as unknown as RequestInit;
}

export async function fetchJwks(jwksUri: string, options: JwksOptions = {}): Promise<JsonWebKey[]> {
  const validateTls = options.validateTls ?? true;
  const cached = jwksCache.get(jwksUri);
  if (cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) {
    return cached.keys;
  }

  debug(`Fetching JWKS from ${jwksUri}`);
  const fetchImpl = options.fetchImpl ?? fetch;
  const response = await fetchImpl(jwksUri, buildFetchInit(validateTls));
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(
      `JWKS fetch failed: ${response.status} ${response.statusText} from ${jwksUri}${body ? ` — ${body.slice(0, 200)}` : ""}`,
    );
  }

  const payload = (await response.json()) as { keys?: unknown };
  if (!Array.isArray(payload.keys)) {
    throw new Error(`JWKS at ${jwksUri} did not contain a keys array.`);
  }

  const keys = payload.keys.filter((key): key is JsonWebKey => {
    return Boolean(key && typeof key === "object" && typeof (key as JsonWebKey).kty === "string");
  });
  jwksCache.set(jwksUri, { fetchedAt: Date.now(), keys });
  return keys;
}

export function jwkToPem(jwk: JsonWebKey): string {
  if (jwk.kty !== "RSA") {
    throw new Error(`Unsupported JWK key type '${jwk.kty}' — only RSA is supported.`);
  }
  if (typeof jwk.n !== "string" || typeof jwk.e !== "string") {
    throw new Error("RSA JWK is missing required n/e parameters.");
  }
  const publicKey = createPublicKey({
    format: "jwk",
    key: {
      kty: "RSA",
      n: jwk.n,
      e: jwk.e,
    },
  });
  return publicKey.export({ type: "pkcs1", format: "pem" }) as string;
}

function selectJwk(keys: JsonWebKey[], kid: string | undefined): JsonWebKey | null {
  const signingKeys = keys.filter((key) => key.kty === "RSA" && (!key.use || key.use === "sig"));
  if (kid) {
    const match = signingKeys.find((key) => key.kid === kid);
    return match ?? null;
  }
  if (signingKeys.length === 1) {
    return signingKeys[0] ?? null;
  }
  return null;
}

export interface VerifyIdTokenSignatureOptions extends JwksOptions {
  /** When false, skip verification if jwks_uri is absent. Default: true (fail closed). */
  requireJwksUri?: boolean;
}

/**
 * Verifies the JWT signature of an id_token against the issuer JWKS.
 * @throws when verification fails or JWKS cannot be loaded.
 */
export async function verifyIdTokenSignature(
  idToken: string,
  jwksUri: string | undefined,
  options: VerifyIdTokenSignatureOptions = {},
): Promise<void> {
  if (!jwksUri) {
    if (options.requireJwksUri ?? true) {
      throw new Error("OIDC metadata did not provide jwks_uri — cannot verify id_token signature.");
    }
    warn("jwks_uri missing in OIDC metadata — skipping id_token signature verification.");
    return;
  }

  const decoded = decodeJws(idToken);
  if (!decoded?.header || typeof decoded.header !== "object") {
    throw new Error("id_token is not a valid JWT.");
  }

  const header = decoded.header as { alg?: string; kid?: string };
  const alg = header.alg;
  if (!alg || !SUPPORTED_ALGORITHMS.has(alg)) {
    throw new Error(`id_token uses unsupported or missing signature algorithm '${alg ?? ""}'.`);
  }

  let keys: JsonWebKey[];
  try {
    keys = await fetchJwks(jwksUri, options);
  } catch (err) {
    throw new Error(`Failed to fetch JWKS for signature verification: ${(err as Error).message}`);
  }

  const jwk = selectJwk(keys, typeof header.kid === "string" ? header.kid : undefined);
  if (!jwk) {
    const kidMsg = header.kid ? `kid '${header.kid}'` : "missing kid";
    throw new Error(`No matching RSA signing key found in JWKS for ${kidMsg}.`);
  }

  let pem: string;
  try {
    pem = jwkToPem(jwk);
  } catch (err) {
    throw new Error(`Failed to import JWK for signature verification: ${(err as Error).message}`);
  }

  let valid = false;
  try {
    valid = verifyJws(idToken, alg as Algorithm, pem);
  } catch (err) {
    throw new Error(`id_token signature verification error: ${(err as Error).message}`);
  }

  if (!valid) {
    throw new Error("id_token signature verification failed — token may have been tampered with.");
  }

  debug(`id_token signature verified (${alg}, jwks_uri=${jwksUri}).`);
}

export function __clearJwksCache(): void {
  jwksCache.clear();
}
