/**
 * In-memory token cache for the Insomnia plugin.
 *
 * Two kinds of cached values:
 *   - Successful tokens, keyed by a caller-chosen `cacheKey`, with a TTL
 *     derived from the id_token `exp` claim minus a 5-minute grace period.
 *   - Error results, cached for a short window so a 100-request batch that
 *     fails the first time doesn't open 100 browser tabs.
 *
 * Concurrency: when an authentication is in flight for a given `cacheKey`,
 * subsequent callers get the same in-flight promise instead of starting a
 * second flow. This matches what Insomnia does when many requests fire at
 * once during environment changes.
 */

import { decode as decodeJws } from "jws";
import { verifyIdTokenSignature } from "../auth/jwks";
import { fromBase64Url } from "./encoding";
import { debug, warn } from "./log";

const GRACE_SECONDS = 5 * 60;
const ERROR_TTL_SECONDS = 5 * 60;

interface OkEntry {
  kind: "ok";
  token: string;
  cachedAt: number;
  expiresAt: number;
}

interface ErrEntry {
  kind: "err";
  message: string;
  cachedAt: number;
}

type CacheEntry = OkEntry | ErrEntry;
type CacheValue = { entry: CacheEntry; expiresAt: number };

const cache = new Map<string, CacheValue>();
const inflight = new Map<string, Promise<string>>();

function decodeExp(token: string): number | null {
  const decoded = decodeJws(token);
  if (!decoded) return null;
  let claims: { exp?: number };
  if (typeof decoded.payload === "string") {
    try {
      claims = JSON.parse(decoded.payload) as { exp?: number };
    } catch {
      try {
        claims = JSON.parse(fromBase64Url(decoded.payload).toString("utf8")) as { exp?: number };
      } catch {
        return null;
      }
    }
  } else {
    claims = decoded.payload as { exp?: number };
  }
  return typeof claims.exp === "number" ? claims.exp : null;
}

export interface CacheHit {
  kind: "ok-fresh" | "ok-expired" | "err" | "miss";
  token?: string;
  expiresAt?: number;
  errorMessage?: string;
  errorCachedAt?: number;
}

export function lookup(cacheKey: string): CacheHit {
  const item = cache.get(cacheKey);
  if (!item) return { kind: "miss" };

  const nowSec = Math.floor(Date.now() / 1000);
  if (nowSec >= item.expiresAt) {
    cache.delete(cacheKey);
    return { kind: "miss" };
  }

  const { entry } = item;
  if (entry.kind === "err") {
    return { kind: "err", errorMessage: entry.message, errorCachedAt: entry.cachedAt };
  }
  const nowSecForFreshness = Math.floor(Date.now() / 1000);
  if (nowSecForFreshness + GRACE_SECONDS >= entry.expiresAt) {
    return { kind: "ok-expired", token: entry.token, expiresAt: entry.expiresAt };
  }
  return { kind: "ok-fresh", token: entry.token, expiresAt: entry.expiresAt };
}

export interface StoreOkOptions {
  jwksUri?: string;
  validateTls?: boolean;
  fetchImpl?: typeof fetch;
}

/**
 * Caches a successful id_token after optional JWKS signature verification.
 *
 * @returns `true` when the token was cached.
 * @returns `false` when the token is valid but not cached (e.g. near expiry).
 * @throws when signature verification fails — the token must not be used.
 */
export async function storeOk(cacheKey: string, token: string, options: StoreOkOptions = {}): Promise<boolean> {
  try {
    await verifyIdTokenSignature(token, options.jwksUri, {
      validateTls: options.validateTls,
      fetchImpl: options.fetchImpl,
    });
  } catch (err) {
    const message = (err as Error).message;
    warn(`id_token signature verification failed for cacheKey — not cached: ${message}`);
    throw new Error(message);
  }

  const exp = decodeExp(token);
  const nowSec = Math.floor(Date.now() / 1000);
  if (exp === null) {
    debug(`Token for cacheKey did not have a parseable exp — not cached.`);
    return false;
  }
  const ttlSec = exp - nowSec - GRACE_SECONDS;
  if (ttlSec <= 0) {
    debug(`Token for cacheKey is too close to expiry — not cached.`);
    return false;
  }
  cache.set(cacheKey, { entry: { kind: "ok", token, cachedAt: nowSec, expiresAt: exp }, expiresAt: exp });
  return true;
}

export function storeErr(cacheKey: string, message: string): void {
  const nowSec = Math.floor(Date.now() / 1000);
  const entry: ErrEntry = { kind: "err", message, cachedAt: nowSec };
  cache.set(cacheKey, { entry, expiresAt: nowSec + ERROR_TTL_SECONDS });
}

export function invalidate(cacheKey: string): void {
  cache.delete(cacheKey);
}

/** Coalesces concurrent calls for the same key onto a single producer. */
export async function withInflightLock<T extends string>(
  cacheKey: string,
  producer: () => Promise<T>,
): Promise<T> {
  const existing = inflight.get(cacheKey);
  if (existing) {
    return existing as Promise<T>;
  }
  const promise = (async () => {
    try {
      return await producer();
    } finally {
      inflight.delete(cacheKey);
    }
  })();
  inflight.set(cacheKey, promise);
  return promise;
}

export const __testReset = (): void => {
  cache.clear();
  inflight.clear();
};
