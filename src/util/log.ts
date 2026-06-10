/**
 * Central logging helpers with mandatory redaction.
 *
 * Rules enforced here (so nothing else in the codebase needs to remember them):
 *   - Tokens, authorization codes, PKCE verifiers, vault passwords, access codes,
 *     and `client_secret`-like keys are ALWAYS replaced with `***`.
 *   - URL query strings are scrubbed of `code`, `state`, `token`, `id_token`,
 *     `access_token`, `client_secret`, `password`, `accessCode1`, `accessCode2`.
 *   - Anything containing a JWT-like string (three base64url segments) is masked
 *     to its header and a fingerprint.
 *
 * Callers MUST go through {@link debug}, {@link info}, {@link warn}, {@link error}.
 * Direct `console.*` calls are forbidden by review (see THREAT_MODEL.md).
 */

import { createHash } from "node:crypto";

const SECRET_KEYS = new Set([
  "password",
  "vaultpassword",
  "client_secret",
  "clientsecret",
  "accesscode1",
  "accesscode2",
  "ac1",
  "ac2",
  "code",
  "code_verifier",
  "codeverifier",
  "code_challenge",
  "id_token",
  "idtoken",
  "access_token",
  "accesstoken",
  "refresh_token",
  "refreshtoken",
  "token",
  "state",
  "nonce",
  "authorization",
]);

const SCRUBBED_QUERY_PARAMS = [
  "code",
  "state",
  "token",
  "id_token",
  "access_token",
  "refresh_token",
  "client_secret",
  "password",
  "accessCode1",
  "accessCode2",
  "code_verifier",
  "nonce",
];

const JWT_RE = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;

function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 8);
}

function maskJwt(value: string): string {
  return value.replace(JWT_RE, (match: string): string => {
    const [header] = match.split(".");
    return `<jwt header=${header ?? "?"} fp=${fingerprint(match)}>`;
  });
}

function scrubUrl(value: string): string {
  try {
    const url = new URL(value);
    let mutated = false;
    for (const param of SCRUBBED_QUERY_PARAMS) {
      if (url.searchParams.has(param)) {
        url.searchParams.set(param, "***");
        mutated = true;
      }
    }
    return mutated ? url.toString() : value;
  } catch {
    return value;
  }
}

function redactString(value: string): string {
  return maskJwt(scrubUrl(value));
}

function redactObject(input: unknown, depth = 0): unknown {
  if (input === null || input === undefined) return input;
  if (depth > 6) return "<deep>";
  if (typeof input === "string") return redactString(input);
  if (typeof input === "number" || typeof input === "boolean") return input;
  if (Buffer.isBuffer(input)) return `<buffer len=${input.length}>`;
  if (Array.isArray(input)) return input.map((item) => redactObject(item, depth + 1));
  if (typeof input === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      if (SECRET_KEYS.has(key.toLowerCase())) {
        out[key] = "***";
      } else {
        out[key] = redactObject(value, depth + 1);
      }
    }
    return out;
  }
  return "<unprintable>";
}

function formatArgs(args: readonly unknown[]): unknown[] {
  return args.map((arg) => redactObject(arg));
}

function emit(level: "debug" | "info" | "warn" | "error", message: string, args: readonly unknown[]): void {
  const stamped = `[plus4u-oidc-v2] ${message}`;
  const redacted = formatArgs(args);
  switch (level) {
    case "debug":
      console.debug(stamped, ...redacted);
      return;
    case "info":
      console.info(stamped, ...redacted);
      return;
    case "warn":
      console.warn(stamped, ...redacted);
      return;
    case "error":
      console.error(stamped, ...redacted);
      return;
  }
}

export function debug(message: string, ...args: unknown[]): void {
  emit("debug", message, args);
}

export function info(message: string, ...args: unknown[]): void {
  emit("info", message, args);
}

export function warn(message: string, ...args: unknown[]): void {
  emit("warn", message, args);
}

export function error(message: string, ...args: unknown[]): void {
  emit("error", message, args);
}

export const __test = { redactObject, redactString, fingerprint };
