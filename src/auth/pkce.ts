/**
 * PKCE (RFC 7636) helpers and per-flow secrets.
 *
 * Each auth flow allocates a fresh {@link FlowSecrets} bundle: a high-entropy
 * `code_verifier` (later hashed into `code_challenge`), a `state` value that
 * gates the callback, and a `nonce` that the OIDC server will embed in the
 * id_token. None of these values are persisted to disk or logged.
 */

import { createHash, randomBytes } from "node:crypto";
import { toBase64Url } from "../util/encoding";

export interface FlowSecrets {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  state: string;
  nonce: string;
}

/** RFC 7636 allows 43..128 unreserved chars; 32 random bytes → 43 base64url chars. */
const VERIFIER_BYTES = 32;

export function generateFlowSecrets(): FlowSecrets {
  const codeVerifier = toBase64Url(randomBytes(VERIFIER_BYTES));
  const codeChallenge = toBase64Url(createHash("sha256").update(codeVerifier).digest());
  const state = toBase64Url(randomBytes(16));
  const nonce = toBase64Url(randomBytes(16));
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
    state,
    nonce,
  };
}
