/**
 * AES-256-GCM authenticated encryption for vault payloads.
 *
 * Why GCM and not CTR/CBC:
 *   - GCM provides confidentiality AND integrity in a single primitive.
 *   - Any bit-flip in the ciphertext, the IV, or the auth tag causes
 *     decryption to throw, so the caller cannot silently process tampered
 *     data — closes the malleability gap in the legacy AES-CTR vault.
 *
 * IV requirement: a 12-byte IV MUST never be reused with the same key.
 * We generate a fresh random IV on every encrypt; the seal/open helpers
 * package IV + tag into the ciphertext-side data structure.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;

export interface SealedPayload {
  iv: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

export interface SealOptions {
  /** Pre-generated IV (12 bytes). If omitted, a fresh random IV is used. */
  iv?: Buffer;
  /** Additional authenticated data bound to the tag (e.g., the file header). */
  aad?: Buffer;
}

export function seal(plaintext: Buffer, key: Buffer, options: SealOptions = {}): SealedPayload {
  if (key.length !== 32) {
    throw new Error(`AEAD key must be 32 bytes (got ${key.length}).`);
  }
  const iv = options.iv ?? randomBytes(IV_LENGTH_BYTES);
  if (iv.length !== IV_LENGTH_BYTES) {
    throw new Error(`AEAD IV must be ${IV_LENGTH_BYTES} bytes (got ${iv.length}).`);
  }
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_LENGTH_BYTES });
  if (options.aad) cipher.setAAD(options.aad);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: enc, tag };
}

export interface OpenOptions {
  /** Additional authenticated data — MUST be byte-identical to the value used at seal time. */
  aad?: Buffer;
}

export function open(sealed: SealedPayload, key: Buffer, options: OpenOptions = {}): Buffer {
  if (key.length !== 32) {
    throw new Error(`AEAD key must be 32 bytes (got ${key.length}).`);
  }
  if (sealed.iv.length !== IV_LENGTH_BYTES) {
    throw new Error(`Vault IV must be ${IV_LENGTH_BYTES} bytes (got ${sealed.iv.length}).`);
  }
  if (sealed.tag.length !== TAG_LENGTH_BYTES) {
    throw new Error(`Vault auth tag must be ${TAG_LENGTH_BYTES} bytes (got ${sealed.tag.length}).`);
  }
  const decipher = createDecipheriv(ALGORITHM, key, sealed.iv, { authTagLength: TAG_LENGTH_BYTES });
  decipher.setAuthTag(sealed.tag);
  if (options.aad) decipher.setAAD(options.aad);
  try {
    return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
  } catch {
    // Mask the underlying crypto message so we don't leak whether the tag,
    // ciphertext, or AAD mismatch was the cause. The uniform error starves an
    // attacker of side channels and matches what the user actually needs to know.
    throw new Error("Vault decryption failed: wrong password or the file has been tampered with.");
  }
}

export const __aead_consts = { ALGORITHM, IV_LENGTH_BYTES, TAG_LENGTH_BYTES };
