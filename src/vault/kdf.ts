/**
 * Password-based key derivation for the vault.
 *
 * Two algorithms are supported so we can grow without another breaking format
 * change later:
 *   - "scrypt"   (default) — memory-hard, recommended; N=2^15, r=8, p=1.
 *   - "pbkdf2-sha256"      — fallback for environments without enough memory;
 *                            iterations=600_000 (OWASP 2023 minimum).
 *
 * scrypt parameters were chosen so derivation takes ~250-500ms on a 2020-era
 * laptop while staying under Node's default 32 MiB scrypt memory cap (N=2^15,
 * r=8 ⇒ ~32 MiB). Increase `N` in a future format version when hardware moves.
 */

import { promisify } from "node:util";
import { pbkdf2 as pbkdf2Cb, scrypt as scryptCb } from "node:crypto";

const scrypt = promisify(scryptCb) as (
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

const pbkdf2 = promisify(pbkdf2Cb) as (
  password: string | Buffer,
  salt: Buffer,
  iterations: number,
  keylen: number,
  digest: string,
) => Promise<Buffer>;

export type KdfAlgorithm = "scrypt" | "pbkdf2-sha256";

export interface KdfParams {
  algorithm: KdfAlgorithm;
  /** scrypt cost parameter (log2 N). */
  logN?: number;
  /** scrypt block size. */
  r?: number;
  /** scrypt parallelization. */
  p?: number;
  /** pbkdf2 iteration count. */
  iterations?: number;
}

export const DEFAULT_SCRYPT_PARAMS: KdfParams = {
  algorithm: "scrypt",
  logN: 15,
  r: 8,
  p: 1,
};

export const DEFAULT_PBKDF2_PARAMS: KdfParams = {
  algorithm: "pbkdf2-sha256",
  iterations: 600_000,
};

const KEY_LENGTH_BYTES = 32;

export async function deriveKey(password: string, salt: Buffer, params: KdfParams): Promise<Buffer> {
  if (!password) {
    throw new Error("Vault password must not be empty.");
  }
  if (salt.length < 16) {
    throw new Error(`Vault salt must be at least 16 bytes (got ${salt.length}).`);
  }

  switch (params.algorithm) {
    case "scrypt": {
      const logN = params.logN ?? DEFAULT_SCRYPT_PARAMS.logN!;
      const r = params.r ?? DEFAULT_SCRYPT_PARAMS.r!;
      const p = params.p ?? DEFAULT_SCRYPT_PARAMS.p!;
      const N = 1 << logN;
      const maxmem = Math.max(128 * N * r * 2, 64 * 1024 * 1024);
      return scrypt(password, salt, KEY_LENGTH_BYTES, { N, r, p, maxmem });
    }
    case "pbkdf2-sha256": {
      const iterations = params.iterations ?? DEFAULT_PBKDF2_PARAMS.iterations!;
      if (iterations < 600_000) {
        throw new Error(`PBKDF2 iteration count must be at least 600000 (got ${iterations}).`);
      }
      return pbkdf2(password, salt, iterations, KEY_LENGTH_BYTES, "sha256");
    }
    default: {
      const exhaustive: never = params.algorithm;
      throw new Error(`Unknown KDF algorithm: ${String(exhaustive)}`);
    }
  }
}

export function paramsToHeader(params: KdfParams): Record<string, number | string> {
  switch (params.algorithm) {
    case "scrypt":
      return {
        kdf: "scrypt",
        logN: params.logN ?? DEFAULT_SCRYPT_PARAMS.logN!,
        r: params.r ?? DEFAULT_SCRYPT_PARAMS.r!,
        p: params.p ?? DEFAULT_SCRYPT_PARAMS.p!,
      };
    case "pbkdf2-sha256":
      return {
        kdf: "pbkdf2-sha256",
        iterations: params.iterations ?? DEFAULT_PBKDF2_PARAMS.iterations!,
      };
  }
}

export function headerToParams(header: Record<string, unknown>): KdfParams {
  const kdf = header.kdf;
  if (kdf === "scrypt") {
    return {
      algorithm: "scrypt",
      logN: Number(header.logN ?? DEFAULT_SCRYPT_PARAMS.logN),
      r: Number(header.r ?? DEFAULT_SCRYPT_PARAMS.r),
      p: Number(header.p ?? DEFAULT_SCRYPT_PARAMS.p),
    };
  }
  if (kdf === "pbkdf2-sha256") {
    return {
      algorithm: "pbkdf2-sha256",
      iterations: Number(header.iterations ?? DEFAULT_PBKDF2_PARAMS.iterations),
    };
  }
  throw new Error(`Unsupported KDF in vault header: ${String(kdf)}`);
}
