/**
 * Reader for the legacy `oidc-plus4u-vault` file format (≤ 0.9.1).
 *
 * Legacy format (from jiridudekusy/keystore-insomnia-oidc-plus4u, lib/mycrypto.js):
 *
 *   - File is a UTF-8 string: `${ivHex}:${ciphertextHex}`
 *   - IV: 16 random bytes (AES-CTR)
 *   - Key: HMAC-SHA256(password, password)  — no salt, no stretching
 *   - Cipher: AES-256-CTR (no integrity tag — see THREAT_MODEL.md §"Legacy crypto")
 *   - Plaintext: JSON object — `{ [identification]: { ac1, ac2, oidcServer? } }`
 *
 * This module is READ-ONLY: it never writes back to the legacy file. The
 * migration tool consumes it and writes into the new vault format via
 * src/vault/store.
 */

import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { createDecipheriv, createHmac } from "node:crypto";
import type { VaultEntry } from "../vault/store";

export const LEGACY_DEFAULT_PATH = join(homedir(), ".oidc-plus4u-vault", "vault.data");

interface LegacyEntry {
  ac1: string;
  ac2: string;
  oidcServer?: string;
}

type LegacyVault = Record<string, LegacyEntry>;

function legacyKey(password: string): Buffer {
  return createHmac("sha256", password).digest();
}

export function decryptLegacy(rawFile: Buffer | string, password: string): LegacyVault {
  const text = typeof rawFile === "string" ? rawFile : rawFile.toString("utf8");
  const parts = text.split(":");
  if (parts.length < 2) {
    throw new Error("Legacy vault file is malformed (expected `<ivHex>:<ciphertextHex>`).");
  }
  const ivHex = parts.shift() as string;
  const ctHex = parts.join(":");
  const iv = Buffer.from(ivHex, "hex");
  const ciphertext = Buffer.from(ctHex, "hex");
  if (iv.length !== 16) {
    throw new Error(`Legacy vault IV must be 16 bytes (got ${iv.length}).`);
  }
  const key = legacyKey(password);
  const decipher = createDecipheriv("aes-256-ctr", key, iv);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext.toString("utf8"));
  } catch {
    // The legacy format has NO authentication; bad password just produces
    // gibberish that fails JSON parse. Treat that as "wrong password".
    throw new Error("Legacy vault decryption produced invalid JSON — usually means the wrong password.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Legacy vault contents are not an object.");
  }
  return parsed as LegacyVault;
}

export async function readLegacyVault(password: string, filePath: string = LEGACY_DEFAULT_PATH): Promise<LegacyVault> {
  const raw = await readFile(filePath);
  return decryptLegacy(raw, password);
}

export interface LegacyImport {
  identification: string;
  entry: VaultEntry;
}

const DEFAULT_LEGACY_OIDC_SERVER =
  "https://uuidentity.plus4u.net/uu-oidc-maing02/bb977a99f4cc4c37a2afce3fd599d0a7/oidc";

/** Normalizes a legacy vault into a list of new-format entries. */
export function legacyToEntries(vault: LegacyVault): LegacyImport[] {
  const out: LegacyImport[] = [];
  for (const [identification, legacy] of Object.entries(vault)) {
    if (!legacy || typeof legacy !== "object") continue;
    if (typeof legacy.ac1 !== "string" || typeof legacy.ac2 !== "string") continue;
    out.push({
      identification,
      entry: {
        accessCode1: legacy.ac1,
        accessCode2: legacy.ac2,
        oidcServer: typeof legacy.oidcServer === "string" && legacy.oidcServer.length > 0
          ? legacy.oidcServer
          : DEFAULT_LEGACY_OIDC_SERVER,
        meta: { migratedFrom: "oidc-plus4u-vault" },
      },
    });
  }
  return out;
}
