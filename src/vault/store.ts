/**
 * High-level vault API used by the Insomnia tags and the migration tool.
 *
 * One vault holds many entries keyed by `identification` (an arbitrary label,
 * typically a uuIdentity or a free-form name like "my-bot"). Each entry stores
 * the two access codes and the OIDC server URL they belong to.
 *
 * Atomic writes: we always write to `<file>.tmp` and rename, so a crash never
 * leaves the user with a truncated vault file.
 */

import { chmod, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { open as aeadOpen, seal as aeadSeal } from "./aead";
import { decode, encode } from "./format";
import { DEFAULT_SCRYPT_PARAMS, deriveKey, type KdfParams } from "./kdf";
import {
  entryIdentification,
  entryStorageKey,
  isCompositeStorageKey,
  normalizeOidcServer,
  oidcServersMatch,
} from "./keys";

export interface VaultEntry {
  /** First access code (uuOIDC ROPC AC1, or generic username). */
  accessCode1: string;
  /** Second access code (uuOIDC ROPC AC2, or generic password). */
  accessCode2: string;
  /** OIDC token endpoint base URL this credential authenticates against. */
  oidcServer: string;
  /** Free-form metadata for forward-compatibility (notes, source, etc). */
  meta?: Record<string, string>;
}

export interface VaultContents {
  /** Map from identification → entry. */
  entries: Record<string, VaultEntry>;
}

export interface VaultLocation {
  /** Absolute path to the vault file. */
  filePath: string;
}

export const DEFAULT_VAULT_DIRNAME = ".plus4u-oidc-v2";
export const DEFAULT_VAULT_BASENAME = "vault.data";

export function defaultVaultPath(): string {
  return join(homedir(), DEFAULT_VAULT_DIRNAME, DEFAULT_VAULT_BASENAME);
}

export function resolveVaultPath(override?: string): string {
  return override ?? defaultVaultPath();
}

export async function vaultExists(filePath: string): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

export interface ReadVaultOptions {
  filePath?: string;
}

export async function readVault(password: string, options: ReadVaultOptions = {}): Promise<VaultContents> {
  const filePath = resolveVaultPath(options.filePath);
  const raw = await readFile(filePath);
  const parsed = decode(raw);
  const key = await deriveKey(password, parsed.salt, parsed.kdfParams);
  const plaintext = aeadOpen(
    { iv: parsed.iv, ciphertext: parsed.ciphertext, tag: parsed.tag },
    key,
    { aad: parsed.aad },
  );
  try {
    const data = JSON.parse(plaintext.toString("utf8")) as VaultContents;
    if (!data || typeof data !== "object" || !data.entries) {
      throw new Error("Vault payload missing 'entries' field.");
    }
    return data;
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new Error("Vault payload is not valid JSON (corruption or wrong password).");
    }
    throw err;
  }
}

export interface WriteVaultOptions {
  filePath?: string;
  kdfParams?: KdfParams;
}

export async function writeVault(
  contents: VaultContents,
  password: string,
  options: WriteVaultOptions = {},
): Promise<VaultLocation> {
  const filePath = resolveVaultPath(options.filePath);
  const kdfParams = options.kdfParams ?? DEFAULT_SCRYPT_PARAMS;
  const salt = randomBytes(32);
  const key = await deriveKey(password, salt, kdfParams);
  const plaintext = Buffer.from(JSON.stringify(contents), "utf8");

  // First pass encodes a placeholder so we know the AAD; we then seal with
  // that AAD and re-encode with the real ciphertext + tag.
  const placeholderTag = Buffer.alloc(16);
  const placeholderCt = Buffer.alloc(0);
  const placeholderIv = Buffer.alloc(12);
  const { aad } = encode({
    kdfParams,
    salt,
    iv: placeholderIv,
    ciphertext: placeholderCt,
    tag: placeholderTag,
  });

  const sealed = aeadSeal(plaintext, key, { aad });
  const { bytes } = encode({
    kdfParams,
    salt,
    iv: sealed.iv,
    ciphertext: sealed.ciphertext,
    tag: sealed.tag,
  });

  const parentDir = dirname(filePath);
  await mkdir(parentDir, { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.tmp`;
  await writeFile(tmpPath, bytes, { mode: 0o600 });
  await rename(tmpPath, filePath);
  // Windows ignores mode bits; on POSIX, umask can weaken mkdir/writeFile modes.
  if (process.platform !== "win32") {
    await chmod(filePath, 0o600);
    await chmod(parentDir, 0o700);
  }
  return { filePath };
}

export interface MutateOptions extends ReadVaultOptions {
  kdfParams?: KdfParams;
}

export interface EntryLookupOptions extends ReadVaultOptions {
  /** When set, selects the entry for this OIDC server (required if multiple exist). */
  oidcServer?: string;
}

function legacyEntryFor(
  entries: Record<string, VaultEntry>,
  identification: string,
  oidcServer?: string,
): VaultEntry | null {
  const legacy = entries[identification];
  if (!legacy) return null;
  if (oidcServer && !oidcServersMatch(legacy.oidcServer, oidcServer)) {
    return null;
  }
  return legacy;
}

function compositeEntryFor(
  entries: Record<string, VaultEntry>,
  identification: string,
  oidcServer: string,
): VaultEntry | null {
  return entries[entryStorageKey(identification, oidcServer)] ?? null;
}

/** Resolve an entry by user label + OIDC server (composite key, legacy key, or stored oidcServer). */
export function findEntryInContents(
  entries: Record<string, VaultEntry>,
  identification: string,
  oidcServer?: string,
): VaultEntry | null {
  const id = identification.trim();
  if (!id) return null;

  if (oidcServer) {
    const composite = compositeEntryFor(entries, id, oidcServer);
    if (composite) return composite;
    const legacy = legacyEntryFor(entries, id, oidcServer);
    if (legacy) return legacy;
    for (const key of listStorageKeysForIdentification(entries, id)) {
      const entry = entries[key];
      if (entry && oidcServersMatch(entry.oidcServer, oidcServer)) {
        return entry;
      }
    }
    return null;
  }

  const legacy = legacyEntryFor(entries, id);
  if (legacy) return legacy;
  const matches = listStorageKeysForIdentification(entries, id);
  if (matches.length === 1) {
    return entries[matches[0]!] ?? null;
  }
  return null;
}

/** All storage keys whose user label matches `identification`. */
export function listStorageKeysForIdentification(
  entries: Record<string, VaultEntry>,
  identification: string,
): string[] {
  return Object.keys(entries).filter((key) => entryIdentification(key) === identification);
}

export async function addEntry(
  identification: string,
  entry: VaultEntry,
  password: string,
  options: MutateOptions = {},
): Promise<VaultLocation> {
  const id = identification.trim();
  const existing = (await safeRead(password, options)) ?? { entries: {} };
  const normalizedEntry: VaultEntry = {
    ...entry,
    oidcServer: normalizeOidcServer(entry.oidcServer),
  };
  const key = entryStorageKey(id, normalizedEntry.oidcServer);
  if (id in existing.entries && !isCompositeStorageKey(id)) {
    delete existing.entries[id];
  }
  existing.entries[key] = normalizedEntry;
  return writeVault(existing, password, options);
}

export async function removeEntry(
  identification: string,
  password: string,
  options: EntryLookupOptions = {},
): Promise<VaultLocation> {
  const existing = (await safeRead(password, options)) ?? { entries: {} };
  const oidcServer = options.oidcServer?.trim();
  if (oidcServer) {
    const key = entryStorageKey(identification, oidcServer);
    delete existing.entries[key];
    const legacy = legacyEntryFor(existing.entries, identification, oidcServer);
    if (legacy) {
      delete existing.entries[identification];
    }
    return writeVault(existing, password, options);
  }

  const matches = listStorageKeysForIdentification(existing.entries, identification);
  if (matches.length === 0) {
    delete existing.entries[identification];
    return writeVault(existing, password, options);
  }
  if (matches.length === 1) {
    delete existing.entries[matches[0]!];
    return writeVault(existing, password, options);
  }
  throw new Error(
    `Multiple vault entries for '${identification}'. Pass oidcServer (CLI: --uri) to select which one to remove.`,
  );
}

export async function listEntries(password: string, options: ReadVaultOptions = {}): Promise<string[]> {
  const existing = (await safeRead(password, options)) ?? { entries: {} };
  return Object.keys(existing.entries).sort();
}

export async function getEntry(
  identification: string,
  password: string,
  options: EntryLookupOptions = {},
): Promise<VaultEntry | null> {
  const existing = (await safeRead(password, options)) ?? { entries: {} };
  const oidcServer = options.oidcServer?.trim();
  return findEntryInContents(existing.entries, identification, oidcServer || undefined);
}

async function safeRead(password: string, options: ReadVaultOptions): Promise<VaultContents | null> {
  const filePath = resolveVaultPath(options.filePath);
  if (!(await vaultExists(filePath))) {
    return null;
  }
  return readVault(password, options);
}
