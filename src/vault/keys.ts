/**
 * Vault entry keys: one identification may map to multiple OIDC servers.
 *
 * New entries are stored under a composite key `identification + SEP + oidcServer`.
 * Legacy vaults used `identification` alone; readers still resolve those keys.
 */

/** Record separator — unlikely in user-chosen labels or URLs. */
export const VAULT_ENTRY_KEY_SEP = "\x1e";

export function normalizeOidcServer(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

/** True when both values denote the same OIDC base URL (trim, no trailing slash). */
export function oidcServersMatch(a: string, b: string): boolean {
  return normalizeOidcServer(a) === normalizeOidcServer(b);
}

export function entryStorageKey(identification: string, oidcServer: string): string {
  return `${identification}${VAULT_ENTRY_KEY_SEP}${normalizeOidcServer(oidcServer)}`;
}

export function isCompositeStorageKey(key: string): boolean {
  return key.includes(VAULT_ENTRY_KEY_SEP);
}

/** User-facing label from a storage key (composite or legacy). */
export function entryIdentification(key: string): string {
  const idx = key.indexOf(VAULT_ENTRY_KEY_SEP);
  return idx >= 0 ? key.slice(0, idx) : key;
}

export function entryOidcFromKey(key: string, entryOidc: string): string {
  const idx = key.indexOf(VAULT_ENTRY_KEY_SEP);
  return idx >= 0 ? key.slice(idx + 1) : entryOidc;
}
