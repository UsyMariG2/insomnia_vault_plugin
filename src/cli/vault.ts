/**
 * Vault CLI subcommands: `add`, `delete`, `list`, `import`.
 *
 * Wired by [src/migrate/cli.ts](../migrate/cli.ts), which dispatches on the
 * second positional token (`cli vault add`, `cli vault delete`, `cli vault
 * list`). All side effects (prompts, ROPC HTTP call, vault read/write, log,
 * stdout) are routed through the `VaultCliDeps` injection so the handlers
 * are unit-testable without a TTY, network, or the user's real vault.
 *
 * `add` performs a live ROPC credential test against the OIDC server BEFORE
 * persisting the entry — wrong credentials are caught at write time, not at
 * the first Insomnia request hours later.
 *
 * The vault file is created on the fly with a fresh password (with retype
 * and 12-char minimum, matching `migrate-legacy-vault`) when `add` is run
 * against a non-existent path. `delete` and `list` require an existing
 * vault.
 */

import type { ropc as RopcFn } from "../auth/ropc";
import {
  entryIdentification,
  entryOidcFromKey,
} from "../vault/keys";
import {
  addEntry,
  defaultVaultPath,
  listStorageKeysForIdentification,
  readVault,
  removeEntry,
  resolveVaultPath,
  vaultExists,
  writeVault,
  type VaultContents,
  type VaultEntry,
} from "../vault/store";

export interface VaultCliDeps {
  promptText: (q: string) => Promise<string>;
  promptPassword: (q: string) => Promise<string>;
  ropc: typeof RopcFn;
  stdout: { write: (s: string) => void };
  log: { info: (s: string) => void; error: (s: string) => void };
}

/**
 * Plus4U production uuOIDC endpoint. Used as the `--uri` default for
 * `vault add` when the user does not supply one. Intentionally inlined
 * here rather than pulled from a shared module because the same literal is
 * already duplicated across three places in the codebase
 * (`src/tags/uu-person-token.ts`, `src/tags/uu-ee-token.ts`,
 * `src/migrate/legacy-vault.ts`); consolidating them is orthogonal cleanup.
 */
export const DEFAULT_PLUS4U_OIDC_SERVER =
  "https://uuidentity.plus4u.net/uu-oidc-maing02/bb977a99f4cc4c37a2afce3fd599d0a7/oidc";

const NEW_VAULT_PASSWORD_MIN_LENGTH = 12;

export async function runVaultAdd(
  options: Map<string, string>,
  _flags: Set<string>,
  deps: VaultCliDeps,
): Promise<number> {
  const user = (options.get("user") ?? "").trim();
  if (!user) {
    deps.log.error("`vault add` requires --user <identification>.");
    return 2;
  }

  const uriArg = (options.get("uri") ?? "").trim();
  const oidcServer = uriArg || DEFAULT_PLUS4U_OIDC_SERVER;
  if (!isHttpUrl(oidcServer)) {
    deps.log.error(`--uri must be a http(s):// URL (got: ${oidcServer}).`);
    return 2;
  }

  const filePath = resolveVaultPath(options.get("vault"));

  const accessCode1 = await deps.promptPassword("Access Code 1 (username): ");
  if (!accessCode1) {
    deps.log.error("Access Code 1 cannot be empty.");
    return 2;
  }
  const accessCode2 = await deps.promptPassword("Access Code 2 (password): ");
  if (!accessCode2) {
    deps.log.error("Access Code 2 cannot be empty.");
    return 2;
  }

  deps.log.info(`Testing credentials against ${oidcServer} ...`);
  try {
    const result = await deps.ropc({
      oidcServer,
      scope: "openid",
      accessCode1,
      accessCode2,
      shape: "uu-oidc",
      validateTls: true,
    });
    if (!result.idToken) {
      deps.log.error("Credentials test failed: OIDC server did not return an id_token.");
      return 3;
    }
  } catch (err) {
    deps.log.error(`Credentials test failed: ${(err as Error).message}`);
    return 3;
  }
  deps.log.info("Credentials accepted by OIDC server.");

  const entry: VaultEntry = { accessCode1, accessCode2, oidcServer };

  if (!(await vaultExists(filePath))) {
    deps.log.info(`No vault file at ${filePath}; creating a new one.`);
    const pw1 = await deps.promptPassword("New vault password: ");
    const pw2 = await deps.promptPassword("Retype new vault password: ");
    if (pw1 !== pw2) {
      deps.log.error("Passwords do not match.");
      return 5;
    }
    if (pw1.length < NEW_VAULT_PASSWORD_MIN_LENGTH) {
      deps.log.error(`New vault password must be at least ${NEW_VAULT_PASSWORD_MIN_LENGTH} characters long.`);
      return 6;
    }
    await addEntry(user, entry, pw1, { filePath });
    deps.log.info(`Stored '${user}' in vault ${filePath}.`);
    return 0;
  }

  const password = await deps.promptPassword("Vault password: ");
  try {
    await addEntry(user, entry, password, { filePath });
  } catch (err) {
    deps.log.error(`Could not update vault: ${(err as Error).message}`);
    return 4;
  }
  deps.log.info(`Stored '${user}' in vault ${filePath}.`);
  return 0;
}

export async function runVaultDelete(
  options: Map<string, string>,
  _flags: Set<string>,
  deps: VaultCliDeps,
): Promise<number> {
  const user = (options.get("user") ?? "").trim();
  if (!user) {
    deps.log.error("`vault delete` requires --user <identification>.");
    return 2;
  }
  const uriArg = (options.get("uri") ?? "").trim();
  const oidcServer = uriArg || undefined;
  if (oidcServer && !isHttpUrl(oidcServer)) {
    deps.log.error(`--uri must be a http(s):// URL (got: ${oidcServer}).`);
    return 2;
  }
  const filePath = resolveVaultPath(options.get("vault"));

  if (!(await vaultExists(filePath))) {
    deps.log.error(`No vault file at ${filePath}.`);
    return 5;
  }

  const password = await deps.promptPassword("Vault password: ");
  let existing;
  try {
    existing = await readVault(password, { filePath });
  } catch (err) {
    deps.log.error(`Could not read vault: ${(err as Error).message}`);
    return 4;
  }
  const matches = listStorageKeysForIdentification(existing.entries, user);
  const legacyOnly = user in existing.entries && matches.length === 0;
  if (matches.length === 0 && !legacyOnly) {
    deps.log.error(`No entry for '${user}' in vault ${filePath}.`);
    return 6;
  }
  if (!oidcServer && matches.length > 1) {
    deps.log.error(
      `Multiple OIDC entries for '${user}'. Re-run with --uri <oidc-server-url> to pick one.`,
    );
    return 7;
  }
  try {
    await removeEntry(user, password, { filePath, oidcServer });
  } catch (err) {
    deps.log.error(`Could not update vault: ${(err as Error).message}`);
    return 4;
  }
  deps.log.info(`Removed '${user}' from vault ${filePath}.`);
  return 0;
}

export async function runVaultList(
  options: Map<string, string>,
  deps: VaultCliDeps,
): Promise<number> {
  const filePath = resolveVaultPath(options.get("vault"));
  if (!(await vaultExists(filePath))) {
    deps.stdout.write(`(no vault file at ${filePath})\n`);
    return 0;
  }
  const password = await deps.promptPassword("Vault password: ");
  let existing;
  try {
    existing = await readVault(password, { filePath });
  } catch (err) {
    deps.log.error(`Could not read vault: ${(err as Error).message}`);
    return 4;
  }
  const ids = Object.keys(existing.entries).sort();
  if (ids.length === 0) {
    deps.stdout.write("(vault contains no entries)\n");
    return 0;
  }
  for (const id of ids) {
    const entry = existing.entries[id];
    if (!entry) continue;
    const label = entryIdentification(id);
    const oidc = entryOidcFromKey(id, entry.oidcServer);
    deps.stdout.write(`${label} - ${oidc}\n`);
  }
  return 0;
}

export async function runVaultImport(
  options: Map<string, string>,
  _flags: Set<string>,
  deps: VaultCliDeps,
): Promise<number> {
  const sourcePath = (options.get("source") ?? options.get("s") ?? "").trim();
  if (!sourcePath) {
    deps.log.error("`vault import` requires --source <path> (or -s <path>).");
    return 2;
  }

  const targetPath = resolveVaultPath(options.get("vault"));
  if (sourcePath === targetPath) {
    deps.log.error("Source and target vault paths must be different.");
    return 2;
  }

  if (!(await vaultExists(sourcePath))) {
    deps.log.error(`Source vault file not found at ${sourcePath}.`);
    return 3;
  }

  const sourcePassword = await deps.promptPassword("Source vault password: ");
  let sourceVault: VaultContents;
  try {
    sourceVault = await readVault(sourcePassword, { filePath: sourcePath });
  } catch (err) {
    deps.log.error(`Could not read source vault: ${(err as Error).message}`);
    return 3;
  }

  const importCount = Object.keys(sourceVault.entries).length;

  let targetPassword: string;
  let merged: VaultContents = { entries: {} };

  if (!(await vaultExists(targetPath))) {
    deps.log.info(`No vault file at ${targetPath}; creating a new one.`);
    const pw1 = await deps.promptPassword("New vault password: ");
    const pw2 = await deps.promptPassword("Retype new vault password: ");
    if (pw1 !== pw2) {
      deps.log.error("Passwords do not match.");
      return 5;
    }
    if (pw1.length < NEW_VAULT_PASSWORD_MIN_LENGTH) {
      deps.log.error(`New vault password must be at least ${NEW_VAULT_PASSWORD_MIN_LENGTH} characters long.`);
      return 6;
    }
    targetPassword = pw1;
  } else {
    targetPassword = await deps.promptPassword("Vault password: ");
    try {
      merged = await readVault(targetPassword, { filePath: targetPath });
    } catch (err) {
      deps.log.error(`Could not read target vault: ${(err as Error).message}`);
      return 4;
    }
  }

  for (const [key, entry] of Object.entries(sourceVault.entries)) {
    merged.entries[key] = entry;
  }

  try {
    await writeVault(merged, targetPassword, { filePath: targetPath });
  } catch (err) {
    deps.log.error(`Could not write target vault: ${(err as Error).message}`);
    return 4;
  }

  deps.log.info(`Imported ${importCount} entries into vault ${targetPath}.`);
  deps.log.info(`The source vault at ${sourcePath} was NOT modified.`);
  return 0;
}

function isHttpUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

/** Re-export so the CLI dispatcher and tests can share one default path. */
export { defaultVaultPath };
