/**
 * CLI entry point for the new plugin's helper commands.
 *
 *   migrate-legacy-vault [--from <path>] [--to <path>] [--force]
 *   vault add    --user <id> [--uri <oidc>] [--vault <path>]
 *   vault delete --user <id> [--uri <oidc>] [--vault <path>]
 *   vault list                           [--vault <path>]
 *
 * `migrate-legacy-vault` reads a legacy `oidc-plus4u-vault` file, prompts
 * for its password and for the new vault password, and writes a fresh
 * new-format vault containing the same entries (the legacy file is never
 * modified). The `vault` group manages entries in an existing — or freshly
 * created — new-format vault.
 */

import { argv, exit, stdout } from "node:process";
import { entryStorageKey } from "../vault/keys";
import { defaultVaultPath, readVault, vaultExists, writeVault, type VaultContents } from "../vault/store";
import { LEGACY_DEFAULT_PATH, legacyToEntries, readLegacyVault } from "../migrate/legacy-vault";
import { promptPassword, promptText } from "../util/prompt";
import { error as logError, info as logInfo } from "../util/log";
import { ropc as ropcImpl } from "../auth/ropc";
import {
  DEFAULT_PLUS4U_OIDC_SERVER,
  runVaultAdd,
  runVaultDelete,
  runVaultList,
  type VaultCliDeps,
} from "./vault";

interface ParsedArgs {
  /** First non-flag positional token (kept for backward compatibility with the single-command era). */
  command: string | undefined;
  /** Every non-flag positional token in order — used for multi-level dispatch like `vault add`. */
  positionals: string[];
  options: Map<string, string>;
  flags: Set<string>;
}

function parseArgs(rawArgs: readonly string[]): ParsedArgs {
  const options = new Map<string, string>();
  const flags = new Set<string>();
  const positionals: string[] = [];
  for (let i = 0; i < rawArgs.length; i += 1) {
    const token = rawArgs[i];
    if (token === undefined) continue;
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const next = rawArgs[i + 1];
      if (next !== undefined && !next.startsWith("--")) {
        options.set(key, next);
        i += 1;
      } else {
        flags.add(key);
      }
    } else {
      positionals.push(token);
    }
  }
  return { command: positionals[0], positionals, options, flags };
}

function printHelp(): void {
  stdout.write(
    [
      "insomnia-plugin-plus4u-oidc-v2 — CLI helpers",
      "",
      "Usage: oidc-plus4u-vault-v2 <command> [options]",
      "       (alias: insomnia-plugin-plus4u-oidc-v2 <command> [options])",
      "       (in a source clone, with no global install: node bin/cli.js <command> [options])",
      "",
      "Commands:",
      "  migrate-legacy-vault   Re-encrypt a legacy `oidc-plus4u-vault` file into the new format.",
      "  vault add              Interactively add (or overwrite) a vault entry. Tests the credentials against the OIDC server first.",
      "  vault delete           Remove a vault entry (by user; use --uri if several OIDC servers share the label).",
      "  vault list             Print one line per entry: `<user> - <oidc-server-url>`.",
      "  help                   Show this help.",
      "",
      "migrate-legacy-vault options:",
      `  --from <path>          Path to the legacy vault file. Default: ${LEGACY_DEFAULT_PATH}`,
      `  --to   <path>          Path to write the new vault to. Default: ${defaultVaultPath()}`,
      "  --force                Overwrite the destination vault if it already exists.",
      "",
      "vault add options:",
      "  --user <id>            REQUIRED. Identification (label) under which the entry is stored.",
      `  --uri  <url>           OIDC server URL. Default: ${DEFAULT_PLUS4U_OIDC_SERVER}`,
      `  --vault <path>         Vault file path. Default: ${defaultVaultPath()}`,
      "",
      "vault delete options:",
      "  --user <id>            REQUIRED. Identification of the entry to remove.",
      "  --uri  <url>           OIDC server URL (required when multiple entries share the same --user).",
      `  --vault <path>         Vault file path. Default: ${defaultVaultPath()}`,
      "",
      "vault list options:",
      `  --vault <path>         Vault file path. Default: ${defaultVaultPath()}`,
      "",
    ].join("\n"),
  );
}

function printVaultHelp(): void {
  stdout.write(
    [
      "Usage: oidc-plus4u-vault-v2 vault <add|delete|list> [options]",
      "Run `oidc-plus4u-vault-v2 help` for the full option reference.",
      "",
    ].join("\n"),
  );
}

const defaultDeps: VaultCliDeps = {
  promptText,
  promptPassword,
  ropc: ropcImpl,
  stdout: { write: (s) => stdout.write(s) },
  log: { info: logInfo, error: logError },
};

async function runMigrate(options: Map<string, string>, flags: Set<string>): Promise<number> {
  const from = options.get("from") ?? LEGACY_DEFAULT_PATH;
  const to = options.get("to") ?? defaultVaultPath();
  const force = flags.has("force");

  logInfo(`Reading legacy vault from ${from}`);
  if (!(await vaultExists(from))) {
    logError(`Legacy vault file not found at ${from}.`);
    return 2;
  }

  const oldPassword = await promptPassword("Legacy vault password: ");
  let legacy;
  try {
    legacy = await readLegacyVault(oldPassword, from);
  } catch (err) {
    logError(`Could not read legacy vault: ${(err as Error).message}`);
    return 3;
  }

  const imports = legacyToEntries(legacy);
  logInfo(`Loaded ${imports.length} entries from the legacy vault.`);

  if (await vaultExists(to)) {
    if (!force) {
      logError(`Destination vault already exists at ${to}. Re-run with --force to overwrite, or pick a different --to path.`);
      return 4;
    }
    logInfo(`--force was passed; the existing vault at ${to} will be overwritten.`);
  }

  let mergedNewVault: VaultContents = { entries: {} };
  if (await vaultExists(to) && !force) {
    // Defensive — `force` checked above, but kept here so a future refactor
    // that allows merging instead of overwriting has the read in place.
    const newPassword = await promptPassword("Existing new vault password (for merge): ");
    mergedNewVault = await readVault(newPassword, { filePath: to });
  }

  for (const item of imports) {
    mergedNewVault.entries[entryStorageKey(item.identification, item.entry.oidcServer)] = item.entry;
  }

  const password1 = await promptPassword("New vault password: ");
  const password2 = await promptPassword("Retype new vault password: ");
  if (password1 !== password2) {
    logError("Passwords do not match.");
    return 5;
  }
  if (password1.length < 12) {
    logError("New vault password must be at least 12 characters long.");
    return 6;
  }

  const written = await writeVault(mergedNewVault, password1, { filePath: to });
  logInfo(`Migration complete. New vault written to ${written.filePath}.`);
  logInfo(`The legacy file at ${from} was NOT modified.`);
  logInfo(`Once you have verified the new vault works in Insomnia, remove the legacy file with:`);
  logInfo(`  rm '${from}'`);
  return 0;
}

export async function main(rawArgs: readonly string[] = argv.slice(2)): Promise<number> {
  const args = parseArgs(rawArgs);
  switch (args.command) {
    case undefined:
    case "help":
    case "--help":
    case "-h":
      printHelp();
      return 0;
    case "migrate-legacy-vault":
      return runMigrate(args.options, args.flags);
    case "vault":
      return runVaultGroup(args.positionals[1], args.options, args.flags);
    default:
      logError(`Unknown command: ${args.command}`);
      printHelp();
      return 1;
  }
}

async function runVaultGroup(
  subcommand: string | undefined,
  options: Map<string, string>,
  flags: Set<string>,
): Promise<number> {
  switch (subcommand) {
    case "add":
      return runVaultAdd(options, flags, defaultDeps);
    case "delete":
      return runVaultDelete(options, flags, defaultDeps);
    case "list":
      return runVaultList(options, defaultDeps);
    case undefined:
      logError("`vault` requires a subcommand: add, delete, or list.");
      printVaultHelp();
      return 1;
    default:
      logError(`Unknown vault subcommand: ${subcommand}`);
      printVaultHelp();
      return 1;
  }
}

if (require.main === module) {
  main()
    .then((code) => exit(code))
    .catch((err: unknown) => {
      logError(`Unhandled error: ${(err as Error).message}`);
      exit(99);
    });
}
