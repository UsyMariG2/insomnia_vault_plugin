# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-06-18

### Changed

- `uuEePlus4uOidcToken` resolves the file-vault password and access codes from
  Insomnia's render context instead of OS environment variables (which
  GUI-launched Insomnia never inherits). Order per value: Insomnia **Secret**
  variable (`vault.*`, encrypted) → interactive prompt (pre-v13) → plain
  Insomnia environment variable (last resort). Variable names are unchanged
  (`PLUS4U_OIDC_V2_VAULT_PASSWORD`, `PLUS4U_OIDC_V2_ACCESS_CODE_1` / `_2`,
  per-identification `PLUS4U_OIDC_V2_<IDENT>_AC1` / `_AC2`). On failure the tag
  embeds a non-secret `(diag: …)` suffix and logs safe diagnostics to the
  Insomnia main-process log (`main.log`). (`src/util/insomnia-prompt.ts`,
  `src/tags/uu-ee-token.ts`)
### Added

- `vault import --source <path> [-s <path>] [--vault <path>]` — merge entries
  from another new-format vault into the target vault (`src/cli/vault.ts`).
  Creates the target vault with a new password when it does not exist yet
  (same rules as `vault add`). Source entries overwrite collisions. The
  source file is never modified.

## [1.0.0] - 2026-06-10

### Added

- Initial public release on the
  [npm registry](https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc-v2).
  Install the Insomnia plugin from **Preferences → Plugins**, or the vault
  CLI globally with `npm install -g insomnia-plugin-plus4u-oidc-v2`
  (`npx uu-safe-install -g …` on Plus4U workstations).

### Documentation

- `README.md`, `MIGRATION.md`, `PUBLISHING.md`: end-user docs describe
  public npm install only (Insomnia UI and global `oidc-plus4u-vault-v2`
  CLI). Removed tarball, git-clone, symlink, `npm link`, and other
  local-development install paths, plus unpublished / pre-release wording.

## [1.0.0-rc.3] - 2026-06-09

### Added

- `src/auth/jwks.ts`: asynchronous id_token signature verification against the
  OIDC issuer JWKS (RS256/RS384/RS512) before a token is cached. JWKS
  documents are cached in memory for 24 hours per `jwks_uri`.
- `uuPersonPlus4uOidcToken`: configurable **Token scope** field (same as the
  uuEE tag). Pass the uuApp scope (e.g.
  `openid uu-oidc:unregistered-client:<awid>`) to avoid
  `authentication/invalidCredentials` / "Token scope does not match" errors.

### Security

- Successful id_tokens are verified against the OIDC server's JWKS before
  `storeOk` caches them. Tokens with invalid signatures, unknown `kid`, or
  unreachable JWKS are rejected.

### Fixed

- All interactive auth tags (`uuPersonPlus4uOidcToken`,
  `uuPersonCustomOidcToken`, `uuEePlus4uOidcToken`): debounce browser login /
  ROPC by ~1000 ms after the last config change so editing string fields
  (especially **Token scope**) in Insomnia no longer opens a new browser tab
  on every keystroke. Cached tokens are still returned immediately.

## [1.0.0-rc.2] - 2026-06-04

### Changed

- `src/vault/keys.ts`, `src/vault/store.ts`: one identification label may
  now map to **multiple OIDC servers** (e.g. the same uuIdentity for prod
  and dev). New module `src/vault/keys.ts` provides
  `normalizeOidcServer`, `oidcServersMatch`, `entryStorageKey`,
  `entryIdentification`, and `entryOidcFromKey`. New entries are stored
  under a composite map key `identification + 0x1E + normalizedOidcServer`;
  legacy vaults that keyed entries by identification alone remain readable.
  `addEntry` writes composite keys and transparently upgrades a legacy
  single-key entry on overwrite; `findEntryInContents`, `getEntry`, and
  `removeEntry` accept an optional `oidcServer` to disambiguate.
  `migrate-legacy-vault` writes imported entries under composite keys to
  match `vault add`.
- `src/tags/uu-ee-token.ts`: session credential cache and vault lookup
  are keyed by `(identification, oidcServer)` instead of identification
  alone — the same label can hold prod and dev credentials when the tag's
  **OIDC Server** field differs (typically via environment variables).
- `src/auth/authorize.ts`: `authorize()` now defaults `client_id` to the
  Plus4U public-client sentinel `00000000000000000000000000000000` when
  the caller does not supply one. Empty and whitespace-only strings from
  `uuPersonCustomOidcToken`'s `Client ID` field are treated the same way.
  The same effective value is sent on
  both `/oidc/auth` and the matching `/oidc/token` PKCE exchange to
  satisfy OIDC servers (including Plus4U) that require `client_id` for
  public clients (RFC 6749 §4.1.3 mandates `client_id` at the token
  endpoint for any public client that is not authenticating). Result:
  out-of-the-box use of `uuPersonPlus4uOidcToken` and an empty `Client ID` field on `uuPersonCustomOidcToken` both work without any further
  configuration. Exported `DEFAULT_OIDC_CLIENT_ID` plus the previously
  internal `buildAuthzUrl` so the sentinel behavior is unit-testable.
- `src/auth/authorize.ts`: `validateIdToken` is now invoked with
  `expectedAudience` **only** when the caller supplied an explicit
  `client_id`. The sentinel default is never used as `expectedAudience`
  — Plus4U's `aud` claim is the resolved identity, not `0…0`, so
  enforcing the sentinel would reject every legitimate token. Likewise
  the success-redirect URL (`buildRedirect`) only appends `?clientId=…`
  for explicit values; it never leaks the sentinel into the info-page.
  ROPC (`uuEePlus4uOidcToken`) is intentionally unchanged.
- `src/tags/uu-person-custom-token.ts`: help text on the optional
  `Client ID` field now explains the new sentinel default and when it
  is necessary to fill in a real registered client_id instead.
- `README.md` install section rewritten to document the **tarball install**
  and the **developer (symlink) install** paths. The old `Manual` block had
  a chicken-and-egg bug (`npm install --omit=dev` followed by `npm run build` could not work because `tsc` was a devDep).
- `package.json` `files` allow-list tightened to `dist/src/` so the
  published tarball no longer ships test code (37 → 31 files; 42.7 → 39.4 KB).

### Added

- `bin/cli.js vault add --user <id> [--uri <oidc-server>] [--vault <path>]`
  — interactively prompts for `Access Code 1` (username) and `Access Code 2` (password), runs a live ROPC token request against the OIDC
  server to validate the credentials, and only writes the entry to the
  encrypted vault on success. Wrong credentials are caught at write
  time instead of at the first Insomnia request hours later. `--uri`
  defaults to the Plus4U production uuOIDC URL. Creates a brand-new
  vault on the fly (with password + retype + 12-character minimum,
  matching `migrate-legacy-vault`) when the target file does not exist.
- `bin/cli.js vault delete --user <id> [--uri <oidc-server>] [--vault <path>]` — removes the
  named entry from the encrypted vault. When several entries share the
  same `--user` label but differ in OIDC server URL, `--uri` is required
  to select which one to remove.
- `bin/cli.js vault list [--vault <path>]` — prints one line per entry
  in `<user> - <oidc-server-url>` format (user-facing label, not the
  internal composite storage key), sorted alphabetically.
- `src/cli/vault.ts` — vault CLI handlers (`add`, `delete`, `list`)
  extracted from the main CLI dispatcher; all side effects are injected
  via `VaultCliDeps` so the handlers are unit-testable without a TTY,
  network, or the user's real vault.
- `test/cli-vault.test.ts` — unit tests for `runVaultAdd`, `runVaultDelete`,
  and `runVaultList` (temp vault, stubbed prompts/ROPC/log/stdout).
- `test/authorize.test.ts` — unit tests for `DEFAULT_OIDC_CLIENT_ID` and
  exported `buildAuthzUrl`.
- `test/vault-store.test.ts`: composite-key and legacy-key resolution
  cases for `findEntryInContents`.
- `test/token.test.ts`: `exchangeCodeForToken` unit tests — sentinel
  `client_id` round-trips into the URL-encoded body; omission when the
  caller passes none.
- Convenience npm scripts: `npm run vault:add`, `npm run vault:delete`,
  `npm run vault:list` — thin wrappers around the corresponding
  `bin/cli.js` invocations.
- `package.json` `bin` now exposes a second, short global command name
  `oidc-plus4u-vault-v2` in addition to the existing
  `insomnia-plugin-plus4u-oidc-v2`. After `npm install -g insomnia-plugin-plus4u-oidc-v2`
  (once on the registry), `npm install -g .` from a clone, or
  `npm link` from the working tree, you can invoke every CLI command
  directly as `oidc-plus4u-vault-v2 vault add --user ...` /
  `oidc-plus4u-vault-v2 migrate-legacy-vault ...` instead of the
  `node bin/cli.js ...` form that only works inside the source tree.
  Both bin names symlink to the same `bin/cli.js` shim, so any
  documentation or muscle memory built around the long name keeps
  working. The shorter name is deliberately **not** `oidc-plus4u-vault`
  (the legacy package's binary) so the two can coexist on a single
  machine during a migration window. `printHelp()` and `printVaultHelp()`
  banners now lead with the short name as well.
- `[PUBLISHING.md](PUBLISHING.md)` — internal maintainer runbook for
  tarball releases, public npm releases, the Plus4U `.npmrc` install-time
  gotcha and three workarounds (per-install registry override, scoped
  registry mapping, tarball install), and the Nexus private-registry
  release path.
- `package.json` `uu-safe-install` script — convenience wrapper around
  `npx uu-safe-install` for Unicorn-internal workstations.

### Documentation

- `README.md`, `[MIGRATION.md](MIGRATION.md)`, `[PUBLISHING.md](PUBLISHING.md)`:
  cross-platform overhaul — **Platform paths** tables (macOS / Linux /
  Windows) for Insomnia plugins, vault files, settings DB, and user
  `.npmrc`; PowerShell and CMD examples for install, migrate, tarball
  extract, developer junction/symlink, cleanup, and rollback; Windows
  tarball install via built-in `tar` (Windows 10+); NTFS ACL note for
  vault permissions where POSIX modes are not enforced.
- `README.md`, `MIGRATION.md`, `PUBLISHING.md`: **Installing dependencies**
  guidance — Unicorn coworkers use `npx uu-safe-install` (same flags as
  npm, including `-g` and `--omit=dev`); everyone else keeps standard
  `npm install`.
- `MIGRATION.md`: expanded operator runbook — per-step Windows variants,
  `migrate-legacy-vault` exit-code table, rollback procedure, fleet
  checklist; §"Install the new plugin" points to the Insomnia 11+
  elevated-access prerequisite.
- `README.md`: `uuEePlus4uOidcToken` and vault-management sections explain
  prod/dev credential pairs under one identification label and the
  matching `vault add --uri` / `vault delete --uri` workflow.
- `VAULT_FORMAT.md` §4: documents composite map keys and backward-compatible
  legacy `identification`-only keys.
- `README.md` now opens with a `Prerequisite: enable "Allow elevated access for plugins"` section and adds a matching first row to the
  Troubleshooting table. Insomnia 11+ otherwise renders every template
  tag from external plugins as `unknown block tag: <name>` because the
  templating Web Worker only sees tags from the hard-coded bundle plugin
  list (`@kong/insomnia-plugin-external-vault`, `@kong/insomnia-plugin-ai`).
  Toggling the setting promotes external plugins into that pipeline.
  References: Kong/insomnia
  [#8917](https://github.com/Kong/insomnia/issues/8917),
  [#8708](https://github.com/Kong/insomnia/issues/8708),
  [#9211](https://github.com/Kong/insomnia/issues/9211),
  [PR #9759](https://github.com/Kong/insomnia/pull/9759).

### Fixed

- `src/auth/callback-server.ts`: drop the trailing `.unref()` on the
  5-minute idle-timeout `setTimeout`. With `Allow elevated access for plugins` enabled — the only mode in which external template tags
  actually fire — Insomnia executes plugins in the Electron renderer
  process (`renderInThisProcess`, see entry.main.min.js gated on
  `pluginsAllowElevatedAccess`). The renderer's `globalThis.setTimeout`
  is Chromium's DOM API and returns a `number`, not a Node `Timeout`, so
  `setTimeout(...).unref()` threw `TypeError: setTimeout(...).unref is not a function` and crashed every render of `uuPersonPlus4uOidcToken`
  and `uuPersonCustomOidcToken`. The crash result was then cached for
  five minutes by `src/util/token-cache.ts`, producing the visible
  `-- plus4u-oidc-v2 token-error-cached: setTimeout(...).unref is not a function … --` message until the per-tag `Disabled` toggle was flipped.
  `uuEePlus4uOidcToken` was unaffected because the ROPC path does not
  start the callback server. The timer is still cancelled deterministically
  via `clear()` in every success, error, and `close()` path, so the
  defensive `.unref()` is not needed. Regression test added in
  `test/callback-server.test.ts` that shims `globalThis.setTimeout` to
  return a plain number (the renderer behavior) and asserts
  `startCallbackServer` no longer throws.
- `package.json` `test` script: pass the test files as a quoted glob
  (`"dist/test/*.js"`) so it works on Node 22+, which dropped the
  implicit directory-scan behavior that older Node versions accepted for
  `node --test <dir>/`.

## [1.0.0-rc.1] - 2026-05-19

### Added

- Initial release replacing `insomnia-plugin-plus4u-oidc` (≤ 0.6.x) and
  `oidc-plus4u-vault` (≤ 0.9.1).
- Authorization Code flow with PKCE (S256), `state`, and `nonce`.
- Hardened localhost callback server (127.0.0.1, single-shot, state-gated,
  5 min hard timeout, `GET /` only).
- AES-256-GCM authenticated vault with scrypt (default) or PBKDF2-SHA256
  (≥ 600 000 iterations) password-based key derivation.
- One-shot CLI command `insomnia-plugin-plus4u-oidc-v2 migrate-legacy-vault`
  that re-encrypts a legacy `~/.oidc-plus4u-vault/vault.data` file into the
  new format without modifying the original.
- Three template tags (names preserved from the legacy plugin):
  - `uuPersonPlus4uOidcToken` — production / development modes.
  - `uuPersonCustomOidcToken` — custom uuOIDC server, PKCE-only.
  - `uuEePlus4uOidcToken` — opt-in ROPC for uuEE service accounts.
- Central log redaction (`src/util/log.ts`) that strips tokens, codes,
  secrets, and sensitive URL query parameters.

### Removed

- Hard-coded production `client_id` / `client_secret`.
- `r2`, `url-parse`, `node-fetch`, `mkdirp` dependencies (replaced with
  native `fetch`, `URL`, `fs/promises`).
- Resource Owner Password Credentials grant from the default path of
  `uuEePlus4uOidcToken` (now requires an explicit opt-in toggle).

