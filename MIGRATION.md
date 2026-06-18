# Migration runbook — from `oidc-plus4u-vault` (legacy) to v2

Operator-facing checklist for moving a single user (or a fleet) from the legacy `oidc-plus4u-vault` CLI + `insomnia-plugin-plus4u-oidc` (≤ 0.6.x) combination to this plugin.

Estimated time per workstation: **5 minutes**.

### Platform paths (quick reference)

The CLI resolves vault locations with Node.js `os.homedir()` — the same defaults apply on every OS. Insomnia plugin folders differ by platform.


| Resource                                     | macOS                                                         | Linux                                     | Windows                                       |
| -------------------------------------------- | ------------------------------------------------------------- | ----------------------------------------- | --------------------------------------------- |
| Legacy vault file                            | `~/.oidc-plus4u-vault/vault.data`                             | same as macOS                             | `%USERPROFILE%\.oidc-plus4u-vault\vault.data` |
| New vault file (after migration)             | `~/.plus4u-oidc-v2/vault.data`                                | same as macOS                             | `%USERPROFILE%\.plus4u-oidc-v2\vault.data`    |
| Insomnia plugins directory                   | `~/Library/Application Support/Insomnia/plugins`              | `~/.config/Insomnia/plugins`              | `%APPDATA%\Insomnia\plugins`                  |
| Insomnia settings DB (elevated-access check) | `~/Library/Application Support/Insomnia/insomnia.Settings.db` | `~/.config/Insomnia/insomnia.Settings.db` | `%APPDATA%\Insomnia\insomnia.Settings.db`     |


On Windows, `~` in shell examples below means `%USERPROFILE%` in CMD or `$env:USERPROFILE` in PowerShell unless noted otherwise.

---

## 1. Prerequisites

- Node.js ≥ 18 available on the workstation (Insomnia 9+ bundles one, but
  the CLI uses the system Node).
- The user knows their legacy vault password. The migration cannot recover
  a forgotten password (the legacy file's HMAC-SHA256 KDF is not
  reversible in the relevant sense; an offline brute force is the only
  option — see THREAT_MODEL.md §"Legacy crypto").
- Network access to `registry.npmjs.org` (or your internal npm mirror) so
  Insomnia can install the plugin from the UI and you can install the vault
  CLI globally (`npm install -g insomnia-plugin-plus4u-oidc-v2` or
  `npx uu-safe-install -g insomnia-plugin-plus4u-oidc-v2` on Plus4U
  workstations).

---

## 2. Pre-migration checklist

- Confirm the legacy file exists (pick your platform):
  **macOS / Linux (bash):**
  ```bash
  test -f ~/.oidc-plus4u-vault/vault.data && ls -l ~/.oidc-plus4u-vault/vault.data
  ```
  **Windows (PowerShell):**
  ```powershell
  $legacy = Join-Path $env:USERPROFILE '.oidc-plus4u-vault\vault.data'
  if (-not (Test-Path -LiteralPath $legacy)) { throw "Legacy vault not found: $legacy" }
  Get-Item -LiteralPath $legacy
  ```
  **Windows (CMD):**
  ```cmd
  if not exist "%USERPROFILE%\.oidc-plus4u-vault\vault.data" (
    echo Legacy vault not found & exit /b 1
  )
  dir "%USERPROFILE%\.oidc-plus4u-vault\vault.data"
  ```
  If the file is missing on every path above, the user may never have run
  the legacy `oidc-plus4u-vault` CLI, or the vault lives elsewhere — use
  `migrate-legacy-vault --from <path>` once you locate it.
- Take a backup of the legacy file (defense in depth, in case the user
  mistypes the password):
  **macOS / Linux (bash):**
  ```bash
  cp ~/.oidc-plus4u-vault/vault.data ~/oidc-plus4u-vault.bak.$(date +%Y%m%d)
  ```
  **Windows (PowerShell):**
  ```powershell
  $stamp = Get-Date -Format yyyyMMdd
  Copy-Item -LiteralPath (Join-Path $env:USERPROFILE '.oidc-plus4u-vault\vault.data') `
    -Destination (Join-Path $env:USERPROFILE "oidc-plus4u-vault.bak.$stamp")
  ```
  **Windows (CMD)** — replace `YYYYMMDD` with today's date:
  ```cmd
  copy "%USERPROFILE%\.oidc-plus4u-vault\vault.data" "%USERPROFILE%\oidc-plus4u-vault.bak.YYYYMMDD"
  ```
- Note which Insomnia template tags reference the legacy plugin. Tag
  names are unchanged in v2 (`uuPersonPlus4uOidcToken`,
  `uuPersonCustomOidcToken`, `uuEePlus4uOidcToken`), so existing
  requests will continue to work after the install.

---

## 3. Install the new plugin

The plugin is publicly available on npm as
[`insomnia-plugin-plus4u-oidc-v2`](https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc-v2).

In Insomnia:

1. `Application → Preferences → Plugins` (`Cmd+,` on macOS, `Ctrl+,` on
   Windows/Linux).
2. Type `insomnia-plugin-plus4u-oidc-v2` into the install field and click
   `Install Plugin`.
3. Wait for the spinner to finish; Insomnia loads the plugin from npm
   automatically.

> **Plus4U `.npmrc` gotcha:** if your user `.npmrc` pins a private registry
> (for example `https://repo.plus4u.net/repository/npm-dev/`), Insomnia's
> bundled Yarn hits that mirror first and the in-app install fails with
> `Yarn error {"type":"error","data":"Received invalid response from npm."}`.
> Fix it before step 2 — either remove the private `registry=` line or
> temporarily set `registry=https://registry.npmjs.org/`, install the
> plugin, then restore your usual config. See `README.md` §"Install plugin
> to Insomnia" for details.

> **After install, enable elevated plugin access.** On Insomnia 11+,
> external plugins do not register template tags with the templating
> worker until `Preferences → Plugins → Allow elevated access for plugins`
> is toggled ON (Kong/insomnia
> [#8917](https://github.com/Kong/insomnia/issues/8917)). Without it,
> every tag in every migrated request renders as
> `unknown block tag: <tag name>`. Toggle the setting, fully quit
> Insomnia (`Cmd+Q` on macOS; close all windows on Windows/Linux), and
> relaunch. See `README.md` §"Prerequisite" for the full rationale.
>
> Optional — confirm the setting was persisted (paths from the table
> above):
>
> **macOS (bash):**
>
> ```bash
> grep -o '"pluginsAllowElevatedAccess":[^,}]*' \
>   "$HOME/Library/Application Support/Insomnia/insomnia.Settings.db"
> ```
>
> **Linux (bash):**
>
> ```bash
> grep -o '"pluginsAllowElevatedAccess":[^,}]*' \
>   "$HOME/.config/Insomnia/insomnia.Settings.db"
> ```
>
> **Windows (PowerShell):**
>
> ```powershell
> Select-String -Path (Join-Path $env:APPDATA 'Insomnia\insomnia.Settings.db') `
>   -Pattern '"pluginsAllowElevatedAccess":[^,}]*'
> ```

---

## 4. Run the migration

Install the vault CLI globally first (see `README.md` §"Install the CLI
globally for vault management"), then run:

```bash
oidc-plus4u-vault-v2 migrate-legacy-vault
```

The tool will:

1. Read the legacy vault at the default path for the current OS (see
   [Platform paths](#platform-paths-quick-reference)) unless you pass
   `--from`.
2. Prompt: `Legacy vault password:`
3. Print how many entries it loaded.
4. Prompt: `New vault password:` (must be ≥ 12 chars).
5. Prompt: `Retype new vault password:`.
6. Write the new vault under `~/.plus4u-oidc-v2/` (POSIX modes `0600` /
   `0700` where the OS enforces them; on Windows, rely on NTFS ACLs for
   the user profile).
7. Print the path to the new file and a one-liner to remove the legacy
   file.

Common flags:


| Flag            | Purpose                                                                |
| --------------- | ---------------------------------------------------------------------- |
| `--from <path>` | Read from a non-default legacy file (e.g., a shared vault checked in). |
| `--to <path>`   | Write to a non-default destination (rarely needed).                    |
| `--force`       | Overwrite an existing destination vault — review carefully.            |


Exit codes:


| Code | Meaning                                                    |
| ---- | ---------------------------------------------------------- |
| `0`  | Success.                                                   |
| `2`  | Legacy file not found at `--from`.                         |
| `3`  | Legacy decryption failed (wrong password or corrupt file). |
| `4`  | Destination already exists and `--force` was not passed.   |
| `5`  | New password confirmation did not match.                   |
| `6`  | New password is shorter than 12 characters.                |
| `99` | Unhandled internal error.                                  |


---

## 5. Verify in Insomnia

1. Open a request that uses one of the template tags.
2. Trigger the request. The plugin should:
- For `uuPerson*OidcToken`: open the default browser, finish login, and
  fill the header.
- For `uuEePlus4uOidcToken`: prompt for the **new** vault password (the
  legacy password is no longer used), then fetch a token.
3. Inspect the response — a successful API call confirms the migration.

If `uuEePlus4uOidcToken` returns a `missing-config` message, the user has
not ticked the `**Use ROPC (legacy password grant)`** toggle in the tag
configuration. That is intentional — see `README.md` §"uuEE".

If every tag returns `unknown block tag: <tag name>` instead, the
`Allow elevated access for plugins` toggle is OFF — go back to §3 and
the README prerequisite above.

---

## 6. Post-migration cleanup

Once the user confirms the new plugin works for every account:

**macOS / Linux (bash):**

```bash
rm ~/.oidc-plus4u-vault/vault.data
rmdir ~/.oidc-plus4u-vault 2>/dev/null || rm -rf ~/.oidc-plus4u-vault   # if empty
npm uninstall -g oidc-plus4u-vault   # if it was installed globally
```

**Windows (PowerShell):**

```powershell
Remove-Item -LiteralPath (Join-Path $env:USERPROFILE '.oidc-plus4u-vault\vault.data') -ErrorAction Stop
$dir = Join-Path $env:USERPROFILE '.oidc-plus4u-vault'
if ((Get-ChildItem -LiteralPath $dir -Force | Measure-Object).Count -eq 0) {
  Remove-Item -LiteralPath $dir -Force
}
npm uninstall -g oidc-plus4u-vault   # if it was installed globally
```

Optionally remove the legacy Insomnia plugin from
`Preferences → Plugins → insomnia-plugin-plus4u-oidc → Disable / Uninstall`.

---

## 7. Rollback

If something is wrong with the new plugin:

1. Re-install the legacy plugin in Insomnia:
   `Preferences → Plugins → insomnia-plugin-plus4u-oidc`.
2. Restore the legacy vault from the backup made in §2:
   **macOS / Linux (bash):**
   **Windows (PowerShell):**
3. The new vault file (default path in the table above) can be deleted or
   kept — the legacy plugin ignores it.

File the issue with the steps to reproduce, the redacted DevTools log
(`Help → Show Log Folder`), and the output of:

```bash
oidc-plus4u-vault-v2 help
```
