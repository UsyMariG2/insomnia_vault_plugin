# insomnia-plugin-plus4u-oidc-v2

Insomnia plugin for OIDC authentication against `oidc.plus4u.net` and any custom uuOIDC server. Replaces the legacy `insomnia-plugin-plus4u-oidc` (≤ 0.6.x) and its companion CLI `oidc-plus4u-vault` (≤ 0.9.1) with a single, security-hardened package.

If you are migrating from the legacy plugin, jump straight to  [Migration from](#migration-from-oidc-plus4u-vault) `oidc-plus4u-vault`.

**npm:** `[insomnia-plugin-plus4u-oidc-v2](https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc-v2)` — publicly available on the npm registry.

---

## Requirements


| Component | Version                                                                             |
| --------- | ----------------------------------------------------------------------------------- |
| Insomnia  | 8.0 or newer (template-tag API v3)                                                  |
| Node.js   | 18 or newer for the standalone CLI (Insomnia bundles a compatible Node for plugins) |
| OS        | macOS 12+, Windows 10+, Linux with `xdg-open` for the browser launch                |

### Platform paths

Insomnia plugin folders and vault files differ by OS:

| Resource           | macOS                                            | Linux                        | Windows                                       |
| ------------------ | ------------------------------------------------ | ---------------------------- | --------------------------------------------- |
| Insomnia plugins   | `~/Library/Application Support/Insomnia/plugins` | `~/.config/Insomnia/plugins` | `%APPDATA%\Insomnia\plugins`                  |
| Vault (v2 default) | `~/.plus4u-oidc-v2/vault.data`                   | same as macOS                | `%USERPROFILE%\.plus4u-oidc-v2\vault.data`    |
| Legacy vault       | `~/.oidc-plus4u-vault/vault.data`                | same as macOS                | `%USERPROFILE%\.oidc-plus4u-vault\vault.data` |

On Windows, `~` in bash examples means `%USERPROFILE%` in CMD or `$env:USERPROFILE` in PowerShell.

---

## Prerequisite: enable "Allow elevated access for plugins"
For v13+ see [Insomnia 13+ credentials via Insomnia variables](#insomnia-13-credentials-via-insomnia-variables-)
> **Requires a one-time setting change**, otherwise template tags from any external plugin (including this one) render as `unknown block tag: uuPersonPlus4uOidcToken` (and the same for the two other tags). This is an Insomnia security setting, not a plugin bug — see Kong/insomnia [#8917](https://github.com/Kong/insomnia/issues/8917), [#8708](https://github.com/Kong/insomnia/issues/8708), [#9211](https://github.com/Kong/insomnia/issues/9211).

How to enable it:

1. In Insomnia, open `Application → Preferences` (`Cmd+,` on macOS, `Ctrl+,` on Windows/Linux) and select the `Plugins` tab.
2. Toggle ON `**Allow elevated access for plugins`**.
3. Fully quit Insomnia (`Cmd+Q` on macOS, close all windows on Windows/Linux) and reopen it.

Why this plugin needs it: the auth flow runs a `127.0.0.1`-bound `http` callback server, derives keys with `node:crypto` (PKCE, scrypt, AES-256-GCM), reads/writes the encrypted vault with `node:fs`, and launches the system browser via the `open` package (system default handler; on Linux typically `xdg-open`). Insomnia gates all of those Node APIs behind elevated access. With the toggle off, Insomnia still loads the plugin module (`renderer.log` shows `[plugin] Loading plus4u-oidc-v2`), but never forwards its template tags to the templating Web Worker that does the actual rendering.

---

## What it does

The plugin registers three Insomnia template tags:

| Tag                       | Purpose                                                                                              | Auth method                         |
| ------------------------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `uuPersonPlus4uOidcToken` | Log in as a real user against the Plus4U **production** or **development** OIDC server.              | Browser-based, **PKCE**             |
| `uuPersonCustomOidcToken` | Log in as a real user against a user-configured uuOIDC server (gateway, internal, self-signed cert). | Browser-based, **PKCE** (no secret) |
| `uuEePlus4uOidcToken`     | Service-account (uuEE) login. Opt-in only; vault-backed access codes supported.                      | ROPC (legacy password grant)        |

All three return a raw `id_token` string when successful, or a clearly formatted `-- plus4u-oidc-v2 <status>: <detail> --` message when not. Drop the tag into any header, body, or environment variable.

---

## Install the CLI globally for vault management

Install the vault CLI from npm. It puts `oidc-plus4u-vault-v2` on your `PATH` (alias `insomnia-plugin-plus4u-oidc-v2`).

### From npm

Install the latest published version from the public npm registry.

| Audience          | Command                                                 |
| ----------------- | ------------------------------------------------------- |
| Unicorn coworkers | `npx uu-safe-install -g insomnia-plugin-plus4u-oidc-v2` |
| Everyone else     | `npm install -g insomnia-plugin-plus4u-oidc-v2`         |

Verify: `oidc-plus4u-vault-v2 help` (or `oidc-plus4u-vault-v2 --version` if your shell resolves the global bin).

---

## Install plugin to Insomnia

### From the Insomnia UI

The plugin is publicly available on npm as [insomnia-plugin-plus4u-oidc-v2](https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc-v2).

1. `Application → Preferences → Plugins` (`Cmd+,` on macOS, `Ctrl+,` on Windows/Linux).
2. Enter `insomnia-plugin-plus4u-oidc-v2` in the *Install Plugin* field and click **Install Plugin**.
3. Insomnia loads the plugin from npm automatically.
4. Restart Insomnia and confirm `[Allow elevated access for plugins](#prerequisite-enable-allow-elevated-access-for-plugins)` is ON.

In the Insomnia UI: `Preferences → Plugins` should list **Plus4U OIDC (v2)** with the installed npm version and three template tags registered.

---

## First-time setup

1. Open environment setting for given collection Insomnia.
2. Create a variable where you wills store token.
3. Pick tag depending on your use case
4. Open any request. Into Header add new Authorization header as value use "Bearer "token variable"
5. Send the request. Depending on picked tag for token. It will either open browser where you will login (or if logged already it will get token) or it will ask for your password to the vault

That's it. The token is cached until 5 minutes before it expires; the
next 55-minute window of requests is silent.

When you edit tag configuration (e.g. **Token scope**), Insomnia re-evaluates
the tag on every keystroke. The plugin waits ~800 ms after you stop typing
before opening the browser or prompting for credentials; cached tokens for the
current settings are still returned immediately.

### Configuration reference

#### `uuPersonPlus4uOidcToken`

| Field       | Default      | Description                                                                                                         |
| ----------- | ------------ | ------------------------------------------------------------------------------------------------------------------- |
| Mode        | `Production` | `Production` uses `uuidentity.plus4u.net`. `Development` uses `uuidentity-dev.plus4u.net`.                          |
| Disabled    | `false`      | Toggle to return a no-op message; flip it off to force a fresh login.                                               |
| Token scope | `openid`     | Scope to request. For uuApp API calls, include the target scope (e.g. `openid uu-oidc:unregistered-client:<awid>`). |

#### `uuPersonCustomOidcToken`

| Field                     | Default    | Description                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Disabled                  | `false`    | Toggle to force a refresh.                                                                                                                                                                                                                                                                                                                                       |
| Cache Tag                 | `default`  | Free-form label so you can hold several distinct cached tokens against the same server.                                                                                                                                                                                                                                                                          |
| OIDC Server               | (required) | Base URL of the OIDC server. No trailing slash. Example: `https://example.com/uu-oidc-maing02/.../oidc`.                                                                                                                                                                                                                                                         |
| OIDC Info Page            | (empty)    | URL the browser lands on after a successful login. Leave empty for a plain text confirmation page.                                                                                                                                                                                                                                                               |
| Client ID                 | (empty)    | OIDC `client_id`. Leave empty to send the public-client sentinel `00000000000000000000000000000000` — Plus4U `/oidc/auth` rejects requests without any `client_id`, and most uuOIDC servers accept the sentinel for the PKCE flow. Fill in only if your OIDC server requires a registered client_id. **No `client_secret` is ever sent** — PKCE is used instead. |
| Validate TLS certificates | `true`     | Disable only for trusted local development with self-signed certificates.                                                                                                                                                                                                                                                                                        |

#### `uuEePlus4uOidcToken`

| Field                                       | Default                                                | Description                                                                                                                                                                                           |
| ------------------------------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Prompt user identification                  | (required)                                             | Free-form label (e.g. `6-804-1`). The same label may be used for prod and dev if **OIDC Server** differs (via environment variables).                                                                 |
| OIDC Server                                 | `https://uuidentity.plus4u.net/.../oidc` (Plus4U prod) | Base URL of the OIDC server — must match `vault add --uri` for that entry. For two tokens in one collection, set e.g. `{{ oidc_prod }}` vs `{{ oidc_dev }}` here (not only the identification field). |
| Token scope                                 | `openid`                                               | Scope to request.                                                                                                                                                                                     |
| Use ROPC (legacy password grant) — REQUIRED | `false`                                                | Must be ticked to enable this tag. ROPC is deprecated by OAuth 2.1; this toggle keeps it off the default happy path.                                                                                  |
| Load access codes from vault                | `true`                                                 | If ticked, the plugin reads credentials from the default v2 vault path (see [Platform paths](#platform-paths)) before prompting. Vault password is asked once per Insomnia session.                   |
| Validate TLS certificates                   | `true`                                                 | Disable only for trusted local development with self-signed certificates.                                                                                                                             |

### **Insomnia 13+ credentials via Insomnia variables.** 
The uuEE tag is the only
one that needs typed secrets. Insomnia v13 runs user-installed plugin tags in
the main process, where `context.app.prompt` dialogs are not shown and OS
environment variables are not visible (GUI apps do not inherit your shell). The
tag therefore reads credentials from Insomnia's own variables, using these
names:

| Variable name                                                   | Purpose                                                                                                                                 |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `PLUS4U_OIDC_V2_VAULT_PASSWORD`                                 | Decrypt `~/.plus4u-oidc-v2/vault.data` when **Load access codes from vault** is ticked                                                  |
| `PLUS4U_OIDC_V2_ACCESS_CODE_1` / `PLUS4U_OIDC_V2_ACCESS_CODE_2` | Access codes when the file vault is off or has no matching entry                                                                        |
| `PLUS4U_OIDC_V2_<IDENT>_AC1` / `_AC2`                           | Per-identification override (`<IDENT>` = identification with non-alphanumeric characters removed, uppercased; e.g. `6-804-1` → `68041`) |

**Recommended — Insomnia Secret variable (encrypted at rest):**

1. `Preferences → General → Security` → **Generate Vault Key**.
2. In the same Security section, tick **Enable vault in scripts**.
3. Create a **private global sub-environment** (Environments → Base Environment
  → `+`), then add the variable above (e.g. `PLUS4U_OIDC_V2_VAULT_PASSWORD`)
   with type **Secret**.
4. Select that global sub-environment in your collection, then **send** the
  request (secrets are only decrypted on send, not in live preview).

See [Insomnia → Secret environment variables](https://developer.konghq.com/insomnia/environments/#secret-environment-variables).

**Last resort — plain Insomnia environment variable:** add the same-named
variable as a normal (non-secret) value in your base/collection environment.
This is stored in plaintext, so prefer the Secret variable above.

Resolution order per value: Insomnia Secret (`vault.`*) → prompt (pre-v13
only) → plain Insomnia environment variable. PKCE tags (`uuPerson`*) are
unaffected.

---

## Migration from `oidc-plus4u-vault`

If you used the old plugin, you already have a vault file at the default legacy path for your OS (see [Platform paths](#platform-paths)). The migration tool re-encrypts it into the new format **without modifying the original**, so you can roll back if needed.

For more information, see [`MIGRATION.md`](MIGRATION.md).

---

## Vault management

Manage entries directly from the CLI with the `vault` subcommand group. Every command takes an optional `--vault <path>` flag; if you omit it, the CLI uses the default v2 vault for the current OS (see [Platform paths](#platform-paths)).

Install the CLI globally first (see [Install the CLI globally for vault management](#install-the-cli-globally-for-vault-management)). The short command `oidc-plus4u-vault-v2` is on your `PATH` after a global install; the long form `insomnia-plugin-plus4u-oidc-v2` is registered as an alias and accepts the same arguments.

The short command name was deliberately chosen so it does **not** collide with the legacy `oidc-plus4u-vault` binary — both can be installed side by side during a migration window.

### Subcommands

```bash
# Add (or overwrite) an entry. The CLI prompts for Access Code 1 and
# Access Code 2, runs a real ROPC call against --uri to validate them,
# and only writes the entry on success. --uri defaults to the Plus4U
# production uuOIDC URL when omitted.
oidc-plus4u-vault-v2 vault add --user my-bot
# or, with a custom OIDC server:
oidc-plus4u-vault-v2 vault add --user my-bot \
  --uri https://my-oidc.example.com/uu-oidc-maing02/awid/oidc

# Remove an entry (same --user may exist for several --uri values).
oidc-plus4u-vault-v2 vault delete --user my-bot
oidc-plus4u-vault-v2 vault delete --user my-bot \
  --uri https://my-oidc.example.com/uu-oidc-maing02/awid/oidc

# List every entry as `<user> - <oidc-server-url>`.
oidc-plus4u-vault-v2 vault list
```

The first `vault add` against a non-existent vault file will prompt for a new vault password (twice; minimum 12 characters) before storing the entry, so you can start fresh without first running `migrate-legacy-vault`. Subsequent commands prompt once for the existing vault password.

The vault is also populated automatically by `uuEePlus4uOidcToken` — which prompts you for new access codes on first sight of a new identification, caches them in session memory, and re-uses them across requests with the same label — and by the `migrate-legacy-vault` tool.

| File / directory (default)         | Mode   | Contents                                                    |
| ---------------------------------- | ------ | ----------------------------------------------------------- |
| `~/.plus4u-oidc-v2/` (macOS/Linux) | `0700` | Vault directory. Windows: `%USERPROFILE%\.plus4u-oidc-v2\`. |
| `vault.data` inside that directory | `0600` | AES-256-GCM encrypted vault (see `VAULT_FORMAT.md`).        |

**Backups.** The vault file is self-contained — copying it to a USB stick or encrypted backup is enough. The encryption is bound to your chosen password, so as long as the password is strong (≥ 12 random characters), the file is safe at rest. Do **not** share the file via unencrypted channels (email, public chat).

**Multiple machines.** Copy the file to the second machine at the same path; the plugin will prompt for the same password on first use.

---

## uuEE (ROPC) opt-in

Resource Owner Password Credentials (`grant_type=password`) is deprecated by OAuth 2.1 and is not the default behavior of this plugin.

You enable it per tag by ticking the `**Use ROPC (legacy password grant)`** checkbox in the `uuEePlus4uOidcToken` configuration. Without that tick, the tag returns:

```
-- plus4u-oidc-v2 missing-config: uuEE login uses the deprecated ROPC grant. … --
```

Why we keep ROPC at all: today, Plus4U uuOIDC does not support `client_credentials` for per-uuEE service accounts. ROPC is the only practical way to log in as a service account from Insomnia. We will remove the opt-in once `client_credentials` becomes available.

---

## Custom OIDC server

The `uuPersonCustomOidcToken` tag works against any OIDC-compliant `/authorize` + `/token` server that supports the **Authorization Code + PKCE** flow with a localhost redirect URI.

Required fields:

- **OIDC Server** — the base URL the plugin appends `/.well-known/openid-configuration` to.
- **OIDC Info Page** *(optional)* — where the browser should land after login. The plugin appends `?clientId=<id>` to it **only** when you filled in an explicit Client ID; the sentinel default is never leaked into the redirect URL.
- **Client ID** *(optional)* — leave empty to send the public-client sentinel `00000000000000000000000000000000`. The plugin sends this same value on both `/oidc/auth` and the matching `/oidc/token` PKCE exchange, which is what Plus4U's uuOIDC and most other OIDC servers require for public clients (RFC 6749 §4.1.3). Fill in a real `client_id` only if your OIDC server rejects the sentinel.
- **id_token** `aud` **validation** — when you fill in an explicit Client ID, the plugin enforces that the returned id_token's `aud` claim
  contains it. When the field is empty (sentinel default), `aud` is not enforced, because the server's actual `aud` is normally the resolved identity, not `0…0`.

The plugin **never sends a** `client_secret`. If your OIDC server rejects PKCE-only requests, ask the operator to register a public client for this plugin (no secret required by RFC 8252).

---

## Token caching & refresh

- Successful tokens are verified against the OIDC issuer's JWKS (signature check)
before caching. JWKS documents are cached in memory for 24 hours.
- Verified tokens are cached in process memory until **5 minutes before the**
`id_token` **exp claim**. Subsequent renders return the cached token with zero
network traffic.
- A failed login is cached for **5 minutes** so a 100-request batch doesn't open 100 browser tabs. The cached error is returned as `-- plus4u-oidc-v2 token-error-cached: <message> (cached <timestamp>; toggle Disabled to refresh) --`.
- To force a refresh: open the tag configuration, tick **Disabled**, close it, then untick **Disabled**. The next render starts a fresh
flow.
- All caches are in-memory only. Restarting Insomnia clears them.

---

## Security model (short version)

We protect:

- The vault file at rest (scrypt KDF + AES-256-GCM with per-vault salt; tampering is detected and rejected).
- The authorization `code` (PKCE — no other local process can redeem a stolen code).
- The localhost callback (`state` parameter, 127.0.0.1-only binding, `GET /` only, single-shot, 5-minute hard timeout).
- The `id_token` against replay (`nonce` validated on every flow) and forgery
  (JWKS signature verification before cache).

We do **not** protect against:

- A compromised Insomnia process or OS user account (the vault password and tokens live in process memory after first use).
- An OIDC operator that issues tokens to the wrong user.

Full details: [THREAD_MODEL.md](THREAT_MODEL.md). File format spec: [VAULT_FORMAT.md](VAULT_FORMAT.md).

---

## Troubleshooting

| Symptom                                                                                                  | Likely cause                                                                                                                                                                                                                                                      | Fix                                                                                                                                                                                                                                                                                   |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `unknown block tag: uuPersonPlus4uOidcToken` (also for `uuPersonCustomOidcToken`, `uuEePlus4uOidcToken`) | Insomnia 11–12: `Allow elevated access for plugins` disabled (Kong/insomnia [#8917](https://github.com/Kong/insomnia/issues/8917)). Insomnia 13+ routes plugins via IPC regardless of that toggle — if tags still fail to load, reinstall the plugin and restart. | Insomnia 11–12: toggle `Preferences → Plugins → Allow elevated access for plugins` ON, fully quit and relaunch. See [Prerequisite](#prerequisite-enable-allow-elevated-access-for-plugins) Insomnia 13+: reinstall plugin, restart, check logs for `[plugin] Loading plus4u-oidc-v2`. |
| `-- plus4u-oidc-v2 vault-locked` / `missing-config` with a `(diag: …)` suffix (uuEE)                     | Insomnia v13 cannot show plugin credential dialogs and does not see OS environment variables.                                                                                                                                                                     | Store credentials in an Insomnia **Secret** variable (`vault.`*) or a plain Insomnia environment variable of the same name, then **send** the request. See [uuEePlus4uOidcToken](#uueeplus4uoidctoken). The `(diag: …)` suffix shows which variable names were found.                 |
| `-- plus4u-oidc-v2 token-error-cached: … --`                                                             | A previous login failed and the error is cached for 5 min.                                                                                                                                                                                                        | Toggle the **Disabled** switch on/off to refresh, or wait 5 min.                                                                                                                                                                                                                      |
| `-- plus4u-oidc-v2 token-error: Vault decryption failed: wrong password or … tampered … --`              | Vault password typed wrong, OR another process modified the file.                                                                                                                                                                                                 | Restart Insomnia and re-enter the password. If still failing, restore from backup.                                                                                                                                                                                                    |
| `-- plus4u-oidc-v2 missing-config: OIDC Server is required. --`                                          | Custom OIDC tag is using the placeholder `--fill-in--` server URL.                                                                                                                                                                                                | Fill in the OIDC Server field with a real base URL.                                                                                                                                                                                                                                   |
| `Authentication timed out after 300s.`                                                                   | You closed the browser before finishing login, or the OIDC server never redirected.                                                                                                                                                                               | Re-trigger the request; complete the login within 5 minutes.                                                                                                                                                                                                                          |
| `OIDC server returned error 'access_denied'`                                                             | The user cancelled the login.                                                                                                                                                                                                                                     | Re-trigger the request and complete the login.                                                                                                                                                                                                                                        |
| `Callback` state `did not match …`                                                                       | A stale browser tab (or a malicious page) sent a callback. Safe to ignore.                                                                                                                                                                                        | Close stale OIDC tabs in the browser, re-trigger the request.                                                                                                                                                                                                                         |
| Browser does not open                                                                                    | `xdg-open` / system default browser not configured (mostly Linux / headless).                                                                                                                                                                                     | Manually open the URL printed in Insomnia's `Help → Show Log Folder` log.                                                                                                                                                                                                             |
| `EADDRINUSE` on listening                                                                                | Vanishingly rare; race against another process grabbing the same random port.                                                                                                                                                                                     | Re-trigger the request.                                                                                                                                                                                                                                                               |
To see the full DevTools log inside Insomnia:
`Help → Show Log Folder` (Insomnia 9+), or open DevTools with
`Cmd+Option+I` on macOS / `Ctrl+Shift+I` on Windows and Linux.

---

## FAQ

**Q: Why does the new plugin not ship a `client_secret`?**
A: The legacy plugin shipped its production `client_secret` in the npm tarball, which made it "public" in the OAuth sense — anyone could have impersonated the plugin. We now use PKCE (RFC 7636), which provides the proof-of-possession the `client_secret` was meant to provide, without having to keep a secret in a shipped artifact.

**Q: Can I share the vault file across machines?**  
A: Yes — copy the file to the same path on the other machine and use the same password. The vault is self-contained.

**Q: How do I rotate the vault password?**  
A: Today the workflow is: migrate the current vault to a temporary location with a new password (`oidc-plus4u-vault-v2 migrate-legacy-vault --from <current-vault> --to <new-vault>`), then move the new file in place. A dedicated `rotate` command is on the roadmap.

**Q: What changed vs. the old plugin?**  
A: At-a-glance: PKCE/state/nonce in the auth flow, AES-256-GCM + scrypt in the vault (with per-vault salt), no hard-coded `client_secret`, ROPC moved behind an opt-in flag, all secret logging removed. Full list in `CHANGELOG.md` and `THREAT_MODEL.md`.

**Q: Does it work with Azure AD / Keycloak / Auth0?**  
A: Any OIDC server that supports the Authorization Code + PKCE flow with a localhost redirect URI works via `uuPersonCustomOidcToken`. The plugin does not implement vendor-specific quirks (Azure scope-as-clientid, etc.); for those, use the vendor's own OAuth client.

**Q: Does the plugin send anything home?**  
A: No. The only network traffic is between the plugin, the OIDC server you configured, and your default browser.

---

## Uninstall / data removal

1. `Application → Preferences → Plugins → insomnia-plugin-plus4u-oidc-v2 → Disable`, then **Uninstall**.
2. Remove the vault file and its directory:
  **macOS / Linux (bash):**
   **Windows (PowerShell):**
3. If you used the bundled CLI globally, remove it:
  ```bash
   npm uninstall -g insomnia-plugin-plus4u-oidc-v2
  ```
4. Restart Insomnia.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
