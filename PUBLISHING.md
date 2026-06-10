# Publishing the plugin

Internal runbook for maintainers. The package is publicly available on
the npm registry as
[`insomnia-plugin-plus4u-oidc-v2`](https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc-v2).
This document covers pre-flight checks, tagging, publish, and smoke tests.

Commands below are grouped by **macOS**, **Linux** (bash), and **Windows**
(PowerShell) where paths or shell syntax differ. Registry operations
(`npm publish`, `npm pack`, `npm login`) are the same on every OS.

---

## Platform paths (quick reference)

Insomnia plugin folders differ by OS (same table as
`[MIGRATION.md](MIGRATION.md#platform-paths-quick-reference)`):


| Resource                | macOS                                            | Linux                        | Windows                      |
| ----------------------- | ------------------------------------------------ | ---------------------------- | ---------------------------- |
| Insomnia plugins folder | `~/Library/Application Support/Insomnia/plugins` | `~/.config/Insomnia/plugins` | `%APPDATA%\Insomnia\plugins` |
| User npm config (§4)    | `~/.npmrc`                                       | `~/.npmrc`                   | `%USERPROFILE%\.npmrc`       |


On Windows, `~` in bash examples means `%USERPROFILE%` in CMD or
`$env:USERPROFILE` in PowerShell unless noted otherwise.

---

## Installing dependencies (maintainer)

Whenever this runbook says to install packages in the **repository**,
use the command that matches your environment:


| Audience                                                           | Install command       | Notes                                                                                                                                                                                                                                                                                         |
| ------------------------------------------------------------------ | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Unicorn coworkers** (Plus4U internal workstations)               | `npx uu-safe-install` | Required by internal policy: dependency install goes through the audited wrapper instead of bare `npm install`. Accepts the same flags as npm (e.g. `--omit=dev`). [BookKit reference](https://uuapp.plus4u.net/uu-bookkit-maing01/0238a88bac124b3ca828835b57144ffa/book/page?code=58494690). |
| **Everyone else** (external users, contractors, personal machines) | `npm install`         | Standard npm; no `uu-safe-install` required.                                                                                                                                                                                                                                                  |


After dependencies are installed, `**npm run build`** and `**npm test**`
are the same for both audiences.

Publishing to npm (`npm publish`) always uses the **npm CLI** directly —
not `uu-safe-install`.

---

## 1. Pre-flight checklist

Run from your **clone** of this repository (adjust `cd` to your path).

1. The working tree is clean: `git status` shows nothing unstaged.
2. The version in `package.json` matches the release section in
   `CHANGELOG.md` (Semantic Versioning).
3. A clean build passes the full test suite:
  ```bash
   cd /path/to/insomnia-plugin-plus4u-oidc-v2
   npm run clean
   # Unicorn Universe:
   npx uu-safe-install
   # Everyone else:
   # npm install
   npm test
  ```
`npm test` runs `build` then the spec reporter over `dist/test/*.test.js`
— all tests must pass.
4. The plugin loads end-to-end in Insomnia: install
   `insomnia-plugin-plus4u-oidc-v2` from **Preferences → Plugins**,
   enable elevated plugin access, and confirm the four template tags appear
   in the auth dropdown.

---

## 2. Public npm release

### 2.1 One-time setup

1. Confirm the package name and current version on npm:
  ```bash
   npm view insomnia-plugin-plus4u-oidc-v2 version \
     --registry https://registry.npmjs.org/
  ```
2. Log in to npm against the public registry:
  ```bash
   npm login --registry https://registry.npmjs.org/
  ```
3. Confirm the publishing identity:
  ```bash
   npm whoami --registry https://registry.npmjs.org/
  ```

### 2.2 Tags before publish (required)

Open `package.json` and note the `"version"` you are about to release.
Do the following **before** `npm publish --dry-run` and the real publish.

**1. Git tag** — name it `v` + that version (e.g. version `1.0.0-rc.2`
→ tag `v1.0.0-rc.2`):

```bash
git tag -a v1.0.0-rc.2 -m "Release v1.0.0-rc.2"
git push origin v1.0.0-rc.2
```

Check that `HEAD` is on that tag:

```bash
git describe --exact-match --tags HEAD
```

**2. npm dist-tag** — every `npm publish` (including `--dry-run`) must
include `--tag <name>`. Pick `<name>` from the version string:


| `version` in `package.json` | Use in commands |
| --------------------------- | --------------- |
| `X.Y.Z` (no `-` suffix)     | `--tag latest`  |
| contains `-rc.`             | `--tag rc`      |
| contains `-beta.`           | `--tag beta`    |
| contains `-alpha.`          | `--tag alpha`   |


Do not omit `--tag`; pre-releases must not use `latest`.

Examples below use `--tag rc` for the current RC line — substitute
`latest` (or another row) when you ship a stable release.

### 2.3 Dry run

From the repository root (after §1 pre-flight and §2.2):

```bash
npm publish --dry-run --registry https://registry.npmjs.org/ \
  --tag rc --access public
```

Inspect the listed files. Anything sensitive (`.env`, internal docs,
private fixtures) should NOT appear. If something is in the list that
shouldn't be there, add it to `.npmignore` or remove it from the `files`
allow-list in `package.json`.

Confirm the CLI summary shows the dist-tag you chose (e.g. `+ rc`, not
`+ latest` for an RC).

### 2.4 Publish

Use the same `--tag` value as in the dry run:

```bash
npm publish --registry https://registry.npmjs.org/ \
  --tag rc --access public
```

The `--access public` flag is required only for scoped packages; for
the current unscoped name it is a harmless no-op.

### 2.5 Smoke test the published version

Use a clean cache, then install the package and require it from Node.
Pick the block for your OS.

Clear npm cache (any OS):

```bash
npm cache clean --force
```

**macOS / Linux (bash)** — use the same dist-tag as publish (e.g. `@latest`
for a stable release):

```bash
SMOKE="$(mktemp -d)"
cd "$SMOKE" && npm init -y >/dev/null
npm install insomnia-plugin-plus4u-oidc-v2 \
  --registry https://registry.npmjs.org/
node -e "console.log(require('insomnia-plugin-plus4u-oidc-v2').templateTags.map(t=>t.name))"
cd - >/dev/null && rm -rf "$SMOKE"
```

**Windows (PowerShell):**

```powershell
$smoke = Join-Path $env:TEMP ("insomnia-smoke-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $smoke | Out-Null
Set-Location $smoke
npm init -y | Out-Null
npm install insomnia-plugin-plus4u-oidc-v2 `
  --registry https://registry.npmjs.org/
node -e "console.log(require('insomnia-plugin-plus4u-oidc-v2').templateTags.map(t=>t.name))"
Set-Location $env:TEMP
Remove-Item -Recurse -Force $smoke
```

On a Plus4U workstation you may smoke-test dependency resolution with
`npx uu-safe-install insomnia-plugin-plus4u-oidc-v2 --registry https://registry.npmjs.org/`
instead of `npm install` in the temp directory above.

Expected `templateTags` names match §1 step 4.

---

## 3. The Plus4U `.npmrc` gotcha

The Plus4U developer image ships a user-level `.npmrc` (`~/.npmrc` on
macOS/Linux, `%USERPROFILE%\.npmrc` on Windows) that pins all installs to
`https://repo.plus4u.net/repository/npm-dev/`. Insomnia's bundled Yarn
reads this file, so even after a public release the in-app install
will fail with:

```text
Yarn error {"type":"error","data":"Received invalid response from npm."}
```

Document the workaround alongside the release announcement. The least
invasive options, in order of preference:

1. **Per-install registry override** (no global config change):
  ```bash
   npm config set registry https://registry.npmjs.org/ --location=user
   # Restart Insomnia, install the plugin from the UI.
   npm config delete registry --location=user
  ```
2. **Scoped registry mapping** in the user `.npmrc` (cleanest for users who
   want to keep the private registry default for everything else):
   This only helps if we rename the package to a scoped name (e.g.
   `@unicornuniverse/insomnia-plugin-plus4u-oidc-v2`). Worth doing if
   publishing under the Unicorn Universe npm organization.

---

## 4. Internal Nexus / private registry release

If we want users with the existing user `.npmrc` to install with zero
changes, publish to the Plus4U Nexus:

```bash
npm publish --registry https://repo.plus4u.net/repository/plus4unet-sbx-npm/ \
  --tag rc
```

Complete §2.2 first; use the same `--tag` as for the public registry.
Uses the `_authToken` already configured in the user `.npmrc`.

After this, the in-app installer will find the package on its first
registry hit and the standard `Preferences → Plugins → Install Plugin`
flow works without registry juggling. This is the recommended path for
internal-only distribution.

---

## 5. Post-publish checklist

- Confirm the git tag from §2.2 is on the remote (replace with your version):
  `git ls-remote --tags origin v1.0.0-rc.2`
- Confirm the npm dist-tag points at the new version:
  `npm dist-tag ls insomnia-plugin-plus4u-oidc-v2 --registry https://registry.npmjs.org/`
  (e.g. `rc` → `1.0.0-rc.2`, or `latest` → `1.0.0`).
- Update `CHANGELOG.md` with the release date.
- Add a note to internal Slack / docs that pin the public registry
  workaround (see §3).
- Verify the npm package page renders the README correctly:
  `https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc-v2`.

---

## 6. Yanking a bad release

If a published release is broken, **deprecate** instead of `unpublish`
(npm restricts unpublish to the first 72 hours and to versions with no
dependents):

```bash
npm deprecate insomnia-plugin-plus4u-oidc-v2@<version> \
  "<reason — point at the fixed version>"
```

Then publish a patched version immediately (§2.2: new git tag + `--tag`
in `npm publish`).