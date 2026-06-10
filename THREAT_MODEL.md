# Threat model — insomnia-plugin-plus4u-oidc-v2

This document captures the security assumptions, the assets we protect, the
adversaries we expect, and the controls each adversary forces. It is the
companion to the user-facing `README.md` and the format spec in
`VAULT_FORMAT.md`. Internal audience (security review, future maintainers).

---

## 1. Assets

| ID | Asset | Where it lives |
| -- | ----- | -------------- |
| A1 | OIDC `id_token` for a real human (uuPerson) | Insomnia process memory; HTTP headers of outgoing requests |
| A2 | OIDC `id_token` for a service account (uuEE) | Same as A1 |
| A3 | uuOIDC access codes (`accessCode1`, `accessCode2`) | Encrypted at rest in `~/.plus4u-oidc-v2/vault.data`; decrypted in Insomnia memory after the user enters the vault password |
| A4 | Vault password | Insomnia memory after first prompt; never persisted |
| A5 | PKCE `code_verifier`, `state`, `nonce` | Insomnia memory for the duration of one auth flow (typically < 60 s) |
| A6 | Authorization `code` from the OIDC server | In transit (localhost), then in memory until exchanged at `/token` |

---

## 2. Trust boundaries

```
+-------------------------------------------------------------+
|  User's machine (TRUSTED)                                   |
|                                                             |
|  +-------------------+     +---------------------------+    |
|  |   Insomnia (this  |     |   Default browser         |    |
|  |   plugin runs in  |<--->|   (login UI)              |    |
|  |   the renderer)   |     +-------------+-------------+    |
|  +---------+---------+                   |                  |
|            |                             | TLS              |
|            | localhost (UNTRUSTED-ish:   |                  |
|            | every local process can     v                  |
|            | reach 127.0.0.1)        +----------+           |
|            +------------------------>|  OIDC    |           |
|                                       |  server  |           |
|                                       +----------+           |
+-------------------------------------------------------------+
                                              ^
                                              | TLS
                                              v
                                       +----------+
                                       |  Public  |
                                       |  Network |
                                       +----------+
```

- The user's OS account is in the trust boundary. A compromised OS account
  defeats every control here; we do not pretend otherwise.
- The default browser is mostly trusted for credential entry, but we assume
  malicious pages can be open in tabs the user doesn't know about.
- Other processes running as the same OS user are partially adversarial: any
  of them can talk to `127.0.0.1:<random>` during an auth flow.

---

## 3. Adversaries

| ID | Adversary | Capabilities |
| -- | --------- | ------------ |
| T1 | Casual on-disk attacker | Has read-only access to the vault file (e.g., recovered from a backup, sync conflict, lost laptop) |
| T2 | On-disk attacker with write | Can also rewrite the vault file |
| T3 | Co-located malicious process | Runs as the same OS user; can connect to localhost ports, read `/proc`, etc. |
| T4 | Malicious web page in the user's browser | Can issue requests during the auth window, including to `http://127.0.0.1:<port>/` |
| T5 | Network attacker on the path to the OIDC server | Can MITM if TLS validation is off; otherwise must break TLS |
| T6 | Insomnia plugin supply-chain attacker | Publishes a malicious version of one of our dependencies |
| T7 | Plus4U OIDC operator | We trust the operator; out of scope |

---

## 4. Controls

### 4.1 At-rest secret storage (A3, A4 → T1, T2)

- **Authenticated encryption (AES-256-GCM).** Any modification of the vault
  file — ciphertext bit-flip, header swap, salt swap — triggers a tag
  mismatch on decryption and the file is rejected. Closes T2.
- **Per-vault random salt (32 bytes from `crypto.randomBytes`)** stored in
  the file header. Two users with the same password derive different keys.
  Removes the rainbow-table acceleration available against the legacy vault.
- **scrypt KDF (`N=2^15, r=8, p=1`)** by default; PBKDF2-SHA256 with at least
  600 000 iterations as a fallback. Both make offline brute force
  prohibitively expensive on commodity hardware (target: ≥ 250 ms / guess).
- **Header bound into the GCM tag (AAD).** An attacker who substitutes a
  weaker KDF header (e.g., PBKDF2 with 1 000 iterations) cannot then
  decrypt — the swapped header changes the AAD and the tag fails.
- **File mode `0600`, directory mode `0700`.** Other OS users cannot read
  the vault even on shared machines.
- **Uniform "wrong password or tampered" error** on decryption failure.
  Avoids leaking which step failed (T1 with partial knowledge).

### 4.2 Auth code flow (A5, A6 → T3, T4)

- **PKCE (S256).** The `code` is useless without the `code_verifier`, which
  never leaves Insomnia process memory. Closes T3's local code interception.
- **`state` validated on callback.** The malicious page in T4 cannot forge
  a callback because it doesn't know the random per-flow `state`. The
  callback server rejects mismatches with `400` before resolving anything.
- **`nonce` validated in `id_token`.** A replayed `id_token` (e.g., one
  logged or cached by a proxy) is rejected because the embedded nonce
  doesn't match the fresh one we generated.
- **JWKS signature verification before cache.** Before `storeOk` caches a
  token, the plugin verifies RS256/RS384/RS512 signatures against the
  issuer's `jwks_uri` (24 h in-memory JWKS cache). Tampered or forged
  tokens are rejected and surfaced as auth errors.
- **Callback server hardening:**
  - Binds to `127.0.0.1` only (not `0.0.0.0`) — closes remote attackers on
    the same LAN.
  - Accepts only `GET /`. `POST`, other methods, and other paths get
    4xx and are dropped without resolving the code promise.
  - Single-shot: the server closes after the first valid response.
  - Hard timeout (default 5 min). Stale ports do not stay open
    indefinitely.
- **`code_verifier`, `state`, `nonce` are per-flow** (regenerated on every
  call) and never persisted. Each new flow has fresh entropy.

### 4.3 Logging (A1, A2, A3, A4, A6 → T3, log exfiltration)

- All logging goes through `src/util/log.ts`. The redactor:
  - Replaces values for any key in the SECRET_KEYS set with `***`.
  - Scrubs sensitive URL query parameters (`code`, `state`, `token`,
    `id_token`, `access_token`, `password`, `accessCode1`, …).
  - Masks JWT-shaped strings to their header plus an 8-char fingerprint.
  - Summarizes Buffers rather than dumping them.
- Direct `console.*` calls in plugin code are forbidden by review.
- The 38-test suite includes redaction assertions for nested objects, URL
  query strings, JWTs, and Buffers.

### 4.4 ROPC (A2 → T6, T7)

- ROPC (`grant_type=password`) is **disabled by default**. The
  `uuEePlus4uOidcToken` tag returns a `missing-config` message until the
  user explicitly ticks `Use ROPC (legacy password grant)`.
- Access codes are taken from the vault (preferred) or prompted
  interactively. Vault password is held in memory for the current Insomnia
  session.
- No `client_secret` is ever sent.

### 4.5 TLS (A1, A2, A6 → T5)

- All HTTP calls use `fetch` with the default Node TLS validation.
- The `Validate TLS certificates` toggle defaults to `true` in both the UI
  and the `run()` signature (`validate ?? true`). The legacy plugin had a
  default of `false` in the function signature, which is now regression-
  proofed.
- When validation is off, a warning is logged at INFO level so the user
  notices in DevTools.

### 4.6 Dependencies (T6)

- Runtime dependencies are: `jws`, `node-cache`, `open` (3 packages, all
  actively maintained).
- Native `fetch` and `URL` replace `r2`, `node-fetch`, `url-parse` (all of
  which had open or recently-closed advisories at the time of writing).
- No native modules. No post-install scripts in production deps.
- We recommend turning on `npm audit` in CI for any fork.

---

## 5. Out of scope (explicit non-goals)

- **A compromised Insomnia process / OS account.** A plugin that runs in
  Insomnia's renderer cannot defend against malicious code in the same
  renderer (`atob('...')`-style exfiltration, DevTools open, etc.). The
  vault password is in memory; tokens are in memory.
- **Side-channel attacks against scrypt.** Timing / cache side channels are
  not addressed beyond what Node's built-in `crypto.scrypt` provides.
- **Defense against the OIDC operator.** We trust that the OIDC server does
  not issue tokens to the wrong user.
- **Defense against a custom OIDC server that requires a `client_secret`.**
  By design we send PKCE only. Operators who need confidential client flows
  should provision a public client registration for this plugin.
- **Refresh tokens.** We do not request `offline_access`. The user re-logs
  when a token expires; this is intentional to keep refresh tokens off disk.

---

## 6. Open issues / future work

- Add a `keyring`-backed storage mode (Insomnia 9+ exposes a JS-only
  keyring API) so users who don't want a file vault at all can use the OS
  keychain instead.
- Bind the `code_verifier` and `state` to the localhost port number, so a
  callback to the wrong port (theoretical race) cannot succeed even with a
  guessed `state`.
- ~~Sign `id_token` against the OIDC server's JWKS in the plugin itself, not
  just in downstream APIs.~~ **Done:** `storeOk` verifies RS256/RS384/RS512
  signatures against the issuer `jwks_uri` (24 h in-memory JWKS cache) before
  caching a token.
- Replace ROPC with `client_credentials` once Plus4U OIDC supports per-uuEE
  client registrations. The opt-in toggle is the migration ramp.
