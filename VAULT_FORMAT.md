# Vault file format — `vault.data` v1 (UUV1)

This document is the binary specification for the file written by
`insomnia-plugin-plus4u-oidc-v2`. It is normative for any future reader or
migration tool. Internal audience (auditors, future maintainers).

The default file lives at `~/.plus4u-oidc-v2/vault.data`. Directory mode is
`0700`, file mode is `0600`.

---

## 1. Layout

All multi-byte integers are big-endian (network byte order).

```
+--------+--------+------------------+
| offset | size   | field            |
+--------+--------+------------------+
|   0    |   4    | magic            |  ASCII "UUV1"
|   4    |   1    | versionMajor     |  current: 1
|   5    |   1    | versionMinor     |  current: 0
|   6    |   2    | headerLen (BE)   |  length in bytes of the header JSON
|   8    | header | header JSON      |  UTF-8 JSON, see §2
|        |   12   | iv               |  AES-GCM nonce (always 12 bytes)
|        |   2    | saltLen (BE)     |  length of salt
|        |  salt  | salt             |  random per-vault, ≥ 16 bytes
|        |   4    | ctLen (BE)       |  length of ciphertext
|        |   ct   | ciphertext       |  AES-256-GCM output
|        |   16   | tag              |  AES-GCM authentication tag (always 16 bytes)
+--------+--------+------------------+
```

A reader MUST stop after `tag` and ignore any trailing bytes; a future
minor version (1.x) may append optional fields, so trailing bytes must not
cause an error.

---

## 2. Header JSON

The header is a single JSON object. Required fields depend on the KDF
algorithm. Unknown fields MUST be preserved by writers that re-encrypt the
same vault.

### 2.1 scrypt (default)

```json
{ "kdf": "scrypt", "logN": 15, "r": 8, "p": 1 }
```

| Field  | Type    | Constraints                            |
| ------ | ------- | -------------------------------------- |
| `kdf`  | string  | MUST be `"scrypt"`                     |
| `logN` | integer | 14 ≤ logN ≤ 20 (current default: 15)   |
| `r`    | integer | 1 ≤ r ≤ 32  (current default: 8)        |
| `p`    | integer | 1 ≤ p ≤ 16  (current default: 1)        |

The derived key length is fixed at **32 bytes** (256 bits) — AES-256 key
size.

### 2.2 PBKDF2-SHA256 (fallback)

```json
{ "kdf": "pbkdf2-sha256", "iterations": 600000 }
```

| Field        | Type    | Constraints                                |
| ------------ | ------- | ------------------------------------------ |
| `kdf`        | string  | MUST be `"pbkdf2-sha256"`                  |
| `iterations` | integer | MUST be ≥ 600 000 (OWASP 2023 minimum)     |

---

## 3. Encryption

- Algorithm: `aes-256-gcm`.
- IV: 12 random bytes from `crypto.randomBytes`. MUST NOT be reused with
  the same key.
- Tag length: 16 bytes (default for `aes-256-gcm`).
- **AAD (additional authenticated data):**

  ```
  AAD = magic ‖ versionMajor ‖ versionMinor ‖ headerJson
  ```

  where `‖` is byte concatenation. Binding the header into the tag
  prevents an attacker from substituting a weaker KDF header against the
  same ciphertext.

Pseudocode (writer):

```
salt          := randomBytes(32)
key           := KDF(password, salt, params)         // 32 bytes
plaintext     := utf8(JSON.stringify(VaultContents))
header        := JSON of {kdf, ...params}
aad           := MAGIC ‖ 0x01 ‖ 0x00 ‖ header
{iv, ct, tag} := AES-256-GCM(key, plaintext, aad)
bytes         := MAGIC ‖ 0x01 ‖ 0x00 ‖ headerLen ‖ header ‖
                 iv ‖ saltLen ‖ salt ‖ ctLen ‖ ct ‖ tag
write bytes to <vault>.tmp, fsync, rename to <vault>
```

Pseudocode (reader):

```
parse layout
header := JSON.parse(headerJson)  // reject if invalid
params := headerToParams(header)  // reject unknown kdf
key    := KDF(password, salt, params)
aad    := reconstruct as above
plaintext := AES-256-GCM_decrypt(key, iv, ct, tag, aad)
if decrypt fails → raise "wrong password or tampered"
return JSON.parse(plaintext) as VaultContents
```

---

## 4. Plaintext payload

```ts
interface VaultContents {
  entries: {
    [identification: string]: {
      accessCode1: string;
      accessCode2: string;
      oidcServer: string;
      meta?: { [key: string]: string };
    };
  };
}
```

- `identification` is a free-form label chosen by the user (e.g., a
  uuIdentity or `"my-bot"`). It SHOULD be ≤ 255 chars but no hard limit
  is enforced.
- The same label MAY appear more than once when paired with different
  `oidcServer` values. Writers store such entries under a composite map
  key: `identification` + ASCII `0x1E` + normalized `oidcServer` (no
  trailing slash). Readers MUST still accept legacy keys that are only
  `identification` (one entry per label).
- `oidcServer` is a base URL **without** trailing slash. Empty string is
  invalid.
- `meta` is reserved for forward-compatibility. Readers MUST preserve
  unknown keys on rewrite. The migration tool sets
  `meta.migratedFrom = "oidc-plus4u-vault"`.

---

## 5. Atomicity & locking

- Writes go to `<file>.tmp`, then `rename()` to the final path.
- No file locking is performed. Two concurrent Insomnia instances writing
  the same vault will race; the last writer wins. Users are advised not
  to run multiple Insomnia windows against the same vault.

---

## 6. Versioning policy

- **versionMajor** is incremented for breaking format changes (e.g., a new
  layout). Old plugins MUST refuse to read a file with an unknown major.
- **versionMinor** is incremented for additive changes (new optional
  fields in the header, new trailing sections). Old plugins MUST tolerate
  files with a higher minor as long as the major matches.
- **KDF parameter migration:** to increase, e.g., scrypt `logN`, write a
  fresh vault using the new parameters on the next user-initiated write.
  The format is self-describing, so old files with weaker parameters
  remain readable.

---

## 7. Constants (current version)

| Constant                    | Value                                |
| --------------------------- | ------------------------------------ |
| `MAGIC`                     | `0x55 0x55 0x56 0x31` (`"UUV1"`)     |
| `VERSION_MAJOR`             | `0x01`                               |
| `VERSION_MINOR`             | `0x00`                               |
| AES algorithm               | `aes-256-gcm`                        |
| IV length                   | 12 bytes                             |
| Tag length                  | 16 bytes                             |
| Default salt length         | 32 bytes (writers); ≥ 16 (readers)   |
| KDF default (scrypt)        | `logN=15, r=8, p=1`                  |
| KDF default (PBKDF2)        | `iterations=600 000`                 |
| File mode                   | `0o600`                              |
| Directory mode              | `0o700`                              |

---

## 8. Sample (hex dump)

A round-tripped vault containing one entry with `kdf=scrypt, logN=15`,
truncated for brevity:

```
55 55 56 31 01 00 00 2c   {"kdf":"scrypt","logN":15,"r":8,"p":1}
<12-byte iv>
00 20 <32-byte salt>
00 00 00 5d <93-byte ciphertext>
<16-byte tag>
```
