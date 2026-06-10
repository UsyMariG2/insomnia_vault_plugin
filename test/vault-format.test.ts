/**
 * Round-trip and tamper-detection tests for the vault file format.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readVault, writeVault, type VaultContents } from "../src/vault/store";
import { decode } from "../src/vault/format";

function makeTempDir(): string {
  return mkdtempSync(join(tmpdir(), "plus4u-oidc-v2-test-"));
}

const samplePayload: VaultContents = {
  entries: {
    "you": {
      accessCode1: "ac1-secret",
      accessCode2: "ac2-secret",
      oidcServer: "https://example.com/oidc",
    },
    "my-bot": {
      accessCode1: "bot-ac1",
      accessCode2: "bot-ac2",
      oidcServer: "https://example.com/oidc",
      meta: { source: "manual" },
    },
  },
};

test("write then read with correct password recovers the same payload", async () => {
  const dir = makeTempDir();
  try {
    const file = join(dir, "vault.data");
    await writeVault(samplePayload, "correct-horse-battery-staple", { filePath: file });
    const recovered = await readVault("correct-horse-battery-staple", { filePath: file });
    assert.deepEqual(recovered, samplePayload);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("read with wrong password rejects without leaking which step failed", async () => {
  const dir = makeTempDir();
  try {
    const file = join(dir, "vault.data");
    await writeVault(samplePayload, "right-password", { filePath: file });
    await assert.rejects(
      () => readVault("wrong-password", { filePath: file }),
      /Vault decryption failed: wrong password or the file has been tampered with\./,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ciphertext tamper causes auth-tag failure on read", async () => {
  const dir = makeTempDir();
  try {
    const file = join(dir, "vault.data");
    await writeVault(samplePayload, "pw", { filePath: file });
    const fs = await import("node:fs/promises");
    const bytes = await fs.readFile(file);
    const parsed = decode(bytes);
    // Flip a single byte in the ciphertext.
    const tamperOffset = bytes.indexOf(parsed.ciphertext) + 0;
    bytes[tamperOffset] ^= 0xff;
    writeFileSync(file, bytes);
    await assert.rejects(
      () => readVault("pw", { filePath: file }),
      /Vault decryption failed/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("header tamper (changing logN value) fails because AAD covers the header", async () => {
  const dir = makeTempDir();
  try {
    const file = join(dir, "vault.data");
    await writeVault(samplePayload, "pw", { filePath: file });
    const fs = await import("node:fs/promises");
    const bytes = await fs.readFile(file);
    // Change `"logN":15` to `"logN":14`. headerToParams still accepts the
    // value as a valid scrypt parameter set, so the only thing that can
    // detect the tamper is the AAD bound into the GCM tag.
    const target = Buffer.from('"logN":15');
    const headerStart = bytes.indexOf(target);
    assert.ok(headerStart > 0, "logN header marker must be present");
    bytes[headerStart + target.length - 1] = "4".charCodeAt(0); // 15 -> 14
    writeFileSync(file, bytes);
    await assert.rejects(() => readVault("pw", { filePath: file }), /Vault decryption failed/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("vault file is created with 0o600 mode and parent dir 0o700", {
  skip: process.platform === "win32" ? "POSIX file modes are not enforced on Windows" : false,
}, async () => {
  const dir = makeTempDir();
  try {
    const file = join(dir, "nested", "vault.data");
    await writeVault(samplePayload, "pw", { filePath: file });
    const fs = await import("node:fs/promises");
    const fileStat = await fs.stat(file);
    const dirStat = await fs.stat(join(dir, "nested"));
    assert.equal(fileStat.mode & 0o777, 0o600);
    assert.equal(dirStat.mode & 0o777, 0o700);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
