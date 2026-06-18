/**
 * Vault CLI handler tests — `runVaultAdd`, `runVaultDelete`, `runVaultList`.
 *
 * Each test routes through a temp vault file under `os.tmpdir()` so the
 * user's real `~/.plus4u-oidc-v2/vault.data` is never touched. All side
 * effects (prompts, ROPC HTTP call, log, stdout) are stubbed via the
 * `VaultCliDeps` injection.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, statSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runVaultAdd, runVaultDelete, runVaultImport, runVaultList, type VaultCliDeps } from "../src/cli/vault";
import { entryStorageKey } from "../src/vault/keys";
import { addEntry, readVault, writeVault } from "../src/vault/store";

interface StubDeps extends VaultCliDeps {
  promptCalls: string[];
  promptPasswordCalls: string[];
  ropcCalls: Array<Record<string, unknown>>;
  stdoutBuf: string;
  errorBuf: string[];
  infoBuf: string[];
}

interface StubOptions {
  prompts?: string[];
  passwords?: string[];
  ropcResult?: { idToken: string; raw: Record<string, unknown> } | null;
  ropcError?: Error;
}

function makeDeps(options: StubOptions = {}): StubDeps {
  const prompts = [...(options.prompts ?? [])];
  const passwords = [...(options.passwords ?? [])];
  const deps: StubDeps = {
    promptCalls: [],
    promptPasswordCalls: [],
    ropcCalls: [],
    stdoutBuf: "",
    errorBuf: [],
    infoBuf: [],
    promptText: async (q) => {
      deps.promptCalls.push(q);
      const next = prompts.shift();
      if (next === undefined) throw new Error(`No stubbed promptText answer for: ${q}`);
      return next;
    },
    promptPassword: async (q) => {
      deps.promptPasswordCalls.push(q);
      const next = passwords.shift();
      if (next === undefined) throw new Error(`No stubbed promptPassword answer for: ${q}`);
      return next;
    },
    ropc: (async (req) => {
      deps.ropcCalls.push(req as unknown as Record<string, unknown>);
      if (options.ropcError) throw options.ropcError;
      return options.ropcResult ?? { idToken: "stub.id.token", raw: {} };
    }) as VaultCliDeps["ropc"],
    stdout: {
      write: (s) => {
        deps.stdoutBuf += s;
      },
    },
    log: {
      info: (s) => {
        deps.infoBuf.push(s);
      },
      error: (s) => {
        deps.errorBuf.push(s);
      },
    },
  };
  return deps;
}

function tempVaultPath(): { dir: string; filePath: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "plus4u-vault-cli-test-"));
  const filePath = join(dir, "vault.data");
  return {
    dir,
    filePath,
    cleanup: () => {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    },
  };
}

test("vault add: creates a new vault on first add, stores the entry, calls ropc with the supplied codes", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const deps = makeDeps({
    passwords: ["AC1-secret", "AC2-secret", "new-vault-password-1234", "new-vault-password-1234"],
  });
  try {
    const code = await runVaultAdd(
      new Map([["user", "alice"], ["vault", filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    assert.equal(deps.ropcCalls.length, 1);
    assert.equal((deps.ropcCalls[0] as { accessCode1: string }).accessCode1, "AC1-secret");
    assert.equal((deps.ropcCalls[0] as { accessCode2: string }).accessCode2, "AC2-secret");
    assert.equal((deps.ropcCalls[0] as { shape: string }).shape, "uu-oidc");
    assert.match((deps.ropcCalls[0] as { oidcServer: string }).oidcServer, /^https:\/\/uuidentity\.plus4u\.net\//);
    const vault = await readVault("new-vault-password-1234", { filePath });
    const aliceKey = entryStorageKey("alice", (deps.ropcCalls[0] as { oidcServer: string }).oidcServer);
    assert.equal(vault.entries[aliceKey]?.accessCode1, "AC1-secret");
    assert.equal(vault.entries[aliceKey]?.accessCode2, "AC2-secret");
  } finally {
    cleanup();
  }
});

test("vault add: appends to an existing vault and preserves prior entries", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const vaultPw = "existing-vault-pw-1234";
  try {
    await addEntry(
      "bob",
      { accessCode1: "B1", accessCode2: "B2", oidcServer: "https://oidc.example.com/x" },
      vaultPw,
      { filePath },
    );
    await addEntry(
      "carol",
      { accessCode1: "C1", accessCode2: "C2", oidcServer: "https://oidc.example.com/y" },
      vaultPw,
      { filePath },
    );
    const deps = makeDeps({
      passwords: ["D1", "D2", vaultPw],
    });
    const code = await runVaultAdd(
      new Map([["user", "dave"], ["uri", "https://oidc.example.com/z"], ["vault", filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    const vault = await readVault(vaultPw, { filePath });
    assert.deepEqual(Object.keys(vault.entries).sort(), [
      entryStorageKey("bob", "https://oidc.example.com/x"),
      entryStorageKey("carol", "https://oidc.example.com/y"),
      entryStorageKey("dave", "https://oidc.example.com/z"),
    ]);
    assert.equal(vault.entries[entryStorageKey("dave", "https://oidc.example.com/z")]?.oidcServer, "https://oidc.example.com/z");
  } finally {
    cleanup();
  }
});

test("vault add: aborts when ropc throws and never touches the vault", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const vaultPw = "existing-vault-pw-1234";
  try {
    await addEntry(
      "bob",
      { accessCode1: "B1", accessCode2: "B2", oidcServer: "https://oidc.example.com/x" },
      vaultPw,
      { filePath },
    );
    const mtimeBefore = statSync(filePath).mtimeMs;
    const deps = makeDeps({
      passwords: ["bad1", "bad2"],
      ropcError: new Error("invalid_grant: bad credentials"),
    });
    const code = await runVaultAdd(
      new Map([["user", "eve"], ["vault", filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 3);
    assert.equal(deps.errorBuf[0], "Credentials test failed: invalid_grant: bad credentials");
    const mtimeAfter = statSync(filePath).mtimeMs;
    assert.equal(mtimeBefore, mtimeAfter, "vault file should not have been rewritten");
    const vault = await readVault(vaultPw, { filePath });
    assert.equal("eve" in vault.entries, false);
  } finally {
    cleanup();
  }
});

test("vault add: rejects missing --user without prompting or writing", async () => {
  const { filePath, cleanup } = tempVaultPath();
  try {
    const deps = makeDeps();
    const code = await runVaultAdd(new Map([["vault", filePath]]), new Set(), deps);
    assert.equal(code, 2);
    assert.equal(deps.promptPasswordCalls.length, 0);
    assert.equal(deps.ropcCalls.length, 0);
    assert.equal(existsSync(filePath), false);
  } finally {
    cleanup();
  }
});

test("vault add: same user with two OIDC servers keeps both entries", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const vaultPw = "existing-vault-pw-1234";
  const oidcA = "https://oidc.example.com/a";
  const oidcB = "https://oidc.example.com/b";
  try {
    await addEntry(
      "shared-user",
      { accessCode1: "A1", accessCode2: "A2", oidcServer: oidcA },
      vaultPw,
      { filePath },
    );
    const deps = makeDeps({
      passwords: ["B1", "B2", vaultPw],
    });
    const code = await runVaultAdd(
      new Map([["user", "shared-user"], ["uri", oidcB], ["vault", filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    const vault = await readVault(vaultPw, { filePath });
    assert.equal(vault.entries[entryStorageKey("shared-user", oidcA)]?.accessCode1, "A1");
    assert.equal(vault.entries[entryStorageKey("shared-user", oidcB)]?.accessCode1, "B1");
  } finally {
    cleanup();
  }
});

test("vault delete: removes the targeted entry and leaves others intact", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const vaultPw = "existing-vault-pw-1234";
  try {
    await addEntry("alpha", { accessCode1: "1", accessCode2: "2", oidcServer: "https://oidc.example.com/a" }, vaultPw, { filePath });
    await addEntry("beta",  { accessCode1: "3", accessCode2: "4", oidcServer: "https://oidc.example.com/b" }, vaultPw, { filePath });
    const deps = makeDeps({ passwords: [vaultPw] });
    const code = await runVaultDelete(
      new Map([["user", "alpha"], ["vault", filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    const vault = await readVault(vaultPw, { filePath });
    assert.deepEqual(Object.keys(vault.entries).sort(), [entryStorageKey("beta", "https://oidc.example.com/b")]);
  } finally {
    cleanup();
  }
});

test("vault list: prints '<id> - <url>' sorted, one per line", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const vaultPw = "existing-vault-pw-1234";
  try {
    await addEntry("zeta",  { accessCode1: "1", accessCode2: "2", oidcServer: "https://oidc.example.com/z" }, vaultPw, { filePath });
    await addEntry("alpha", { accessCode1: "3", accessCode2: "4", oidcServer: "https://oidc.example.com/a" }, vaultPw, { filePath });
    await addEntry("mu",    { accessCode1: "5", accessCode2: "6", oidcServer: "https://oidc.example.com/m" }, vaultPw, { filePath });
    const deps = makeDeps({ passwords: [vaultPw] });
    const code = await runVaultList(new Map([["vault", filePath]]), deps);
    assert.equal(code, 0);
    assert.equal(
      deps.stdoutBuf,
      "alpha - https://oidc.example.com/a\nmu - https://oidc.example.com/m\nzeta - https://oidc.example.com/z\n",
    );
  } finally {
    cleanup();
  }
});

test("vault import: merges source entries into a new target vault", async () => {
  const source = tempVaultPath();
  const target = tempVaultPath();
  const sourcePw = "source-vault-pw-1234";
  const targetPw = "target-vault-pw-1234";
  const oidcA = "https://oidc.example.com/a";
  const oidcB = "https://oidc.example.com/b";
  try {
    await addEntry("alice", { accessCode1: "A1", accessCode2: "A2", oidcServer: oidcA }, sourcePw, { filePath: source.filePath });
    await addEntry("bob", { accessCode1: "B1", accessCode2: "B2", oidcServer: oidcB }, sourcePw, { filePath: source.filePath });
    const sourceBefore = await readVault(sourcePw, { filePath: source.filePath });
    const deps = makeDeps({ passwords: [sourcePw, targetPw, targetPw] });
    const code = await runVaultImport(
      new Map([["source", source.filePath], ["vault", target.filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    const imported = await readVault(targetPw, { filePath: target.filePath });
    assert.deepEqual(Object.keys(imported.entries).sort(), [
      entryStorageKey("alice", oidcA),
      entryStorageKey("bob", oidcB),
    ]);
    assert.equal(imported.entries[entryStorageKey("alice", oidcA)]?.accessCode1, "A1");
    assert.deepEqual(await readVault(sourcePw, { filePath: source.filePath }), sourceBefore);
    assert.match(deps.infoBuf.join("\n"), /NOT modified/);
  } finally {
    source.cleanup();
    target.cleanup();
  }
});

test("vault import: merges into an existing target and source overwrites collisions", async () => {
  const source = tempVaultPath();
  const target = tempVaultPath();
  const sourcePw = "source-vault-pw-1234";
  const targetPw = "target-vault-pw-1234";
  const oidcShared = "https://oidc.example.com/shared";
  const oidcOther = "https://oidc.example.com/other";
  try {
    await addEntry("alice", { accessCode1: "SRC-A1", accessCode2: "SRC-A2", oidcServer: oidcShared }, sourcePw, { filePath: source.filePath });
    await addEntry("carol", { accessCode1: "SRC-C1", accessCode2: "SRC-C2", oidcServer: oidcOther }, sourcePw, { filePath: source.filePath });
    await addEntry("bob", { accessCode1: "TGT-B1", accessCode2: "TGT-B2", oidcServer: "https://oidc.example.com/bob-only" }, targetPw, { filePath: target.filePath });
    await addEntry("alice", { accessCode1: "TGT-A1", accessCode2: "TGT-A2", oidcServer: oidcShared }, targetPw, { filePath: target.filePath });
    const deps = makeDeps({ passwords: [sourcePw, targetPw] });
    const code = await runVaultImport(
      new Map([["source", source.filePath], ["vault", target.filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    const merged = await readVault(targetPw, { filePath: target.filePath });
    assert.equal(merged.entries[entryStorageKey("alice", oidcShared)]?.accessCode1, "SRC-A1");
    assert.equal(merged.entries[entryStorageKey("bob", "https://oidc.example.com/bob-only")]?.accessCode1, "TGT-B1");
    assert.equal(merged.entries[entryStorageKey("carol", oidcOther)]?.accessCode1, "SRC-C1");
  } finally {
    source.cleanup();
    target.cleanup();
  }
});

test("vault import: rejects missing --source without prompting", async () => {
  const target = tempVaultPath();
  try {
    const deps = makeDeps();
    const code = await runVaultImport(new Map([["vault", target.filePath]]), new Set(), deps);
    assert.equal(code, 2);
    assert.equal(deps.promptPasswordCalls.length, 0);
    assert.equal(existsSync(target.filePath), false);
  } finally {
    target.cleanup();
  }
});

test("vault import: rejects when source and target paths are the same", async () => {
  const { filePath, cleanup } = tempVaultPath();
  const vaultPw = "existing-vault-pw-1234";
  try {
    await addEntry("solo", { accessCode1: "1", accessCode2: "2", oidcServer: "https://oidc.example.com/solo" }, vaultPw, { filePath });
    const deps = makeDeps();
    const code = await runVaultImport(
      new Map([["source", filePath], ["vault", filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 2);
    assert.equal(deps.promptPasswordCalls.length, 0);
  } finally {
    cleanup();
  }
});

test("vault import: accepts -s as short form of --source", async () => {
  const source = tempVaultPath();
  const target = tempVaultPath();
  const sourcePw = "source-vault-pw-1234";
  const targetPw = "target-vault-pw-1234";
  const oidc = "https://oidc.example.com/short";
  try {
    await writeVault(
      {
        entries: {
          [entryStorageKey("short-user", oidc)]: {
            accessCode1: "S1",
            accessCode2: "S2",
            oidcServer: oidc,
          },
        },
      },
      sourcePw,
      { filePath: source.filePath },
    );
    const deps = makeDeps({ passwords: [sourcePw, targetPw, targetPw] });
    const code = await runVaultImport(
      new Map([["s", source.filePath], ["vault", target.filePath]]),
      new Set(),
      deps,
    );
    assert.equal(code, 0);
    const imported = await readVault(targetPw, { filePath: target.filePath });
    assert.equal(imported.entries[entryStorageKey("short-user", oidc)]?.accessCode1, "S1");
  } finally {
    source.cleanup();
    target.cleanup();
  }
});
