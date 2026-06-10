import { test } from "node:test";
import assert from "node:assert/strict";
import { entryStorageKey } from "../src/vault/keys";
import { findEntryInContents, type VaultEntry } from "../src/vault/store";

const prod = "https://uuidentity.plus4u.net/uu-oidc-maing02/awid/oidc";
const dev = "https://uuidentity-dev.plus4u.net/uu-oidc-maing02/awid/oidc";
const user = "6-804-1";

function entry(oidcServer: string, ac1 = "a1"): VaultEntry {
  return { accessCode1: ac1, accessCode2: "a2", oidcServer };
}

test("findEntryInContents: same user, two OIDC servers via composite keys", () => {
  const entries: Record<string, VaultEntry> = {
    [entryStorageKey(user, prod)]: entry(prod, "prod-ac"),
    [entryStorageKey(user, dev)]: entry(dev, "dev-ac"),
  };
  assert.equal(findEntryInContents(entries, user, prod)?.accessCode1, "prod-ac");
  assert.equal(findEntryInContents(entries, user, dev)?.accessCode1, "dev-ac");
});

test("findEntryInContents: matches by entry.oidcServer when key uses trailing slash", () => {
  const entries: Record<string, VaultEntry> = {
    [entryStorageKey(user, prod)]: entry(`${prod}/`),
  };
  assert.equal(findEntryInContents(entries, user, prod)?.accessCode1, "a1");
});

test("findEntryInContents: legacy key only when oidc matches", () => {
  const entries: Record<string, VaultEntry> = {
    [user]: entry(prod, "legacy-prod"),
  };
  assert.equal(findEntryInContents(entries, user, prod)?.accessCode1, "legacy-prod");
  assert.equal(findEntryInContents(entries, user, dev), null);
});
