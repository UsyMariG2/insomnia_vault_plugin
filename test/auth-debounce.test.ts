/**
 * Interactive-auth debounce — coalesces rapid Insomnia config preview runs.
 */

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
  __testReset,
  scheduleInteractiveAuth,
} from "../src/util/auth-debounce";
import { __testReset as resetTokenCache } from "../src/util/token-cache";

afterEach(() => {
  __testReset();
  resetTokenCache();
});

test("rapid edits on the same group run the producer only once (latest cacheKey wins)", async () => {
  const seenKeys: string[] = [];
  let runs = 0;

  const makeProducer = (cacheKey: string) => async () => {
    runs++;
    seenKeys.push(cacheKey);
    return `token:${cacheKey}`;
  };

  const p1 = scheduleInteractiveAuth("tag:prod", "key-a", makeProducer("key-a"), 40);
  await new Promise((r) => setTimeout(r, 10));
  const p2 = scheduleInteractiveAuth("tag:prod", "key-b", makeProducer("key-b"), 40);

  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(runs, 1);
  assert.deepEqual(seenKeys, ["key-b"]);
  assert.equal(r1, "token:key-b");
  assert.equal(r2, "token:key-b");
});

test("separate group keys debounce independently", async () => {
  let runs = 0;
  const producer = async () => {
    runs++;
    return "ok";
  };

  await Promise.all([
    scheduleInteractiveAuth("group-a", "a", producer, 30),
    scheduleInteractiveAuth("group-b", "b", producer, 30),
  ]);
  assert.equal(runs, 2);
});

test("a later burst after the first flush schedules a new auth", async () => {
  let runs = 0;
  const producer = async () => {
    runs++;
    return "ok";
  };

  await scheduleInteractiveAuth("tag", "k1", producer, 20);
  assert.equal(runs, 1);

  await scheduleInteractiveAuth("tag", "k2", producer, 20);
  assert.equal(runs, 2);
});
