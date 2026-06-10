/**
 * Callback-server hardening tests.
 *
 *   - Only GET /  is accepted (everything else returns 4xx and does not
 *     resolve the code promise).
 *   - State mismatch fails the flow (no code is returned).
 *   - The server binds to 127.0.0.1 only.
 *
 * Each test starts a fresh server, hits it with `fetch`, then closes the
 * server explicitly so the process can exit.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { startCallbackServer } from "../src/auth/callback-server";

async function fetchOnce(port: number, path: string, init?: RequestInit): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}${path}`, { redirect: "manual", ...init });
}

test("happy path: GET / with matching state resolves with the code", async () => {
  const server = await startCallbackServer({
    expectedState: "STATE-OK",
    redirectAfterSuccess: null,
    timeoutMs: 5000,
  });
  try {
    const wait = server.waitForCode();
    const response = await fetchOnce(server.port, "/?code=AUTH_CODE&state=STATE-OK");
    assert.equal(response.status, 200);
    const result = await wait;
    assert.equal(result.code, "AUTH_CODE");
  } finally {
    server.close();
  }
});

test("POST is rejected with 405 and does not resolve", async () => {
  const server = await startCallbackServer({
    expectedState: "S",
    redirectAfterSuccess: null,
    timeoutMs: 1500,
  });
  try {
    const wait = server.waitForCode().catch((err) => err as Error);
    const response = await fetchOnce(server.port, "/?code=X&state=S", { method: "POST" });
    assert.equal(response.status, 405);
    // Allow a small window — the server should still be open waiting.
    await new Promise((r) => setTimeout(r, 50));
    server.close();
    const settled = await wait;
    assert.ok(settled instanceof Error);
    assert.match((settled as Error).message, /closed before a callback/);
  } finally {
    server.close();
  }
});

test("state mismatch returns 400 and rejects the wait promise", async () => {
  const server = await startCallbackServer({
    expectedState: "RIGHT",
    redirectAfterSuccess: null,
    timeoutMs: 5000,
  });
  try {
    const wait = server.waitForCode().catch((err) => err as Error);
    const response = await fetchOnce(server.port, "/?code=X&state=WRONG");
    assert.equal(response.status, 400);
    const settled = await wait;
    assert.ok(settled instanceof Error);
    assert.match((settled as Error).message, /state.*did not match/i);
  } finally {
    server.close();
  }
});

test("missing code returns 400 and rejects the wait promise", async () => {
  const server = await startCallbackServer({
    expectedState: "S",
    redirectAfterSuccess: null,
    timeoutMs: 5000,
  });
  try {
    const wait = server.waitForCode().catch((err) => err as Error);
    const response = await fetchOnce(server.port, "/?state=S");
    assert.equal(response.status, 400);
    const settled = await wait;
    assert.ok(settled instanceof Error);
    assert.match((settled as Error).message, /Missing.*code/i);
  } finally {
    server.close();
  }
});

test("non-root path returns 404 and does not resolve", async () => {
  const server = await startCallbackServer({
    expectedState: "S",
    redirectAfterSuccess: null,
    timeoutMs: 1500,
  });
  try {
    const wait = server.waitForCode().catch((err) => err as Error);
    const response = await fetchOnce(server.port, "/oops?code=X&state=S");
    assert.equal(response.status, 404);
    await new Promise((r) => setTimeout(r, 50));
    server.close();
    const settled = await wait;
    assert.ok(settled instanceof Error);
  } finally {
    server.close();
  }
});

test("timeout fires when no callback arrives within the configured window", async () => {
  const server = await startCallbackServer({
    expectedState: "S",
    redirectAfterSuccess: null,
    timeoutMs: 100,
  });
  try {
    await assert.rejects(server.waitForCode(), /timed out/i);
  } finally {
    server.close();
  }
});

test("redirectAfterSuccess sends a 302 to the configured URL", async () => {
  const server = await startCallbackServer({
    expectedState: "S",
    redirectAfterSuccess: "https://example.com/done",
    timeoutMs: 5000,
  });
  try {
    const wait = server.waitForCode();
    const response = await fetchOnce(server.port, "/?code=A&state=S");
    assert.equal(response.status, 302);
    assert.equal(response.headers.get("location"), "https://example.com/done");
    await wait;
  } finally {
    server.close();
  }
});

test("survives renderer-style setTimeout that returns a number with no .unref()", async () => {
  // Insomnia executes external plugins in the Electron renderer when
  // "Allow elevated access for plugins" is enabled. There, globalThis
  // .setTimeout is the DOM API and returns a number — no .unref().
  // Regression for the bug where startCallbackServer chained .unref() on
  // the timer handle and threw "setTimeout(...).unref is not a function",
  // breaking uuPersonPlus4uOidcToken and uuPersonCustomOidcToken.
  const realSetTimeout = globalThis.setTimeout;
  const realClearTimeout = globalThis.clearTimeout;
  let fakeSetCalls = 0;
  const fakeIds = new Map<number, NodeJS.Timeout>();
  let nextId = 1;
  (globalThis as { setTimeout: unknown }).setTimeout = ((fn: (...a: unknown[]) => void, ms: number, ...args: unknown[]) => {
    fakeSetCalls += 1;
    const id = nextId++;
    const handle = realSetTimeout(fn, ms, ...args);
    fakeIds.set(id, handle);
    return id;
  }) as unknown as typeof setTimeout;
  (globalThis as { clearTimeout: unknown }).clearTimeout = ((id: number | NodeJS.Timeout) => {
    if (typeof id === "number") {
      const handle = fakeIds.get(id);
      if (handle) {
        realClearTimeout(handle);
        fakeIds.delete(id);
      }
      return;
    }
    realClearTimeout(id);
  }) as unknown as typeof clearTimeout;
  try {
    const server = await startCallbackServer({
      expectedState: "S",
      redirectAfterSuccess: null,
      timeoutMs: 60_000,
    });
    assert.ok(fakeSetCalls >= 1, "expected our setTimeout shim to be called at least once");
    server.close();
    // Drain the pending rejection so node:test does not flag an unhandled rejection.
    await assert.rejects(server.waitForCode(), /closed before a callback/);
  } finally {
    globalThis.setTimeout = realSetTimeout;
    globalThis.clearTimeout = realClearTimeout;
    for (const handle of fakeIds.values()) realClearTimeout(handle);
  }
});
