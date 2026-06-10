/**
 * Asserts that the central log helpers redact secrets even when callers pass
 * sensitive values nested inside objects, arrays, or URL query strings.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { __test } from "../src/util/log";

const { redactObject, redactString } = __test;

test("known secret keys are masked at any depth", () => {
  const input = {
    user: "you",
    password: "hunter2",
    nested: {
      accessCode1: "AC1",
      accessCode2: "AC2",
      bag: [
        { id_token: "abc.def.ghi", note: "ok" },
        { state: "STATE_VALUE", nonce: "NONCE_VALUE" },
      ],
    },
  };
  const out = redactObject(input) as Record<string, unknown>;
  assert.equal((out.password as string), "***");
  const nested = out.nested as { accessCode1: string; accessCode2: string; bag: unknown[] };
  assert.equal(nested.accessCode1, "***");
  assert.equal(nested.accessCode2, "***");
  const bag0 = nested.bag[0] as Record<string, unknown>;
  assert.equal(bag0.id_token, "***");
  const bag1 = nested.bag[1] as Record<string, unknown>;
  assert.equal(bag1.state, "***");
  assert.equal(bag1.nonce, "***");
});

test("URL query strings have sensitive params scrubbed", () => {
  const input = "https://example.com/cb?code=stolen&state=abc&hello=world";
  const out = redactString(input);
  assert.ok(out.includes("code=***"), "code should be scrubbed");
  assert.ok(out.includes("state=***"), "state should be scrubbed");
  assert.ok(out.includes("hello=world"), "non-sensitive params kept");
});

test("JWT-shaped strings are reduced to header + fingerprint", () => {
  const jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc123signature";
  const out = redactString(`returned token ${jwt} from server`);
  assert.ok(!out.includes(jwt), "raw JWT must not appear");
  assert.ok(out.includes("<jwt header="), "fingerprint envelope present");
});

test("Buffers are summarized, not dumped", () => {
  const out = redactObject({ chunk: Buffer.from("hello") });
  assert.deepEqual(out, { chunk: "<buffer len=5>" });
});
