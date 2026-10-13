import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { calculate, parseSet } from "../web/psi.mjs";

test("deduplicates and preserves Alice order", async () => {
  const res = await calculate(" b\na\na\n c ", "c\nb\nd");
  assert.deepEqual(res.intersection, ["b", "c"]);
  assert.equal(res.intersectionSize, 2);
  assert.equal(res.aliceSize, 3);
});

test("cardinality mode omits identifiers", async () => {
  const res = await calculate("a\nb", "b\nc", "cardinality");
  assert.equal(res.intersectionSize, 1);
  assert.equal(Object.hasOwn(res, "intersection"), false);
});

test("SHA-256 matching agrees with exact set matching", async () => {
  const res = await calculate("a\nb", "b\nc", "hash", webcrypto);
  assert.deepEqual(res.intersection, ["b"]);
});

test("bad inputs are rejected", async () => {
  assert.throws(() => parseSet("x".repeat(513)));
  await assert.rejects(calculate("", "a"), /at least one/);
  await assert.rejects(calculate("a", "b", "other"), /Unknown/);
});
