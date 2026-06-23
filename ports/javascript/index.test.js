// Smoke test for the JavaScript port. Uses Node's built-in test runner.
//   node --test
import { test } from "node:test";
import assert from "node:assert";
import { normalize, classify, scan, counts, passed } from "./index.js";

test("normalize aliases", () => {
  assert.equal(normalize("MIT License"), "MIT");
  assert.equal(normalize("Apache Software License"), "Apache-2.0");
  assert.equal(normalize("GPLv3"), "GPL-3.0");
  assert.equal(normalize("BSD-3-Clause"), "BSD-3-Clause");
  assert.equal(normalize(""), "UNKNOWN");
  assert.equal(normalize("License :: OSI Approved :: MIT License"), "MIT");
});

test("classify buckets", () => {
  assert.equal(classify("MIT"), "allow");
  assert.equal(classify("MPL-2.0"), "warn");
  assert.equal(classify("GPL-3.0"), "forbid");
  assert.equal(classify("UNKNOWN"), "unknown");
});

test("scan + gate", () => {
  const fs = scan("good==1  # license: MIT\nbad==2  # license: GPL-3.0\nmystery==3\n");
  assert.equal(fs.length, 3);
  const c = counts(fs);
  assert.equal(c.allow, 1);
  assert.equal(c.forbid, 1);
  assert.equal(c.unknown, 1);
  assert.equal(passed(fs), false);
});

test("clean set passes", () => {
  const fs = scan("a==1  # license: MIT\nb==2  # license: Apache-2.0\n");
  assert.equal(passed(fs), true);
});
