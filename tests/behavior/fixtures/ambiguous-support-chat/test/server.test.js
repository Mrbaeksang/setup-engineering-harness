"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { health } = require("../src/server");

test("reports health", () => {
  assert.deepEqual(health(), { status: "ok" });
});
