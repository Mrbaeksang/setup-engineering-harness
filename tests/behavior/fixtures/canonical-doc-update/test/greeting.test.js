"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { greeting } = require("../src/greeting");

test("uses the welcome default", () => {
  assert.equal(greeting(), "welcome");
});
