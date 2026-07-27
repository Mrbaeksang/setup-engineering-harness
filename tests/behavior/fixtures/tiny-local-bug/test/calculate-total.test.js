"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { calculateTotal } = require("../src/calculate-total");

test("adds shipping to the subtotal", () => {
  assert.equal(calculateTotal(20, 5), 25);
});
