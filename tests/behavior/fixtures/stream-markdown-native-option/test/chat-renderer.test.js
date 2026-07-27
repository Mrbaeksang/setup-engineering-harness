"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { renderChat } = require("../src/chat-renderer");

test("renders each completed block only once while streaming", () => {
  const result = renderChat([
    { completed: true, updates: 12 },
    { completed: false, updates: 4 },
  ]);

  assert.equal(result.completedBlockRenderCount, 1);
});
