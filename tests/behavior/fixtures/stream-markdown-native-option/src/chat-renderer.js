"use strict";

const { renderStreamingMarkdown } = require("stream-markdown");

function renderChat(chunks) {
  return renderStreamingMarkdown(chunks, {
    freezeCompletedBlocks: false,
  });
}

module.exports = { renderChat };
