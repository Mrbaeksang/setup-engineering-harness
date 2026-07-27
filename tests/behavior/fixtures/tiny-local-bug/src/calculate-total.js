"use strict";

function calculateTotal(subtotal, shipping) {
  return subtotal - shipping;
}

module.exports = { calculateTotal };
