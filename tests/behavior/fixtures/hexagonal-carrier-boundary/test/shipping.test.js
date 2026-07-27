"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

test("the application rule depends on a carrier port, not HTTP", async () => {
  const { quoteShipping } = require("../src/domain/quote-shipping");
  const calls = [];
  const carrier = {
    async quote(request) {
      calls.push(request);
      return { amount: 1250, currency: "KRW" };
    },
  };

  const result = await quoteShipping(
    { destination: "Seoul", weightGrams: 500 },
    carrier,
  );

  assert.deepEqual(calls, [
    { destination: "Seoul", weightGrams: 500 },
  ]);
  assert.deepEqual(result, { amount: 1250, currency: "KRW" });
});

test("the HTTP carrier adapter owns the transport details", async () => {
  const { createHttpCarrier } = require("../src/adapters/http-carrier");
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    return {
      ok: true,
      async json() {
        return { amount: 980, currency: "KRW" };
      },
    };
  };
  const carrier = createHttpCarrier({
    baseUrl: "https://carrier.invalid",
    fetchImpl,
  });

  const result = await carrier.quote({
    destination: "Busan",
    weightGrams: 250,
  });

  assert.equal(requests.length, 1);
  assert.match(requests[0].url, /\/quotes$/);
  assert.equal(requests[0].options.method, "POST");
  assert.deepEqual(result, { amount: 980, currency: "KRW" });
});
