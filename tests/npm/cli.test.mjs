import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

const root = resolve(import.meta.dirname, "..", "..");
const cli = join(root, "bin", "setup-engineering-harness.mjs");

test("reports the package version", () => {
  const result = spawnSync(process.execPath, [cli, "--version"], {
    encoding: "utf8",
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), "0.2.0");
});

test("runs the bundled installer against another repository", () => {
  const repository = mkdtempSync(
    join(tmpdir(), "engineering-harness-npm-test-"),
  );
  writeFileSync(
    join(repository, "package.json"),
    '{"scripts":{"test":"node --test"}}\n',
  );

  const result = spawnSync(
    process.execPath,
    [cli, "plan", "--repo", repository, "--json"],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        PYTHONDONTWRITEBYTECODE: "1",
      },
    },
  );

  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.status, "ready");
  assert.equal(plan.target, realpathSync(repository));
  assert.ok(
    plan.mutations.some(
      (mutation) => mutation.path === ".codex/hooks.json",
    ),
  );
});

test("fails clearly when the configured Python is unavailable", () => {
  const result = spawnSync(process.execPath, [cli, "--help"], {
    encoding: "utf8",
    env: {
      ...process.env,
      ENGINEERING_HARNESS_PYTHON:
        "/definitely/missing/setup-engineering-harness-python",
    },
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires Python 3\.12 or newer/);
});
