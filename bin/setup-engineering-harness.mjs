#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const packageMetadata = JSON.parse(
  readFileSync(join(packageRoot, "package.json"), "utf8"),
);
const installer = join(
  packageRoot,
  "skills",
  "setup-engineering-harness",
  "scripts",
  "setup_harness.py",
);

const requestedArguments = process.argv.slice(2);
if (
  requestedArguments.length === 1 &&
  ["--version", "-V"].includes(requestedArguments[0])
) {
  process.stdout.write(`${packageMetadata.version}\n`);
  process.exit(0);
}

function pythonVersion(binary) {
  const result = spawnSync(
    binary,
    [
      "-c",
      "import json,sys; print(json.dumps(list(sys.version_info[:3])))",
    ],
    {
      encoding: "utf8",
      shell: false,
      stdio: ["ignore", "pipe", "ignore"],
    },
  );
  if (result.error || result.status !== 0) {
    return null;
  }
  try {
    const version = JSON.parse(result.stdout.trim());
    return Array.isArray(version) && version.length === 3 ? version : null;
  } catch {
    return null;
  }
}

function resolvePython() {
  const configured = process.env.ENGINEERING_HARNESS_PYTHON;
  const candidates = configured ? [configured] : ["python3", "python"];
  const observed = [];

  for (const candidate of candidates) {
    const version = pythonVersion(candidate);
    if (version === null) {
      observed.push(`${candidate}: unavailable`);
      continue;
    }
    observed.push(`${candidate}: ${version.join(".")}`);
    if (version[0] === 3 && version[1] >= 12) {
      return candidate;
    }
  }

  process.stderr.write(
    "setup-engineering-harness requires Python 3.12 or newer.\n" +
      `Checked: ${observed.join(", ")}\n` +
      "Set ENGINEERING_HARNESS_PYTHON to an eligible interpreter if it is not on PATH.\n",
  );
  process.exit(2);
}

const result = spawnSync(resolvePython(), [installer, ...requestedArguments], {
  env: process.env,
  shell: false,
  stdio: "inherit",
});

if (result.error) {
  process.stderr.write(
    `setup-engineering-harness could not start the installer: ${result.error.message}\n`,
  );
  process.exit(2);
}

process.exit(result.status ?? 2);
