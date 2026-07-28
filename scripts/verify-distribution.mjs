#!/usr/bin/env node

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);

function readJson(relativePath) {
  return JSON.parse(readFileSync(new URL(relativePath, root), "utf8"));
}

function requireFile(relativePath) {
  const path = new URL(relativePath, root);
  if (!statSync(path).isFile()) {
    throw new Error(`${relativePath} must be a file`);
  }
}

const packageMetadata = readJson("package.json");
const plugin = readJson(
  "skills/setup-engineering-harness/.claude-plugin/plugin.json",
);
const marketplace = readJson(".claude-plugin/marketplace.json");
const installer = readFileSync(
  new URL(
    "skills/setup-engineering-harness/scripts/setup_harness.py",
    root,
  ),
  "utf8",
);
const harnessVersion = installer.match(
  /^HARNESS_VERSION = "([^"]+)"$/m,
)?.[1];

if (
  packageMetadata.version !== plugin.version ||
  packageMetadata.version !== harnessVersion
) {
  throw new Error(
    `version mismatch: package=${packageMetadata.version}, ` +
      `plugin=${plugin.version}, harness=${harnessVersion ?? "missing"}`,
  );
}

const marketplacePlugin = marketplace.plugins?.find(
  (entry) => entry.name === plugin.name,
);
if (marketplacePlugin?.source !== "./skills/setup-engineering-harness") {
  throw new Error("marketplace source must target the self-contained Skill");
}

for (const path of [
  "LICENSE",
  "NOTICE",
  "README.md",
  "bin/setup-engineering-harness.mjs",
  "skills/setup-engineering-harness/SKILL.md",
]) {
  requireFile(path);
}

function findGeneratedPythonArtifacts(directory) {
  const result = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const child = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__pycache__") {
        result.push(child);
      } else {
        result.push(...findGeneratedPythonArtifacts(child));
      }
    } else if (/\.py[cod]$/.test(entry.name)) {
      result.push(child);
    }
  }
  return result;
}

const generated = findGeneratedPythonArtifacts(
  fileURLToPath(new URL("skills/setup-engineering-harness/", root)),
);
if (generated.length > 0) {
  throw new Error(
    `generated Python artifacts must not be published: ${generated.join(", ")}`,
  );
}

process.stdout.write(
  `Distribution metadata: PASS (${packageMetadata.name}@${packageMetadata.version})\n`,
);
