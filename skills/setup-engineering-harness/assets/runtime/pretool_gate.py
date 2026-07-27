#!/usr/bin/env python3
"""Launch the bundled full scoped-lease Codex Gate."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.dont_write_bytecode = True
RUNTIME_ROOT = Path(__file__).resolve().parent
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from engineering_harness_gate.codex import (
    READ_ONLY_RESEARCH_TOOLS_ENV,
    STATE_PATH_ENV,
    main as gate_main,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    try:
        status = json.loads(args.status.read_text(encoding="utf-8"))
        if (
            not isinstance(status, dict)
            or status.get("projectRoot") != str(args.repo.resolve(strict=True))
        ):
            raise ValueError("setup status belongs to another Project")
        config = json.loads(
            (
                args.repo
                / ".agent-harness"
                / "config.json"
            ).read_text(encoding="utf-8")
        )
        if not isinstance(config, dict):
            raise ValueError("Harness config must be an object")
        research = config.get("research")
        if not isinstance(research, dict):
            raise ValueError("Harness research config must be an object")
        read_only_research_tools = research.get(
            "read_only_tool_names", []
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"Engineering Harness failed closed: {error}",
            }
        }
        print(json.dumps(response, separators=(",", ":"), sort_keys=True))
        return 0
    environ = dict(os.environ)
    environ[STATE_PATH_ENV] = str(args.state)
    environ[READ_ONLY_RESEARCH_TOOLS_ENV] = json.dumps(
        read_only_research_tools,
        separators=(",", ":"),
    )
    return gate_main(environ=environ)


if __name__ == "__main__":
    raise SystemExit(main())
