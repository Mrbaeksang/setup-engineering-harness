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
    AssistiveCodexAdapter,
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
        write_gate = config.get("write_gate", {})
        if not isinstance(write_gate, dict):
            raise ValueError("Harness write_gate config must be an object")
        mode = write_gate.get("mode", "assistive")
        if mode not in {"assistive", "strict"}:
            raise ValueError("write_gate.mode must be assistive or strict")
        research = config.get("research", {})
        if not isinstance(research, dict):
            raise ValueError("Harness research config must be an object")
        read_only_research_tools = research.get("read_only_tool_names", [])
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
    if mode == "assistive":
        try:
            payload = json.load(sys.stdin)
        except (json.JSONDecodeError, UnicodeError) as error:
            payload = {"_malformed_hook_input": str(error)}
        response = AssistiveCodexAdapter(args.repo).hook_response(payload)
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
