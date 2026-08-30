#!/usr/bin/env python3
"""Coordinate an in-container Behave step with its host-side fixture runner."""

import os
import sys
import time
from pathlib import Path


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: orchestrated_action.py ACTION")

    action = sys.argv[1].strip()
    if not action or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in action):
        raise SystemExit(f"invalid action name: {action!r}")

    state_dir = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
    timeout = float(os.getenv("TEST_ACTION_TIMEOUT_SECONDS", "25"))
    request = state_dir / f"{action}.request"
    complete = state_dir / f"{action}.complete"
    state_dir.mkdir(parents=True, exist_ok=True)
    complete.unlink(missing_ok=True)
    request.write_text(f"pid={os.getpid()}\n", encoding="utf-8")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if complete.exists():
            outcome = complete.read_text(encoding="utf-8").strip()
            request.unlink(missing_ok=True)
            complete.unlink(missing_ok=True)
            if outcome.startswith("error:"):
                raise SystemExit(outcome)
            return
        time.sleep(0.1)

    request.unlink(missing_ok=True)
    raise SystemExit(f"timed out waiting for host action {action!r}")


if __name__ == "__main__":
    main()
