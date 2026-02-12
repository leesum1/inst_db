#!/usr/bin/env python3
"""Compatibility wrapper for memory dependency chain query."""

from __future__ import annotations

import sys

from query_reg_dep_chain import main as reg_dep_main


def _force_mem_mode(argv: list[str]) -> list[str]:
    rewritten: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--mode":
            skip_next = True
            continue
        if arg.startswith("--mode="):
            continue
        rewritten.append(arg)
    rewritten.extend(["--mode", "mem"])
    return rewritten


def main() -> int:
    sys.argv = [sys.argv[0], *_force_mem_mode(sys.argv[1:])]
    return reg_dep_main()


if __name__ == "__main__":
    raise SystemExit(main())
