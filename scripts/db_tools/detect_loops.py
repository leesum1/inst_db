#!/usr/bin/env python3
"""Detect loops from instruction sequence using hybrid heuristics."""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from typing import Any

from common import (
    EXIT_BAD_ARGS,
    EXIT_OK,
    EXIT_RUNTIME_ERROR,
    EXIT_SCHEMA_ERROR,
    connect_db,
    emit_rows,
    parse_hex,
    validate_schema,
)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", help="Path to SQLite .db file")
    parser.add_argument("--min-iter", type=int, default=3, help="Minimum loop iterations")
    parser.add_argument("--min-body", type=int, default=2, help="Minimum loop body length")
    parser.add_argument("--max-body", type=int, default=64, help="Maximum loop body length")
    parser.add_argument("--limit", type=int, default=100, help="Maximum rows to output")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--verbose", action="store_true", help="Show extra stderr diagnostics")
    return parser.parse_args()


def _load_trace(conn) -> list[tuple[int, str]]:
    rows = conn.execute(
        "SELECT sequence_id, pc FROM instructions ORDER BY sequence_id ASC"
    ).fetchall()
    return [(int(row["sequence_id"]), str(row["pc"])) for row in rows]


def _detect_repeating_windows(
    trace: list[tuple[int, str]], min_iter: int, min_body: int, max_body: int
) -> dict[tuple[str, ...], dict[str, Any]]:
    pcs = [pc for _, pc in trace]
    window_hits: dict[tuple[str, ...], dict[str, Any]] = {}
    max_body = min(max_body, len(trace))

    for body_len in range(min_body, max_body + 1):
        idx = 0
        while idx + body_len * min_iter <= len(pcs):
            window = tuple(pcs[idx : idx + body_len])
            iterations = 1
            cursor = idx + body_len
            while cursor + body_len <= len(pcs) and tuple(pcs[cursor : cursor + body_len]) == window:
                iterations += 1
                cursor += body_len

            if iterations >= min_iter:
                start_seq = trace[idx][0]
                end_seq = trace[cursor - 1][0]
                existing = window_hits.get(window)
                if existing is None or iterations > existing["iterations"]:
                    window_hits[window] = {
                        "start_seq": start_seq,
                        "end_seq": end_seq,
                        "body_len": body_len,
                        "iterations": iterations,
                        "header_pc": window[0],
                    }
                idx = cursor
            else:
                idx += 1

    return window_hits


def _detect_back_edges(trace: list[tuple[int, str]]) -> dict[str, dict[str, Any]]:
    edges: dict[str, dict[str, Any]] = defaultdict(lambda: {"count": 0, "start_seq": None, "end_seq": None})

    for idx in range(1, len(trace)):
        prev_seq, prev_pc = trace[idx - 1]
        cur_seq, cur_pc = trace[idx]
        prev_pc_int = parse_hex(prev_pc)
        cur_pc_int = parse_hex(cur_pc)
        if prev_pc_int is None or cur_pc_int is None:
            continue
        if cur_pc_int < prev_pc_int:
            bucket = edges[cur_pc]
            bucket["count"] += 1
            if bucket["start_seq"] is None:
                bucket["start_seq"] = prev_seq
            bucket["end_seq"] = cur_seq

    return {pc: data for pc, data in edges.items() if data["count"] > 0}


def _merge_results(
    windows: dict[tuple[str, ...], dict[str, Any]],
    back_edges: dict[str, dict[str, Any]],
    min_iter: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    loop_id = 1

    for window_data in sorted(windows.values(), key=lambda item: (-item["iterations"], item["start_seq"])):
        header_pc = window_data["header_pc"]
        edge = back_edges.get(header_pc)
        method_flags = ["window"]
        confidence = "medium"
        if edge and edge["count"] >= min_iter - 1:
            method_flags.append("back_edge")
            confidence = "high"

        rows.append(
            {
                "loop_id": loop_id,
                "start_seq": window_data["start_seq"],
                "end_seq": window_data["end_seq"],
                "approx_header_pc": header_pc,
                "body_len": window_data["body_len"],
                "iterations": window_data["iterations"],
                "method_flags": "+".join(method_flags),
                "confidence": confidence,
            }
        )
        loop_id += 1
        if len(rows) >= limit:
            return rows

    for header_pc, edge in sorted(back_edges.items(), key=lambda item: (-item[1]["count"], item[0])):
        if len(rows) >= limit:
            break
        if any(row["approx_header_pc"] == header_pc for row in rows):
            continue
        rows.append(
            {
                "loop_id": loop_id,
                "start_seq": edge["start_seq"],
                "end_seq": edge["end_seq"],
                "approx_header_pc": header_pc,
                "body_len": None,
                "iterations": edge["count"] + 1,
                "method_flags": "back_edge",
                "confidence": "medium",
            }
        )
        loop_id += 1

    return rows


def _detect_loops(
    db_path: str,
    min_iter: int,
    min_body: int,
    max_body: int,
    limit: int,
) -> list[dict[str, Any]]:
    conn = connect_db(db_path)
    try:
        validate_schema(conn)
        trace = _load_trace(conn)
        if not trace:
            return []
        windows = _detect_repeating_windows(trace, min_iter, min_body, max_body)
        back_edges = _detect_back_edges(trace)
        return _merge_results(windows, back_edges, min_iter, limit)
    finally:
        conn.close()


def main() -> int:
    args = _parse_args()
    if args.min_iter <= 1:
        sys.stderr.write("Error: --min-iter must be > 1\n")
        return EXIT_BAD_ARGS
    if args.min_body <= 0:
        sys.stderr.write("Error: --min-body must be > 0\n")
        return EXIT_BAD_ARGS
    if args.max_body < args.min_body:
        sys.stderr.write("Error: --max-body must be >= --min-body\n")
        return EXIT_BAD_ARGS
    if args.limit <= 0:
        sys.stderr.write("Error: --limit must be > 0\n")
        return EXIT_BAD_ARGS

    try:
        rows = _detect_loops(
            args.db_path,
            args.min_iter,
            args.min_body,
            args.max_body,
            args.limit,
        )
        emit_rows(
            rows,
            [
                "loop_id",
                "start_seq",
                "end_seq",
                "approx_header_pc",
                "body_len",
                "iterations",
                "method_flags",
                "confidence",
            ],
            args.json,
        )
        if args.verbose:
            sys.stderr.write(f"rows={len(rows)}\n")
        return EXIT_OK
    except ValueError as exc:
        sys.stderr.write(f"Schema error: {exc}\n")
        return EXIT_SCHEMA_ERROR
    except Exception as exc:
        sys.stderr.write(f"Runtime error: {exc}\n")
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    raise SystemExit(main())

