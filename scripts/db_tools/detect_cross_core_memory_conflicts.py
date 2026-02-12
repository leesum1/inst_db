#!/usr/bin/env python3
"""Detect cross-core memory conflicts in a sequence window."""

from __future__ import annotations

import argparse
import sys
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


SQL_LOAD_MEMORY_EVENTS = """
SELECT
    mo.id,
    mo.instruction_id AS sequence_id,
    i.core_id,
    UPPER(mo.operation_type) AS operation_type,
    mo.virtual_address,
    mo.physical_address,
    mo.data_length
FROM memory_operations AS mo
JOIN instructions AS i
  ON i.sequence_id = mo.instruction_id
WHERE UPPER(mo.operation_type) IN ('READ', 'WRITE')
ORDER BY mo.instruction_id ASC, mo.id ASC
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", help="Path to SQLite .db file")
    parser.add_argument("--window", type=int, default=2000, help="Forward sequence window")
    parser.add_argument("--limit", type=int, default=100, help="Maximum rows to output")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--verbose", action="store_true", help="Show extra stderr diagnostics")
    return parser.parse_args()


def _overlap_range(
    start_a: int,
    len_a: int,
    start_b: int,
    len_b: int,
) -> tuple[int, int] | None:
    end_a = start_a + len_a
    end_b = start_b + len_b
    overlap_start = max(start_a, start_b)
    overlap_end = min(end_a, end_b)
    if overlap_start >= overlap_end:
        return None
    return overlap_start, overlap_end


def _query_conflicts(db_path: str, window: int, limit: int) -> list[dict[str, Any]]:
    conn = connect_db(db_path)
    try:
        validate_schema(conn)
        events = conn.execute(SQL_LOAD_MEMORY_EVENTS).fetchall()

        rows: list[dict[str, Any]] = []
        event_id = 1

        parsed_events: list[dict[str, Any]] = []
        for event in events:
            physical_address = parse_hex(event["physical_address"])
            if physical_address is None:
                continue
            data_length = int(event["data_length"])
            if data_length <= 0:
                continue
            parsed_events.append(
                {
                    "sequence_id": int(event["sequence_id"]),
                    "core_id": int(event["core_id"]),
                    "operation_type": event["operation_type"],
                    "physical_address": physical_address,
                    "physical_address_text": event["physical_address"],
                    "data_length": data_length,
                }
            )

        for idx, first in enumerate(parsed_events):
            if first["operation_type"] != "WRITE":
                continue

            first_seq = int(first["sequence_id"])
            for second in parsed_events[idx + 1 :]:
                second_seq = int(second["sequence_id"])
                if second_seq - first_seq > window:
                    break
                if int(second["core_id"]) == int(first["core_id"]):
                    continue

                overlap = _overlap_range(
                    int(first["physical_address"]),
                    int(first["data_length"]),
                    int(second["physical_address"]),
                    int(second["data_length"]),
                )
                if overlap is None:
                    continue

                second_op = str(second["operation_type"])
                if second_op == "WRITE":
                    event_type = "cross_core_write_write"
                elif second_op == "READ":
                    event_type = "cross_core_write_then_read"
                else:
                    continue

                rows.append(
                    {
                        "event_id": event_id,
                        "event_type": event_type,
                        "first_seq": first_seq,
                        "first_core_id": int(first["core_id"]),
                        "first_op": first["operation_type"],
                        "first_paddr": first["physical_address_text"],
                        "first_len": int(first["data_length"]),
                        "second_seq": second_seq,
                        "second_core_id": int(second["core_id"]),
                        "second_op": second_op,
                        "second_paddr": second["physical_address_text"],
                        "second_len": int(second["data_length"]),
                        "overlap_start": f"0x{overlap[0]:016x}",
                        "overlap_end": f"0x{overlap[1]:016x}",
                        "sequence_distance": second_seq - first_seq,
                    }
                )
                event_id += 1

                if len(rows) >= limit:
                    return rows

        return rows
    finally:
        conn.close()


def main() -> int:
    args = _parse_args()
    if args.window <= 0:
        sys.stderr.write("Error: --window must be > 0\n")
        return EXIT_BAD_ARGS
    if args.limit <= 0:
        sys.stderr.write("Error: --limit must be > 0\n")
        return EXIT_BAD_ARGS

    try:
        rows = _query_conflicts(args.db_path, args.window, args.limit)
        emit_rows(
            rows,
            [
                "event_id",
                "event_type",
                "first_seq",
                "first_core_id",
                "first_op",
                "first_paddr",
                "first_len",
                "second_seq",
                "second_core_id",
                "second_op",
                "second_paddr",
                "second_len",
                "overlap_start",
                "overlap_end",
                "sequence_distance",
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
