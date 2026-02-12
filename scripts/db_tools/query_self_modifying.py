#!/usr/bin/env python3
"""Query potential self-modifying instruction writes."""

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
    has_column,
    parse_hex,
    validate_schema,
)


SQL_LOAD_WRITES = """
SELECT
    mo.instruction_id AS writer_seq,
    mo.virtual_address AS write_addr,
    mo.data_length,
    mo.memory_value
FROM memory_operations AS mo
WHERE UPPER(mo.operation_type) = 'WRITE'
ORDER BY mo.instruction_id ASC
"""


SQL_LOAD_TARGETS = """
SELECT sequence_id, pc, instruction_code, disassembly
FROM instructions
WHERE sequence_id > ?
  AND sequence_id <= ?
ORDER BY sequence_id ASC
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", help="Path to SQLite .db file")
    parser.add_argument("--window", type=int, default=2000, help="Forward sequence window")
    parser.add_argument("--limit", type=int, default=100, help="Maximum rows to output")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--verbose", action="store_true", help="Show extra stderr diagnostics")
    return parser.parse_args()


def _extract_bytes_from_memory_value(memory_value: str | None, inst_len: int) -> bytes | None:
    if not memory_value:
        return None
    try:
        value_int = parse_hex(memory_value)
    except ValueError:
        return None
    if value_int is None:
        return None
    total_len = max(inst_len, 1)
    return int(value_int).to_bytes(total_len, byteorder="little", signed=False)[:inst_len]


def _query_self_mod(db_path: str, window: int, limit: int) -> list[dict[str, Any]]:
    conn = connect_db(db_path)
    try:
        validate_schema(conn)
        has_memory_value = has_column(conn, "memory_operations", "memory_value")

        write_rows = conn.execute(SQL_LOAD_WRITES).fetchall()
        rows: list[dict[str, Any]] = []

        for write_row in write_rows:
            writer_seq = int(write_row["writer_seq"])
            write_addr = parse_hex(write_row["write_addr"])
            if write_addr is None:
                continue
            write_len = int(write_row["data_length"])
            target_upper = writer_seq + window

            targets = conn.execute(SQL_LOAD_TARGETS, (writer_seq, target_upper)).fetchall()
            for target in targets:
                target_seq = int(target["sequence_id"])
                target_pc_int = parse_hex(target["pc"])
                if target_pc_int is None:
                    continue

                instruction_code = bytes(target["instruction_code"])
                inst_len = len(instruction_code)
                inst_start = target_pc_int
                inst_end = inst_start + inst_len
                write_end = write_addr + write_len

                overlaps = write_addr < inst_end and write_end > inst_start
                if not overlaps:
                    continue

                memory_value = write_row["memory_value"] if has_memory_value else None
                extracted = _extract_bytes_from_memory_value(memory_value, inst_len)

                if extracted is None:
                    changed = None
                    confidence = "medium"
                else:
                    changed = extracted != instruction_code
                    confidence = "high" if changed else "low"

                rows.append(
                    {
                        "writer_seq": writer_seq,
                        "target_seq": target_seq,
                        "target_pc": target["pc"],
                        "write_addr": write_row["write_addr"],
                        "inst_len": inst_len,
                        "memory_value": memory_value,
                        "old_code_hex": instruction_code.hex(),
                        "changed": changed,
                        "confidence": confidence,
                    }
                )

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
        rows = _query_self_mod(args.db_path, args.window, args.limit)
        emit_rows(
            rows,
            [
                "writer_seq",
                "target_seq",
                "target_pc",
                "write_addr",
                "inst_len",
                "memory_value",
                "old_code_hex",
                "changed",
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

