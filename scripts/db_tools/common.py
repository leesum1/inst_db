"""Shared helpers for DB analysis scripts."""

from __future__ import annotations

import json
import sqlite3
import sys
from typing import Any


EXIT_OK = 0
EXIT_BAD_ARGS = 2
EXIT_SCHEMA_ERROR = 3
EXIT_RUNTIME_ERROR = 4

REQUIRED_COLUMNS = {
    "instructions": {
        "sequence_id",
        "core_id",
        "virtual_pc",
        "physical_pc",
        "instruction_code",
        "disassembly",
    },
    "register_dependencies": {
        "instruction_id",
        "register_name",
        "is_src",
        "is_dst",
    },
    "memory_operations": {
        "instruction_id",
        "operation_type",
        "virtual_address",
        "physical_address",
        "data_length",
    },
}


def connect_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.create_function("HEX_TO_INT", 1, parse_hex)
    return conn


def _get_columns(conn: sqlite3.Connection, table_name: str) -> set[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {str(row[1]) for row in rows}


def validate_schema(conn: sqlite3.Connection) -> None:
    for table_name, required in REQUIRED_COLUMNS.items():
        columns = _get_columns(conn, table_name)
        if not columns:
            raise ValueError(f"Missing table: {table_name}")
        missing = sorted(required - columns)
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"Table {table_name} missing columns: {joined}")


def has_column(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    return column_name in _get_columns(conn, table_name)


def parse_hex(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = value.strip().lower()
    if not text:
        return None
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        return None
    return int(text, 16)


def normalize_hex(value: int, width: int = 16) -> str:
    return f"0x{value:0{width}x}"


def fetch_instruction(conn: sqlite3.Connection, sequence_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT sequence_id, core_id, virtual_pc, physical_pc, disassembly, instruction_code
        FROM instructions
        WHERE sequence_id = ?
        """,
        (sequence_id,),
    ).fetchone()


def to_json_bytes(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def print_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(to_json_bytes(payload) + "\n")


def print_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        sys.stdout.write("No results\n")
        return

    widths: dict[str, int] = {column: len(column) for column in columns}
    for row in rows:
        for column in columns:
            widths[column] = max(widths[column], len(str(row.get(column, ""))))

    header = " | ".join(column.ljust(widths[column]) for column in columns)
    separator = "-+-".join("-" * widths[column] for column in columns)
    sys.stdout.write(header + "\n")
    sys.stdout.write(separator + "\n")

    for row in rows:
        line = " | ".join(str(row.get(column, "")).ljust(widths[column]) for column in columns)
        sys.stdout.write(line + "\n")


def emit_rows(rows: list[dict[str, Any]], columns: list[str], as_json: bool) -> None:
    if as_json:
        print_json({"rows": rows, "count": len(rows)})
    else:
        print_table(rows, columns)
