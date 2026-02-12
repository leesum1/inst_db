"""CLI tests for cross-core memory conflict detection tool."""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE instructions (
            sequence_id INTEGER NOT NULL PRIMARY KEY,
            core_id INTEGER NOT NULL,
            virtual_pc VARCHAR(32) NOT NULL,
            physical_pc VARCHAR(32) NOT NULL,
            instruction_code BLOB NOT NULL,
            disassembly VARCHAR NOT NULL
        );
        CREATE TABLE register_dependencies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instruction_id INTEGER NOT NULL,
            register_id INTEGER,
            register_name VARCHAR(16) NOT NULL,
            is_src BOOLEAN NOT NULL,
            is_dst BOOLEAN NOT NULL
        );
        CREATE TABLE memory_operations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            instruction_id INTEGER NOT NULL,
            operation_type VARCHAR(16) NOT NULL,
            virtual_address VARCHAR(32) NOT NULL,
            physical_address VARCHAR(32) NOT NULL,
            data_length INTEGER NOT NULL,
            memory_value VARCHAR(66)
        );
        """
    )


def test_cross_core_conflicts_detects_write_write_and_write_read(tmp_path: Path) -> None:
    db_path = tmp_path / "cross_core_conflicts.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 0, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "str"),
                (2, 1, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "str"),
                (3, 2, "0x0000000000001008", "0x0000000000009008", bytes.fromhex("03000000"), "ldr"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x0000000000002000", "0x0000000000005000", 8, "0x01"),
                (2, "WRITE", "0x0000000000003000", "0x0000000000005004", 8, "0x02"),
                (3, "READ", "0x0000000000004000", "0x0000000000005002", 4, "0x03"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/detect_cross_core_memory_conflicts.py",
            str(db_path),
            "--window",
            "5",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    rows = payload["rows"]
    event_types = {row["event_type"] for row in rows}
    assert "cross_core_write_write" in event_types
    assert "cross_core_write_then_read" in event_types


def test_cross_core_conflicts_respects_window_boundary(tmp_path: Path) -> None:
    db_path = tmp_path / "cross_core_conflicts_window.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 0, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "str"),
                (4, 1, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "ldr"),
                (5, 1, "0x0000000000001008", "0x0000000000009008", bytes.fromhex("03000000"), "ldr"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x0000000000002000", "0x0000000000005000", 8, "0x01"),
                (4, "READ", "0x0000000000003000", "0x0000000000005000", 8, "0x02"),
                (5, "READ", "0x0000000000003008", "0x0000000000005000", 8, "0x03"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/detect_cross_core_memory_conflicts.py",
            str(db_path),
            "--window",
            "3",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    rows = payload["rows"]
    assert any(row["first_seq"] == 1 and row["second_seq"] == 4 for row in rows)
    assert not any(row["first_seq"] == 1 and row["second_seq"] == 5 for row in rows)
