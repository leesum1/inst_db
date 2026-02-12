"""CLI tests for self-modifying instruction query tool."""

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
            pc VARCHAR(32) NOT NULL,
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


def test_self_modifying_cli_json(tmp_path: Path) -> None:
    db_path = tmp_path / "self_mod.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("aaaaaaaa"), "str w0, [x1]"),
                (2, "0x0000000000002000", bytes.fromhex("11223344"), "nop"),
            ],
        )
        conn.execute(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (1, "WRITE", "0x0000000000002000", "0x0000000000002000", 4, "0x00000000deadbeef"),
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_self_modifying.py",
            str(db_path),
            "--json",
            "--window",
            "10",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    rows = payload["rows"]
    assert rows, payload
    assert rows[0]["writer_seq"] == 1
    assert rows[0]["target_seq"] == 2
    assert rows[0]["changed"] is True

