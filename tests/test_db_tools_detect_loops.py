"""CLI tests for loop detection tool."""

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


def test_loop_detection_is_scoped_per_core(tmp_path: Path) -> None:
    db_path = tmp_path / "loop.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        rows = []
        seq = 1
        for _ in range(3):
            rows.append((seq, 0, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "op"))
            seq += 1
            rows.append((seq, 1, "0x0000000000002000", "0x000000000000a000", bytes.fromhex("01000000"), "op"))
            seq += 1
            rows.append((seq, 0, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("01000000"), "op"))
            seq += 1
            rows.append((seq, 1, "0x0000000000002004", "0x000000000000a004", bytes.fromhex("01000000"), "op"))
            seq += 1

        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/detect_loops.py",
            str(db_path),
            "--json",
            "--min-iter",
            "3",
            "--min-body",
            "2",
            "--max-body",
            "8",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    rows = payload["rows"]
    assert rows, payload
    core_ids = {row["core_id"] for row in rows}
    assert 0 in core_ids
    assert 1 in core_ids
    assert all(row["iterations"] >= 3 for row in rows)
