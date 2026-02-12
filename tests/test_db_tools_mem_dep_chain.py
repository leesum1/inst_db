"""CLI tests for memory dependency chain tool."""

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


def test_mem_dependency_chain_cli_json(tmp_path: Path) -> None:
    db_path = tmp_path / "mem_chain.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("01000000"), "str x0, [x2]"),
                (2, "0x0000000000001004", bytes.fromhex("02000000"), "ldr x1, [x2]"),
                (3, "0x0000000000001008", bytes.fromhex("03000000"), "ldr x3, [x2]"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x0000000000002000", "0x0000000000002000", 8, "0x00000000000000aa"),
                (2, "READ", "0x0000000000002000", "0x0000000000002000", 8, "0x00000000000000aa"),
                (3, "READ", "0x0000000000002000", "0x0000000000002000", 8, "0x00000000000000aa"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_mem_dep_chain.py",
            str(db_path),
            "--seq-id",
            "3",
            "--max-depth",
            "4",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    rows = payload["rows"]
    assert any(row["seq_id"] == 1 and row["parent_seq"] == 3 for row in rows)


def test_mem_dependency_chain_supports_tree_output(tmp_path: Path) -> None:
    db_path = tmp_path / "mem_chain_tree.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("01000000"), "str x0, [x2]"),
                (2, "0x0000000000001004", bytes.fromhex("02000000"), "ldr x1, [x2]"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x0000000000002000", "0x0000000000002000", 8, "0x00000000000000aa"),
                (2, "READ", "0x0000000000002000", "0x0000000000002000", 8, "0x00000000000000aa"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_mem_dep_chain.py",
            str(db_path),
            "--seq-id",
            "2",
            "--max-depth",
            "3",
            "--tree",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "[2]" in result.stdout
    assert "[1]" in result.stdout
    assert "addr=0x0000000000002000" in result.stdout
    assert "root-mem" in result.stdout
    assert "READ addr=0x0000000000002000" in result.stdout


def test_mem_dependency_chain_supports_overlap_match(tmp_path: Path) -> None:
    db_path = tmp_path / "mem_chain_len.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("01000000"), "str w0, [x2]"),
                (2, "0x0000000000001004", bytes.fromhex("02000000"), "ldr x1, [x2]"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x0000000000002004", "0x0000000000002004", 4, "0x000000aa"),
                (2, "READ", "0x0000000000002000", "0x0000000000002000", 8, "0x00000000000000aa"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_mem_dep_chain.py",
            str(db_path),
            "--seq-id",
            "2",
            "--max-depth",
            "3",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["meta"]["engine"] == "mem"
    assert any(row["parent_seq"] == 2 and row["seq_id"] == 1 for row in payload["rows"])
