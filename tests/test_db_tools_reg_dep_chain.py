"""CLI tests for register dependency chain tool."""

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


def test_reg_dependency_chain_cli_json(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("01000000"), "mov x0, #1"),
                (2, "0x0000000000001004", bytes.fromhex("02000000"), "add x1, x0, #2"),
                (3, "0x0000000000001008", bytes.fromhex("03000000"), "add x2, x1, #3"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "x0", 0, 1),
                (2, "x0", 1, 0),
                (2, "x1", 0, 1),
                (3, "x1", 1, 0),
                (3, "x2", 0, 1),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
            str(db_path),
            "--seq-id",
            "3",
            "--max-depth",
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
    chain_pairs = {(row["parent_seq"], row["seq_id"], row["via_register"]) for row in rows}
    assert (3, 2, "x1") in chain_pairs
    assert (2, 1, "x0") in chain_pairs


def test_reg_dependency_chain_json_includes_memory_details(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_mem.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000002000", bytes.fromhex("01000000"), "ldr x0, [x2]"),
                (2, "0x0000000000002004", bytes.fromhex("02000000"), "add x1, x0, #1"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "x2", 1, 0),
                (1, "x0", 0, 1),
                (2, "x0", 1, 0),
                (2, "x1", 0, 1),
            ],
        )
        conn.execute(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (1, "READ", "0x0000000000003000", "0x0000000000003000", 8, "0x00000000000000aa"),
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
            str(db_path),
            "--seq-id",
            "2",
            "--max-depth",
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
    assert rows
    load_row = next(row for row in rows if row["seq_id"] == 1)
    assert load_row["memory_operations"]
    assert load_row["memory_operations"][0]["operation_type"] == "READ"
    assert load_row["memory_operations"][0]["virtual_address"] == "0x0000000000003000"


def test_reg_dependency_chain_supports_tree_output(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_tree.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("01000000"), "mov x0, #1"),
                (2, "0x0000000000001004", bytes.fromhex("02000000"), "add x1, x0, #2"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "x0", 0, 1),
                (2, "x0", 1, 0),
                (2, "x1", 0, 1),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
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
    assert "x0" in result.stdout
    assert "[1]" in result.stdout


def test_reg_dependency_chain_auto_switches_to_mem_for_memory_root(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_auto_mem.db"
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
            "scripts/db_tools/query_reg_dep_chain.py",
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
    rows = payload["rows"]
    assert any(row["parent_seq"] == 2 and row["seq_id"] == 1 for row in rows)

    tree_result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
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
    assert tree_result.returncode == 0, tree_result.stderr
    assert "root-mem" in tree_result.stdout


def test_reg_dependency_chain_child_load_strategy_switch(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_child_strategy.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            "INSERT INTO instructions(sequence_id, pc, instruction_code, disassembly) VALUES(?, ?, ?, ?)",
            [
                (1, "0x0000000000001000", bytes.fromhex("01000000"), "mov x2, #0"),
                (2, "0x0000000000001004", bytes.fromhex("02000000"), "str x3, [x2]"),
                (3, "0x0000000000001008", bytes.fromhex("03000000"), "ldr x0, [x2]"),
                (4, "0x000000000000100c", bytes.fromhex("04000000"), "add x1, x0, #1"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "x2", 0, 1),
                (2, "x2", 1, 0),
                (2, "x3", 1, 0),
                (3, "x2", 1, 0),
                (3, "x0", 0, 1),
                (4, "x0", 1, 0),
                (4, "x1", 0, 1),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (2, "WRITE", "0x0000000000003000", "0x0000000000003000", 8, "0x00000000000000aa"),
                (3, "READ", "0x0000000000003000", "0x0000000000003000", 8, "0x00000000000000aa"),
            ],
        )
        conn.commit()
    finally:
        conn.close()

    default_result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
            str(db_path),
            "--seq-id",
            "4",
            "--mode",
            "reg",
            "--max-depth",
            "4",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert default_result.returncode == 0, default_result.stderr
    default_payload = json.loads(default_result.stdout)
    assert default_payload["meta"]["engine"] == "reg"
    assert default_payload["meta"]["reg_query_logic"] == "load_to_mem"
    default_rows = default_payload["rows"]
    assert any(row["parent_seq"] == 3 and row["seq_id"] == 2 for row in default_rows)
    assert not any(row["parent_seq"] == 3 and row["seq_id"] == 1 for row in default_rows)

    reg_only_result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
            str(db_path),
            "--seq-id",
            "4",
            "--mode",
            "reg",
            "--reg-query-logic",
            "reg_only",
            "--max-depth",
            "4",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert reg_only_result.returncode == 0, reg_only_result.stderr
    reg_only_payload = json.loads(reg_only_result.stdout)
    assert reg_only_payload["meta"]["reg_query_logic"] == "reg_only"
    reg_only_rows = reg_only_payload["rows"]
    assert any(row["parent_seq"] == 3 and row["seq_id"] == 1 for row in reg_only_rows)

def test_mem_dependency_supports_overlap_match(tmp_path: Path) -> None:
    db_path = tmp_path / "mem_length_match.db"
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
            "scripts/db_tools/query_reg_dep_chain.py",
            str(db_path),
            "--seq-id",
            "2",
            "--mode",
            "mem",
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
