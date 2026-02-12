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


def test_reg_dependency_chain_same_core_only(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_same_core.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "mov x0, #1"),
                (2, 0, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "mov x0, #2"),
                (3, 0, "0x0000000000001008", "0x0000000000009008", bytes.fromhex("03000000"), "add x1, x0, #3"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "x0", 0, 1),
                (2, "x0", 0, 1),
                (3, "x0", 1, 0),
                (3, "x1", 0, 1),
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
            "--mode",
            "reg",
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
    assert any(row["parent_seq"] == 3 and row["seq_id"] == 2 for row in rows)
    assert not any(row["seq_id"] == 1 for row in rows)


def test_reg_dependency_chain_load_to_mem_respects_root_core(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_mem_same_core.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "str x3, [x2]"),
                (2, 0, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "str x3, [x2]"),
                (3, 0, "0x0000000000001008", "0x0000000000009008", bytes.fromhex("03000000"), "ldr x0, [x2]"),
                (4, 0, "0x000000000000100c", "0x000000000000900c", bytes.fromhex("04000000"), "add x1, x0, #1"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "x2", 1, 0),
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
                (1, "WRITE", "0x0000000000003000", "0x0000000000005000", 8, "0x00000000000000aa"),
                (2, "WRITE", "0x0000000000003000", "0x0000000000005000", 8, "0x00000000000000aa"),
                (3, "READ", "0x0000000000003000", "0x0000000000005000", 8, "0x00000000000000aa"),
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
            "4",
            "--mode",
            "reg",
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
    assert payload["meta"]["root_core_id"] == 0
    assert any(row["parent_seq"] == 4 and row["seq_id"] == 3 for row in rows)
    assert any(row["parent_seq"] == 3 and row["seq_id"] == 2 for row in rows)
    assert not any(row["seq_id"] == 1 for row in rows)


def test_reg_dependency_chain_supports_tree_output(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_chain_tree.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 0, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "mov x0, #1"),
                (2, 0, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "add x1, x0, #2"),
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
            "--mode",
            "reg",
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
    assert "core=0" in result.stdout


def test_reg_dependency_tree_shows_memory_summary_after_instruction(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_tree_mem_summary.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 0, "0x0000000000002000", "0x0000000000009000", bytes.fromhex("01000000"), "ldr x0, [x2]"),
                (2, 0, "0x0000000000002004", "0x0000000000009004", bytes.fromhex("02000000"), "add x1, x0, #1"),
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
            (1, "READ", "0x0000000000003000", "0x0000000000004000", 8, "0x00000000000000aa"),
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
            "reg",
            "--max-depth",
            "3",
            "--tree",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "| mem:" in result.stdout
    assert "READ va=0x0000000000003000" in result.stdout


def test_reg_dependency_chain_memory_child_auto_switches_to_mem(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_child_mem_auto_switch.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 0, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "mov sp, x0"),
                (2, 0, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "str x3, [sp, #-8]!"),
                (3, 0, "0x0000000000001008", "0x0000000000009008", bytes.fromhex("03000000"), "add x1, sp, #1"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "sp", 0, 1),
                (2, "sp", 1, 1),
                (2, "x3", 1, 0),
                (3, "sp", 1, 0),
                (3, "x1", 0, 1),
            ],
        )
        conn.execute(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            (2, "WRITE", "0x0000000000003000", "0x0000000000003000", 8, "0x00000000000000aa"),
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
            "3",
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
    default_rows = default_payload["rows"]
    assert any(row["parent_seq"] == 3 and row["seq_id"] == 2 for row in default_rows)
    assert not any(row["seq_id"] == 1 for row in default_rows)

    reg_only_result = subprocess.run(
        [
            sys.executable,
            "scripts/db_tools/query_reg_dep_chain.py",
            str(db_path),
            "--seq-id",
            "3",
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
    reg_only_rows = reg_only_payload["rows"]
    assert any(row["seq_id"] == 1 for row in reg_only_rows)


def test_tree_pc_defaults_to_virtual_address(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_tree_virtual_pc_default.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "0x0000000000001111", "0x000000000000aaaa", bytes.fromhex("01000000"), "str w0, [x1]"),
                (2, 0, "0x0000000000002222", "0x000000000000bbbb", bytes.fromhex("02000000"), "ldr w0, [x1]"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x0000000000003000", "0x0000000000005000", 4, "0x0000002a"),
                (2, "READ", "0x0000000000004000", "0x0000000000005000", 4, "0x0000002a"),
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
            "--tree",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "[1] core=1 0x0000000000001111" in result.stdout
    assert "[1] core=1 0x000000000000aaaa" not in result.stdout


def test_reg_memory_switch_can_include_cross_core_with_flag(tmp_path: Path) -> None:
    db_path = tmp_path / "reg_cross_core_mem_flag.db"
    conn = sqlite3.connect(db_path)
    try:
        _create_schema(conn)
        conn.executemany(
            """
            INSERT INTO instructions(sequence_id, core_id, virtual_pc, physical_pc, instruction_code, disassembly)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, 1, "0x0000000000001000", "0x0000000000009000", bytes.fromhex("01000000"), "str x3, [sp, #-8]!"),
                (2, 0, "0x0000000000001004", "0x0000000000009004", bytes.fromhex("02000000"), "mov sp, x0"),
                (3, 0, "0x0000000000001008", "0x0000000000009008", bytes.fromhex("03000000"), "ldr x1, [sp, #-8]"),
                (4, 0, "0x000000000000100c", "0x000000000000900c", bytes.fromhex("04000000"), "add x2, x1, #1"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO register_dependencies(instruction_id, register_id, register_name, is_src, is_dst)
            VALUES(?, NULL, ?, ?, ?)
            """,
            [
                (1, "sp", 1, 1),
                (1, "x3", 1, 0),
                (2, "sp", 0, 1),
                (3, "sp", 1, 0),
                (3, "x1", 0, 1),
                (4, "x1", 1, 0),
                (4, "x2", 0, 1),
            ],
        )
        conn.executemany(
            """
            INSERT INTO memory_operations(instruction_id, operation_type, virtual_address, physical_address, data_length, memory_value)
            VALUES(?, ?, ?, ?, ?, ?)
            """,
            [
                (1, "WRITE", "0x000000000000a000", "0x0000000000005000", 8, "0x00000000000000aa"),
                (3, "READ", "0x000000000000b000", "0x0000000000005000", 8, "0x00000000000000aa"),
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
    default_rows = default_payload["rows"]
    assert any(row["parent_seq"] == 4 and row["seq_id"] == 3 for row in default_rows)
    assert not any(row["seq_id"] == 1 for row in default_rows)

    cross_core_result = subprocess.run(
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
            "--reg-mem-cross-core",
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert cross_core_result.returncode == 0, cross_core_result.stderr
    cross_payload = json.loads(cross_core_result.stdout)
    cross_rows = cross_payload["rows"]
    assert cross_payload["meta"]["reg_mem_cross_core"] is True
    assert any(row["parent_seq"] == 3 and row["seq_id"] == 1 for row in cross_rows)
