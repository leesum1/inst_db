#!/usr/bin/env python3
"""Query register or memory dependency chain for an instruction."""

from __future__ import annotations

import argparse
import sys
from collections import deque
from typing import Any

from common import (
    EXIT_BAD_ARGS,
    EXIT_OK,
    EXIT_RUNTIME_ERROR,
    EXIT_SCHEMA_ERROR,
    connect_db,
    emit_rows,
    fetch_instruction,
    has_column,
    print_json,
    validate_schema,
)


SQL_FIND_PREV_WRITERS_SAME_CORE = """
WITH reads AS (
    SELECT DISTINCT register_name
    FROM register_dependencies
    WHERE instruction_id = ?
      AND is_src = 1
),
candidates AS (
    SELECT
        i.sequence_id,
        i.core_id,
        i.virtual_pc,
        i.physical_pc,
        i.disassembly,
        rd.register_name,
        ROW_NUMBER() OVER (
            PARTITION BY rd.register_name
            ORDER BY i.sequence_id DESC
        ) AS rn
    FROM instructions AS i
    JOIN register_dependencies AS rd
      ON rd.instruction_id = i.sequence_id
    WHERE rd.is_dst = 1
      AND rd.register_name IN (SELECT register_name FROM reads)
      AND i.sequence_id < ?
      AND i.core_id = ?
)
SELECT sequence_id, core_id, virtual_pc, physical_pc, disassembly, register_name
FROM candidates
WHERE rn = 1
ORDER BY sequence_id DESC
"""


def _build_mem_sql(has_memory_value: bool) -> str:
    read_value_expr = "r.memory_value" if has_memory_value else "NULL"
    write_value_expr = "w.memory_value" if has_memory_value else "NULL"
    return f"""
WITH reads AS (
    SELECT
        r.id AS read_id,
        r.instruction_id AS read_instruction_id,
        i_read.core_id AS read_core_id,
        i_read.virtual_pc AS read_virtual_pc,
        i_read.physical_pc AS read_physical_pc,
        r.virtual_address AS read_virtual_address,
        r.physical_address AS read_physical_address,
        HEX_TO_INT(r.virtual_address) AS read_virtual_address_int,
        HEX_TO_INT(r.physical_address) AS read_physical_address_int,
        r.data_length,
        {read_value_expr} AS read_value
    FROM memory_operations AS r
    JOIN instructions AS i_read
      ON i_read.sequence_id = r.instruction_id
    WHERE r.instruction_id = ?
      AND UPPER(r.operation_type) = 'READ'
),
candidates AS (
    SELECT
        rd.read_id,
        rd.read_core_id,
        rd.read_virtual_pc,
        rd.read_physical_pc,
        rd.read_virtual_address,
        rd.read_physical_address,
        rd.data_length,
        rd.read_value,
        i_writer.sequence_id AS writer_seq,
        i_writer.core_id AS writer_core_id,
        i_writer.virtual_pc AS writer_virtual_pc,
        i_writer.physical_pc AS writer_physical_pc,
        i_writer.disassembly,
        {write_value_expr} AS write_value,
        CASE
            WHEN i_writer.core_id = rd.read_core_id THEN 'virtual'
            ELSE 'physical'
        END AS address_mode,
        CASE
            WHEN i_writer.core_id = rd.read_core_id THEN rd.read_virtual_address
            ELSE rd.read_physical_address
        END AS address,
        ROW_NUMBER() OVER (
            PARTITION BY rd.read_id
            ORDER BY i_writer.sequence_id DESC
        ) AS rn
    FROM reads AS rd
    JOIN memory_operations AS w
      ON rd.data_length > 0
     AND w.data_length > 0
     AND HEX_TO_INT(
            CASE
                WHEN (
                    SELECT core_id FROM instructions WHERE sequence_id = w.instruction_id
                ) = rd.read_core_id THEN w.virtual_address
                ELSE w.physical_address
            END
         ) IS NOT NULL
     AND CASE
            WHEN (
                SELECT core_id FROM instructions WHERE sequence_id = w.instruction_id
            ) = rd.read_core_id THEN rd.read_virtual_address_int IS NOT NULL
            ELSE rd.read_physical_address_int IS NOT NULL
         END
     AND HEX_TO_INT(
            CASE
                WHEN (
                    SELECT core_id FROM instructions WHERE sequence_id = w.instruction_id
                ) = rd.read_core_id THEN w.virtual_address
                ELSE w.physical_address
            END
         ) < (
            CASE
                WHEN (
                    SELECT core_id FROM instructions WHERE sequence_id = w.instruction_id
                ) = rd.read_core_id THEN rd.read_virtual_address_int
                ELSE rd.read_physical_address_int
            END
            + rd.data_length
         )
     AND (
            CASE
                WHEN (
                    SELECT core_id FROM instructions WHERE sequence_id = w.instruction_id
                ) = rd.read_core_id THEN rd.read_virtual_address_int
                ELSE rd.read_physical_address_int
            END
         ) < (
            HEX_TO_INT(
                CASE
                    WHEN (
                        SELECT core_id FROM instructions WHERE sequence_id = w.instruction_id
                    ) = rd.read_core_id THEN w.virtual_address
                    ELSE w.physical_address
                END
            )
            + w.data_length
         )
    JOIN instructions AS i_writer
      ON i_writer.sequence_id = w.instruction_id
    WHERE UPPER(w.operation_type) = 'WRITE'
      AND w.instruction_id < rd.read_instruction_id
)
SELECT
    writer_seq,
    writer_core_id,
    writer_virtual_pc,
    writer_physical_pc,
    disassembly,
    address,
    data_length,
    read_value,
    write_value,
    address_mode,
    read_core_id
FROM candidates
WHERE rn = 1
ORDER BY writer_seq DESC
"""


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("db_path", help="Path to SQLite .db file")
    parser.add_argument("--seq-id", type=int, required=True, help="Root instruction sequence ID")
    parser.add_argument(
        "--mode",
        choices=["auto", "reg", "mem"],
        default="auto",
        help="Query engine mode (default: auto)",
    )
    parser.add_argument(
        "--addr-key",
        choices=["virtual_address", "physical_address"],
        default="physical_address",
        help="Legacy address key option (kept for CLI compatibility)",
    )
    parser.add_argument(
        "--reg-query-logic",
        choices=["load_to_mem", "reg_only"],
        default="load_to_mem",
        help="Reg engine traversal logic (default: load_to_mem)",
    )
    parser.add_argument(
        "--reg-mem-cross-core",
        action="store_true",
        help="Allow cross-core writers when reg engine auto-switches to mem",
    )
    parser.add_argument("--max-depth", type=int, default=10, help="Maximum dependency depth")
    parser.add_argument("--limit", type=int, default=100, help="Maximum rows to output")
    parser.add_argument("--tree", action="store_true", help="Emit dependency tree text")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--verbose", action="store_true", help="Show extra stderr diagnostics")
    return parser.parse_args()


def _get_memory_operations(conn, instruction_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT operation_type, virtual_address, physical_address, data_length, memory_value
        FROM memory_operations
        WHERE instruction_id = ?
        ORDER BY id ASC
        """,
        (instruction_id,),
    ).fetchall()
    return [
        {
            "operation_type": row["operation_type"],
            "virtual_address": row["virtual_address"],
            "physical_address": row["physical_address"],
            "data_length": int(row["data_length"]),
            "memory_value": row["memory_value"],
        }
        for row in rows
    ]


def _format_memory_summary(memory_operations: list[dict[str, Any]]) -> str:
    if not memory_operations:
        return ""

    segments: list[str] = []
    for op in memory_operations:
        value_text = f", value={op['memory_value']}" if op.get("memory_value") else ""
        segments.append(
            (
                f"{op['operation_type']} va={op['virtual_address']} "
                f"pa={op['physical_address']} len={op['data_length']}{value_text}"
            )
        )
    return "; ".join(segments)


def _get_root_memory_operations(
    conn: Any,
    seq_id: int,
    has_memory_value: bool,
) -> list[dict[str, Any]]:
    root_mem_sql = (
        """
        SELECT
            UPPER(operation_type) AS operation_type,
            virtual_address,
            physical_address,
            data_length,
            memory_value
        FROM memory_operations
        WHERE instruction_id = ?
        ORDER BY id ASC
        """
        if has_memory_value
        else """
        SELECT
            UPPER(operation_type) AS operation_type,
            virtual_address,
            physical_address,
            data_length,
            NULL AS memory_value
        FROM memory_operations
        WHERE instruction_id = ?
        ORDER BY id ASC
        """
    )
    rows = conn.execute(root_mem_sql, (seq_id,)).fetchall()
    return [
        {
            "operation_type": row["operation_type"],
            "virtual_address": row["virtual_address"],
            "physical_address": row["physical_address"],
            "bytes": int(row["data_length"]),
            "value": row["memory_value"],
        }
        for row in rows
    ]


def _format_pc_for_row(row: dict[str, Any]) -> str:
    return str(row.get("virtual_pc"))


def _build_reg_tree_text(rows: list[dict[str, Any]], root_instruction: Any, root_seq: int) -> str:
    children: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        children.setdefault(int(row["parent_seq"]), []).append(row)

    for dep_rows in children.values():
        dep_rows.sort(key=lambda item: int(item["seq_id"]))

    root_label = (
        f"[{root_seq}] core={root_instruction['core_id']} "
        f"{root_instruction['virtual_pc']} {root_instruction['disassembly']}"
    )
    lines = [root_label]

    def walk(seq_id: int, prefix: str, path: set[int]) -> None:
        dep_rows = children.get(seq_id, [])
        for index, row in enumerate(dep_rows):
            is_last = index == len(dep_rows) - 1
            connector = "└── " if is_last else "├── "
            extension = "    " if is_last else "│   "
            child_seq = int(row["seq_id"])
            pc_text = _format_pc_for_row(row)
            if row.get("edge_kind") == "mem":
                label = (
                    f"[{child_seq}] core={row['core_id']} {pc_text} {row['disassembly']} "
                    f"(mem/{row['address_mode']}: {row['dep_type']}, addr={row['address']}, len={row['bytes']})"
                )
            else:
                label = (
                    f"[{child_seq}] core={row['core_id']} {pc_text} {row['disassembly']} "
                    f"(reg: {row['via_register']})"
                )
            memory_summary = row.get("memory_summary")
            if memory_summary:
                label += f" | mem: {memory_summary}"
            if row.get("is_cycle"):
                label += " [cycle]"
            lines.append(prefix + connector + label)

            if child_seq in path:
                continue
            walk(child_seq, prefix + extension, path | {child_seq})

    walk(root_seq, "", {root_seq})
    return "\n".join(lines)


def _build_mem_tree_text(rows: list[dict[str, Any]], root_instruction: Any, root_seq: int) -> str:
    children: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        children.setdefault(int(row["parent_seq"]), []).append(row)

    for dep_rows in children.values():
        dep_rows.sort(key=lambda item: int(item["seq_id"]))

    root_label = (
        f"[{root_seq}] core={root_instruction['core_id']} "
        f"{root_instruction['virtual_pc']} {root_instruction['disassembly']}"
    )
    root_mem = root_instruction.get("root_memory_operations", [])
    if root_mem:
        mem_parts: list[str] = []
        for op in root_mem:
            value_text = f", value={op['value']}" if op.get("value") else ""
            mem_parts.append(
                (
                    f"{op['operation_type']} va={op['virtual_address']} "
                    f"pa={op['physical_address']} len={op['bytes']}{value_text}"
                )
            )
        root_label += " | root-mem: " + "; ".join(mem_parts)

    lines = [root_label]

    def walk(seq_id: int, prefix: str, path: set[int]) -> None:
        dep_rows = children.get(seq_id, [])
        for index, row in enumerate(dep_rows):
            is_last = index == len(dep_rows) - 1
            connector = "└── " if is_last else "├── "
            extension = "    " if is_last else "│   "
            child_seq = int(row["seq_id"])
            pc_text = _format_pc_for_row(row)
            label = (
                f"[{child_seq}] core={row['core_id']} {pc_text} {row['disassembly']} "
                f"(mem/{row['address_mode']}: {row['dep_type']}, addr={row['address']}, len={row['bytes']})"
            )
            if row.get("read_value"):
                label += f", read={row['read_value']}"
            if row.get("write_value"):
                label += f", write={row['write_value']}"
            memory_summary = row.get("memory_summary")
            if memory_summary:
                label += f" | mem: {memory_summary}"
            if row.get("is_cycle"):
                label += " [cycle]"
            lines.append(prefix + connector + label)

            if child_seq in path:
                continue
            walk(child_seq, prefix + extension, path | {child_seq})

    walk(root_seq, "", {root_seq})
    return "\n".join(lines)


def _query_reg_chain(
    conn: Any,
    seq_id: int,
    root_core_id: int,
    max_depth: int,
    limit: int,
    reg_query_logic: str,
    has_memory_value: bool,
    allow_reg_mem_cross_core: bool,
) -> list[dict[str, Any]]:
    mem_sql = _build_mem_sql(has_memory_value)
    rows: list[dict[str, Any]] = []
    queue: deque[tuple[int, int, set[int], str]] = deque()
    queue.append((seq_id, 0, {seq_id}, "reg"))

    while queue and len(rows) < limit:
        current_seq, depth, path, expand_mode = queue.popleft()
        if depth >= max_depth:
            continue

        if expand_mode == "mem":
            deps = conn.execute(mem_sql, (current_seq,)).fetchall()
            for dep in deps:
                child_seq = int(dep["writer_seq"])
                writer_core_id = int(dep["writer_core_id"])
                if not allow_reg_mem_cross_core and writer_core_id != root_core_id:
                    continue
                is_cycle = child_seq in path
                memory_operations = _get_memory_operations(conn, child_seq)
                rows.append(
                    {
                        "depth": depth + 1,
                        "parent_seq": current_seq,
                        "seq_id": child_seq,
                        "edge_kind": "mem",
                        "via_register": None,
                        "dep_type": "RAW",
                        "address": dep["address"],
                        "bytes": dep["data_length"],
                        "read_value": dep["read_value"],
                        "write_value": dep["write_value"],
                        "address_mode": dep["address_mode"],
                        "core_id": writer_core_id,
                        "virtual_pc": dep["writer_virtual_pc"],
                        "physical_pc": dep["writer_physical_pc"],
                        "disassembly": dep["disassembly"],
                        "memory_operations": memory_operations,
                        "memory_summary": _format_memory_summary(memory_operations),
                        "is_cycle": is_cycle,
                    }
                )
                if len(rows) >= limit:
                    break
                if not is_cycle:
                    queue.append((child_seq, depth + 1, path | {child_seq}, "mem"))
            continue

        deps = conn.execute(
            SQL_FIND_PREV_WRITERS_SAME_CORE,
            (current_seq, current_seq, root_core_id),
        ).fetchall()
        for dep in deps:
            child_seq = int(dep["sequence_id"])
            is_cycle = child_seq in path
            memory_operations = _get_memory_operations(conn, child_seq)
            child_has_memory_ops = bool(memory_operations)
            next_mode = (
                "mem"
                if reg_query_logic == "load_to_mem" and child_has_memory_ops
                else "reg"
            )
            rows.append(
                {
                    "depth": depth + 1,
                    "parent_seq": current_seq,
                    "seq_id": child_seq,
                    "edge_kind": "reg",
                    "via_register": dep["register_name"],
                    "dep_type": None,
                    "address": None,
                    "bytes": None,
                    "read_value": None,
                    "write_value": None,
                    "address_mode": "virtual",
                    "core_id": int(dep["core_id"]),
                    "virtual_pc": dep["virtual_pc"],
                    "physical_pc": dep["physical_pc"],
                    "disassembly": dep["disassembly"],
                    "memory_operations": memory_operations,
                    "memory_summary": _format_memory_summary(memory_operations),
                    "is_cycle": is_cycle,
                }
            )
            if len(rows) >= limit:
                break
            if not is_cycle:
                queue.append((child_seq, depth + 1, path | {child_seq}, next_mode))

    return rows


def _query_mem_chain(
    conn: Any,
    seq_id: int,
    max_depth: int,
    limit: int,
    has_memory_value: bool,
) -> list[dict[str, Any]]:
    sql = _build_mem_sql(has_memory_value)

    rows: list[dict[str, Any]] = []
    queue: deque[tuple[int, int, set[int]]] = deque()
    queue.append((seq_id, 0, {seq_id}))

    while queue and len(rows) < limit:
        current_seq, depth, path = queue.popleft()
        if depth >= max_depth:
            continue

        deps = conn.execute(sql, (current_seq,)).fetchall()
        for dep in deps:
            writer_seq = int(dep["writer_seq"])
            is_cycle = writer_seq in path
            memory_operations = _get_memory_operations(conn, writer_seq)
            rows.append(
                {
                    "depth": depth + 1,
                    "parent_seq": current_seq,
                    "seq_id": writer_seq,
                    "dep_type": "RAW",
                    "address": dep["address"],
                    "bytes": dep["data_length"],
                    "read_value": dep["read_value"],
                    "write_value": dep["write_value"],
                    "address_mode": dep["address_mode"],
                    "core_id": int(dep["writer_core_id"]),
                    "virtual_pc": dep["writer_virtual_pc"],
                    "physical_pc": dep["writer_physical_pc"],
                    "disassembly": dep["disassembly"],
                    "memory_operations": memory_operations,
                    "memory_summary": _format_memory_summary(memory_operations),
                    "is_cycle": is_cycle,
                }
            )
            if len(rows) >= limit:
                break
            if not is_cycle:
                queue.append((writer_seq, depth + 1, path | {writer_seq}))

    return rows


def _query_chain(
    db_path: str,
    seq_id: int,
    max_depth: int,
    limit: int,
    mode: str,
    reg_query_logic: str,
    reg_mem_cross_core: bool,
) -> tuple[list[dict[str, Any]], Any | None, str, bool, str, int | None, bool]:
    conn = connect_db(db_path)
    try:
        validate_schema(conn)

        root_instruction = fetch_instruction(conn, seq_id)
        if root_instruction is None:
            return [], None, "reg", False, reg_query_logic, None, reg_mem_cross_core

        root_core_id = int(root_instruction["core_id"])
        has_memory_value = has_column(conn, "memory_operations", "memory_value")
        root_memory_operations = _get_root_memory_operations(
            conn,
            seq_id,
            has_memory_value,
        )
        root_has_memory = bool(root_memory_operations)

        engine = mode
        if mode == "auto":
            engine = "mem" if root_has_memory else "reg"

        if engine == "mem":
            rows = _query_mem_chain(
                conn,
                seq_id,
                max_depth,
                limit,
                has_memory_value,
            )
            root_payload = dict(root_instruction)
            root_payload["root_memory_operations"] = root_memory_operations
            return (
                rows,
                root_payload,
                "mem",
                root_has_memory,
                reg_query_logic,
                root_core_id,
                reg_mem_cross_core,
            )

        rows = _query_reg_chain(
            conn,
            seq_id,
            root_core_id,
            max_depth,
            limit,
            reg_query_logic,
            has_memory_value,
            reg_mem_cross_core,
        )
        return (
            rows,
            dict(root_instruction),
            "reg",
            root_has_memory,
            reg_query_logic,
            root_core_id,
            reg_mem_cross_core,
        )
    finally:
        conn.close()


def main() -> int:
    args = _parse_args()
    if args.max_depth <= 0:
        sys.stderr.write("Error: --max-depth must be > 0\n")
        return EXIT_BAD_ARGS
    if args.limit <= 0:
        sys.stderr.write("Error: --limit must be > 0\n")
        return EXIT_BAD_ARGS
    if args.tree and args.json:
        sys.stderr.write("Error: --tree and --json cannot be used together\n")
        return EXIT_BAD_ARGS

    try:
        (
            rows,
            root_instruction,
            engine,
            root_has_memory,
            reg_query_logic,
            root_core_id,
            reg_mem_cross_core,
        ) = _query_chain(
            args.db_path,
            args.seq_id,
            args.max_depth,
            args.limit,
            args.mode,
            args.reg_query_logic,
            args.reg_mem_cross_core,
        )

        if args.json:
            print_json(
                {
                    "meta": {
                        "engine": engine,
                        "mode": args.mode,
                        "reg_query_logic": reg_query_logic,
                        "auto_switched": args.mode == "auto" and engine == "mem",
                        "root_has_memory": root_has_memory,
                        "root_core_id": root_core_id,
                        "addr_key": "mixed(core-aware)",
                        "reg_mem_cross_core": reg_mem_cross_core,
                    },
                    "rows": rows,
                    "count": len(rows),
                }
            )
        elif args.tree:
            if root_instruction is None:
                sys.stdout.write("No results\n")
            elif engine == "mem":
                sys.stdout.write(_build_mem_tree_text(rows, root_instruction, args.seq_id) + "\n")
            else:
                sys.stdout.write(_build_reg_tree_text(rows, root_instruction, args.seq_id) + "\n")
        else:
            if engine == "mem":
                emit_rows(
                    rows,
                    [
                        "depth",
                        "parent_seq",
                        "seq_id",
                        "dep_type",
                        "address_mode",
                        "address",
                        "bytes",
                        "read_value",
                        "write_value",
                        "core_id",
                        "virtual_pc",
                        "physical_pc",
                        "disassembly",
                        "memory_summary",
                        "is_cycle",
                    ],
                    False,
                )
            else:
                emit_rows(
                    rows,
                    [
                        "depth",
                        "parent_seq",
                        "seq_id",
                        "edge_kind",
                        "via_register",
                        "dep_type",
                        "address_mode",
                        "address",
                        "bytes",
                        "core_id",
                        "virtual_pc",
                        "physical_pc",
                        "disassembly",
                        "memory_summary",
                        "is_cycle",
                    ],
                    False,
                )
        if args.verbose:
            sys.stderr.write(f"engine={engine}, rows={len(rows)}\n")
        return EXIT_OK
    except ValueError as exc:
        sys.stderr.write(f"Schema error: {exc}\n")
        return EXIT_SCHEMA_ERROR
    except Exception as exc:
        sys.stderr.write(f"Runtime error: {exc}\n")
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
