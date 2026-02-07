import sqlite3

from anytree import Node, RenderTree
from anytree.exporter import DotExporter

DB_PATH = "tmp/quicksort_trace.db"
SEQ = 4120  # 目标指令的 sequence_id
DEPTH = 30  # 依赖深度，1=直接依赖，2=再往上一层
OUTPUT_PATH = "tmp/deps_tree.svg"

SQL = """
WITH cur AS (
  SELECT sequence_id
  FROM instructions
  WHERE sequence_id = ?
),
reads AS (
  SELECT rd.register_name
  FROM register_dependencies rd
  WHERE rd.instruction_id = (SELECT sequence_id FROM cur)
    AND rd.is_src = 1
),
candidates AS (
  SELECT i.sequence_id, i.pc, i.disassembly, rd.register_name
  FROM instructions i
  JOIN register_dependencies rd
    ON rd.instruction_id = i.sequence_id
  WHERE rd.is_dst = 1
    AND rd.register_name IN (SELECT register_name FROM reads)
    AND i.sequence_id < (SELECT sequence_id FROM cur)
),
ranked AS (
  SELECT *,
         ROW_NUMBER() OVER (PARTITION BY register_name ORDER BY sequence_id DESC) AS rn
  FROM candidates
)
SELECT sequence_id, pc, disassembly, register_name
FROM ranked
WHERE rn = 1
ORDER BY sequence_id DESC;
"""

SQL_INSTR = """
SELECT sequence_id, pc, disassembly
FROM instructions
WHERE sequence_id = ?
"""

def get_deps(conn: sqlite3.Connection, seq_id: int) -> list[tuple]:
  return conn.execute(SQL, (seq_id,)).fetchall()


def get_instr(conn: sqlite3.Connection, seq_id: int) -> tuple | None:
  return conn.execute(SQL_INSTR, (seq_id,)).fetchone()


def format_instr(info: tuple | None, seq_id: int) -> str:
  if info is None:
    return f"[{seq_id}]"
  seq, pc, disasm = info
  return f"[{seq}] {pc} {disasm}"


def build_tree(conn: sqlite3.Connection, root_seq: int, max_depth: int):
  tree: dict[int, list[tuple]] = {}
  node_info: dict[int, tuple] = {}
  visited = set()
  frontier = [root_seq]

  for _level in range(1, max_depth + 1):
    next_frontier = []
    for seq_id in frontier:
      if seq_id in visited:
        continue
      visited.add(seq_id)
      if seq_id not in node_info:
        node_info[seq_id] = get_instr(conn, seq_id)
      rows = get_deps(conn, seq_id)
      tree[seq_id] = rows
      for child_seq, pc, disasm, reg_name in rows:
        node_info.setdefault(child_seq, (child_seq, pc, disasm))
        next_frontier.append(child_seq)
    if not next_frontier:
      break
    frontier = next_frontier

  return tree, node_info


def build_anytree(root_seq: int, tree: dict[int, list[tuple]], node_info: dict[int, tuple], max_depth: int) -> Node:
  def helper(seq_id: int, depth: int, node: Node, path: set[int]):
    if depth >= max_depth:
      return

    children = tree.get(seq_id, [])
    for child_seq, _pc, _disasm, child_reg in children:
      label = format_instr(node_info.get(child_seq), child_seq)
      label = f"{label} (reg: {child_reg})"
      if child_seq in path:
        Node(f"{label} [cycle]", parent=node)
        continue

      child_node = Node(label, parent=node)
      helper(child_seq, depth + 1, child_node, path | {child_seq})

  root_label = format_instr(node_info.get(root_seq), root_seq)
  root = Node(root_label)
  helper(root_seq, 0, root, {root_seq})
  return root


with sqlite3.connect(DB_PATH) as conn:
  tree, node_info = build_tree(conn, SEQ, DEPTH)
  root = build_anytree(SEQ, tree, node_info, DEPTH)
  for pre, _fill, node in RenderTree(root):
    print(f"{pre}{node.name}")

  DotExporter(root).to_picture(OUTPUT_PATH)
  print(f"Saved: {OUTPUT_PATH}")