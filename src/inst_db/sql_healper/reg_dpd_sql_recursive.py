import sqlite3

from anytree import Node, RenderTree
from anytree.exporter import DotExporter

DB_PATH = "tmp/quicksort_trace.db"
SEQ = 4120  # 目标指令的 sequence_id
DEPTH = 30  # 依赖深度，1=直接依赖，2=再往上一层
OUTPUT_PATH = "tmp/deps_tree_recursive.svg"

# 使用递归 CTE 一次性查询所有依赖
SQL_RECURSIVE = """
WITH RECURSIVE dep_tree AS (
  -- 基础情况：根节点
  SELECT 
    i.sequence_id,
    i.pc,
    i.disassembly,
    NULL AS via_register,
    NULL AS parent_seq,
    0 AS depth,
    ',' || i.sequence_id || ',' AS path
  FROM instructions i
  WHERE i.sequence_id = ?
  
  UNION ALL
  
  -- 递归情况：查找依赖
  SELECT
    i_writer.sequence_id,
    i_writer.pc,
    i_writer.disassembly,
    rd_src.register_name AS via_register,
    dt.sequence_id AS parent_seq,
    dt.depth + 1 AS depth,
    dt.path || i_writer.sequence_id || ',' AS path
  FROM dep_tree dt
  -- 获取当前指令读取的寄存器
  JOIN register_dependencies rd_src 
    ON rd_src.instruction_id = dt.sequence_id 
    AND rd_src.is_src = 1
  -- 找到最近写该寄存器的指令
  JOIN register_dependencies rd_dst
    ON rd_dst.register_name = rd_src.register_name
    AND rd_dst.is_dst = 1
  JOIN instructions i_writer 
    ON i_writer.sequence_id = rd_dst.instruction_id
    AND i_writer.sequence_id < dt.sequence_id
  -- 确保是最近的一次写入
  WHERE dt.depth < ?
    AND dt.path NOT LIKE '%,' || i_writer.sequence_id || ',%'  -- 避免循环
    -- 使用子查询确保是最近的写入
    AND NOT EXISTS (
      SELECT 1 
      FROM register_dependencies rd_newer
      JOIN instructions i_newer ON i_newer.sequence_id = rd_newer.instruction_id
      WHERE rd_newer.register_name = rd_src.register_name
        AND rd_newer.is_dst = 1
        AND i_newer.sequence_id > i_writer.sequence_id
        AND i_newer.sequence_id < dt.sequence_id
    )
)
SELECT 
  sequence_id,
  pc,
  disassembly,
  via_register,
  parent_seq,
  depth,
  path
FROM dep_tree
ORDER BY depth, sequence_id DESC;
"""


def build_anytree_from_sql(rows: list[tuple], root_seq: int) -> Node:
    """从 SQL 查询结果构建 anytree
    
    使用 path 作为唯一标识，因为同一指令可能在不同路径上出现
    """
    # 使用 path 作为唯一标识
    nodes: dict[str, Node] = {}
    root = None
    
    for seq_id, pc, disasm, via_reg, parent_seq, depth, path in rows:
        # 格式化节点标签
        if depth == 0:
            label = f"[{seq_id}] {pc} {disasm}"
        else:
            label = f"[{seq_id}] {pc} {disasm} (reg: {via_reg})"
        
        # 创建节点
        if parent_seq is None:
            # 根节点
            node = Node(label)
            nodes[path] = node
            root = node
        else:
            # 找到父节点：父节点的 path 是当前 path 去掉最后一个 seq_id
            # path 格式: ',4455,4452,4451,'
            # 去掉最后的 seq_id: ',4455,4452,'
            parent_path = path.rsplit(f'{seq_id},', 1)[0]
            
            parent_node = nodes.get(parent_path)
            if parent_node:
                node = Node(label, parent=parent_node)
                nodes[path] = node
    
    return root


with sqlite3.connect(DB_PATH) as conn:
    rows = conn.execute(SQL_RECURSIVE, (SEQ, DEPTH)).fetchall()
    
    if not rows:
        print(f"No results found for sequence_id {SEQ}")
    else:
        print(f"Found {len(rows)} dependencies\n")
        
        root = build_anytree_from_sql(rows, SEQ)
        
        # 打印树
        for pre, _fill, node in RenderTree(root):
            print(f"{pre}{node.name}")
        
        # 导出为 SVG
        DotExporter(root).to_picture(OUTPUT_PATH)
        print(f"\nSaved: {OUTPUT_PATH}")
