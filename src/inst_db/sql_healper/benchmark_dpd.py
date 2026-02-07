"""
性能测试：比较递归 SQL 和 Python 循环两种依赖查询方式
"""
import sqlite3
import time
from typing import List, Tuple

DB_PATH = "tmp/quicksort_trace.db"
DEPTH = 30  # 依赖深度

# ============= 方法1: Python 循环查询 =============
SQL_PYTHON = """
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


def query_deps_python_loop(conn: sqlite3.Connection, root_seq: int, max_depth: int) -> List[Tuple]:
    """Python 循环方式查询依赖"""
    all_deps = []
    visited = set()
    frontier = [root_seq]
    
    for depth in range(1, max_depth + 1):
        next_frontier = []
        for seq_id in frontier:
            if seq_id in visited:
                continue
            visited.add(seq_id)
            
            # 查询当前节点的依赖
            rows = conn.execute(SQL_PYTHON, (seq_id,)).fetchall()
            for child_seq, pc, disasm, reg_name in rows:
                all_deps.append((seq_id, child_seq, pc, disasm, reg_name, depth))
                next_frontier.append(child_seq)
        
        if not next_frontier:
            break
        frontier = next_frontier
    
    return all_deps


# ============= 方法2: 递归 SQL =============
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


def query_deps_recursive_sql(conn: sqlite3.Connection, root_seq: int, max_depth: int) -> List[Tuple]:
    """递归 SQL 方式查询依赖"""
    rows = conn.execute(SQL_RECURSIVE, (root_seq, max_depth)).fetchall()
    return rows


# ============= 性能测试 =============
def benchmark_single(conn: sqlite3.Connection, seq_id: int, depth: int):
    """对单个指令进行性能测试"""
    # 测试 Python 循环
    start = time.perf_counter()
    deps_python = query_deps_python_loop(conn, seq_id, depth)
    time_python = time.perf_counter() - start
    
    # 测试递归 SQL
    start = time.perf_counter()
    deps_sql = query_deps_recursive_sql(conn, seq_id, depth)
    time_sql = time.perf_counter() - start
    
    return {
        'seq_id': seq_id,
        'deps_python': len(deps_python),
        'time_python': time_python,
        'deps_sql': len(deps_sql),
        'time_sql': time_sql,
        'speedup': time_python / time_sql if time_sql > 0 else 0
    }


def benchmark_batch(conn: sqlite3.Connection, seq_ids: List[int], depth: int):
    """批量测试多个指令"""
    print(f"\n{'='*80}")
    print(f"批量测试: {len(seq_ids)} 条指令, 深度={depth}")
    print(f"{'='*80}\n")
    
    results = []
    total_time_python = 0
    total_time_sql = 0
    
    for i, seq_id in enumerate(seq_ids):
        result = benchmark_single(conn, seq_id, depth)
        results.append(result)
        total_time_python += result['time_python']
        total_time_sql += result['time_sql']
        
        if (i + 1) % 10 == 0 or i == len(seq_ids) - 1:
            print(f"进度: {i+1}/{len(seq_ids)} - "
                  f"seq_id={seq_id}, "
                  f"deps={result['deps_sql']}, "
                  f"Python={result['time_python']*1000:.2f}ms, "
                  f"SQL={result['time_sql']*1000:.2f}ms, "
                  f"加速比={result['speedup']:.2f}x")
    
    print(f"\n{'='*80}")
    print(f"总结:")
    print(f"  总时间 (Python循环): {total_time_python:.3f}s")
    print(f"  总时间 (递归SQL):    {total_time_sql:.3f}s")
    print(f"  平均加速比:         {total_time_python/total_time_sql:.2f}x")
    print(f"  总节省时间:         {(total_time_python-total_time_sql):.3f}s")
    print(f"{'='*80}\n")
    
    return results


def get_sample_instructions(conn: sqlite3.Connection, sample_size: int = 100) -> List[int]:
    """获取采样指令列表"""
    query = """
    SELECT sequence_id 
    FROM instructions 
    WHERE sequence_id % (SELECT COUNT(*) / ? FROM instructions) = 0
    ORDER BY sequence_id
    LIMIT ?
    """
    rows = conn.execute(query, (sample_size, sample_size)).fetchall()
    return [row[0] for row in rows]


def get_all_instructions(conn: sqlite3.Connection) -> List[int]:
    """获取所有指令的 sequence_id"""
    query = "SELECT sequence_id FROM instructions ORDER BY sequence_id"
    rows = conn.execute(query).fetchall()
    return [row[0] for row in rows]


def main():
    with sqlite3.connect(DB_PATH) as conn:
        # 获取数据库统计信息
        total_count = conn.execute("SELECT COUNT(*) FROM instructions").fetchone()[0]
        print(f"数据库中总指令数: {total_count}")
        
        # 测试1: 单个指令详细测试
        print("\n" + "="*80)
        print("测试1: 单个指令性能对比")
        print("="*80)
        test_seq = 4455
        result = benchmark_single(conn, test_seq, DEPTH)
        print(f"\nseq_id={result['seq_id']}")
        print(f"  依赖数量 (Python): {result['deps_python']}")
        print(f"  依赖数量 (SQL):    {result['deps_sql']}")
        print(f"  时间 (Python):     {result['time_python']*1000:.2f}ms")
        print(f"  时间 (SQL):        {result['time_sql']*1000:.2f}ms")
        print(f"  加速比:           {result['speedup']:.2f}x")
        
        # 测试2: 采样测试（100条指令）
        print("\n选择测试模式:")
        print("  1. 采样测试 (100条指令)")
        print("  2. 全量测试 (所有指令)")
        print("  3. 跳过批量测试")
        
        choice = input("\n请选择 (1/2/3, 默认1): ").strip() or "1"
        
        if choice == "1":
            seq_ids = get_sample_instructions(conn, 100)
            benchmark_batch(conn, seq_ids, DEPTH)
        elif choice == "2":
            print("\n警告: 全量测试可能需要很长时间!")
            confirm = input("确认继续? (y/N): ").strip().lower()
            if confirm == 'y':
                seq_ids = get_all_instructions(conn)
                benchmark_batch(conn, seq_ids, DEPTH)
        else:
            print("\n跳过批量测试")


if __name__ == "__main__":
    main()
