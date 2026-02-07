"""Dependency graph builder for instruction database."""
import sqlite3
from typing import Dict, List, Optional, Set, Tuple


# SQL query to find source register dependencies
SQL_GET_DEPS = """
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
SELECT sequence_id, printf('0x%X', pc) AS pc, disassembly, register_name
FROM ranked
WHERE rn = 1
ORDER BY sequence_id DESC;
"""

# SQL query to get instruction info
SQL_GET_INSTR = """
SELECT sequence_id, printf('0x%X', pc) AS pc, disassembly
FROM instructions
WHERE sequence_id = ?
"""


class DependencyGraph:
    """Builds and manages instruction dependency graphs."""

    def __init__(self, conn: sqlite3.Connection):
        """Initialize dependency graph builder.
        
        Args:
            conn: SQLite database connection.
        """
        self.conn = conn

    def get_deps(self, seq_id: int) -> List[Tuple]:
        """Get dependencies for a single instruction.
        
        Args:
            seq_id: Instruction sequence ID.
            
        Returns:
            List of tuples (child_seq, pc, disassembly, register_name).
        """
        cursor = self.conn.execute(SQL_GET_DEPS, (seq_id,))
        return cursor.fetchall()

    def get_instr(self, seq_id: int) -> Optional[Tuple]:
        """Get instruction information.
        
        Args:
            seq_id: Instruction sequence ID.
            
        Returns:
            Tuple of (sequence_id, pc, disassembly) or None.
        """
        cursor = self.conn.execute(SQL_GET_INSTR, (seq_id,))
        return cursor.fetchone()

    def format_instr(self, info: Optional[Tuple], seq_id: int) -> str:
        """Format instruction info as display string.
        
        Args:
            info: Instruction info tuple.
            seq_id: Sequence ID (used as fallback).
            
        Returns:
            Formatted string.
        """
        if info is None:
            return f"[{seq_id}]"
        seq, pc, disasm = info
        return f"[{seq}] {pc} {disasm}"

    def build_tree(
        self, root_seq: int, max_depth: int
    ) -> Tuple[Dict[int, List[Tuple]], Dict[int, Tuple]]:
        """Build dependency tree using BFS.
        
        Args:
            root_seq: Root instruction sequence ID.
            max_depth: Maximum depth to traverse.
            
        Returns:
            Tuple of (tree dict, node_info dict).
            tree: {seq_id: [(child_seq, pc, disasm, reg_name), ...]}
            node_info: {seq_id: (seq_id, pc, disasm)}
        """
        tree: Dict[int, List[Tuple]] = {}
        node_info: Dict[int, Tuple] = {}
        visited: Set[int] = set()
        frontier = [root_seq]

        for _level in range(1, max_depth + 1):
            next_frontier = []
            for seq_id in frontier:
                if seq_id in visited:
                    continue
                visited.add(seq_id)
                
                if seq_id not in node_info:
                    node_info[seq_id] = self.get_instr(seq_id)
                
                rows = self.get_deps(seq_id)
                tree[seq_id] = rows
                
                for child_seq, pc, disasm, reg_name in rows:
                    node_info.setdefault(child_seq, (child_seq, pc, disasm))
                    next_frontier.append(child_seq)
            
            if not next_frontier:
                break
            frontier = next_frontier

        return tree, node_info

    def build_tree_json(self, root_seq: int, max_depth: int) -> Dict:
        """Build dependency tree and convert to JSON format.
        
        Args:
            root_seq: Root instruction sequence ID.
            max_depth: Maximum depth to traverse.
            
        Returns:
            Tree in nested JSON format suitable for frontend rendering.
        """
        tree, node_info = self.build_tree(root_seq, max_depth)

        def helper(seq_id: int, depth: int, path: Set[int]) -> Dict:
            """Recursively build tree node."""
            info = node_info.get(seq_id)
            if info is None:
                node_data = {
                    "sequence_id": seq_id,
                    "label": f"[{seq_id}]",
                    "pc": None,
                    "disassembly": None,
                    "children": [],
                }
            else:
                seq, pc, disasm = info
                node_data = {
                    "sequence_id": seq,
                    "label": f"[{seq}] {pc} {disasm}",
                    "pc": pc,
                    "disassembly": disasm,
                    "children": [],
                }

            if depth >= max_depth:
                return node_data

            children = tree.get(seq_id, [])
            for child_seq, child_pc, child_disasm, child_reg in children:
                child_label = f"[{child_seq}] {child_pc} {child_disasm}"
                
                if child_seq in path:
                    # Cycle detected
                    node_data["children"].append({
                        "sequence_id": child_seq,
                        "label": f"{child_label} (reg: {child_reg}) [cycle]",
                        "pc": child_pc,
                        "disassembly": child_disasm,
                        "register": child_reg,
                        "is_cycle": True,
                        "children": [],
                    })
                else:
                    child_node = helper(child_seq, depth + 1, path | {child_seq})
                    child_node["register"] = child_reg
                    child_node["label"] = f"{child_label} (reg: {child_reg})"
                    child_node["is_cycle"] = False
                    node_data["children"].append(child_node)

            return node_data

        root_node = helper(root_seq, 0, {root_seq})
        
        return {
            "root": root_node,
            "max_depth": max_depth,
            "total_nodes": len(node_info),
        }

    def build_tree_text(self, root_seq: int, max_depth: int) -> str:
        """Build dependency tree as text representation.
        
        Args:
            root_seq: Root instruction sequence ID.
            max_depth: Maximum depth to traverse.
            
        Returns:
            Text tree representation.
        """
        tree, node_info = self.build_tree(root_seq, max_depth)
        
        def helper(seq_id: int, depth: int, path: Set[int], prefix: str = "") -> List[str]:
            """Recursively build text tree."""
            lines = []
            info = node_info.get(seq_id)
            label = self.format_instr(info, seq_id)
            
            if depth == 0:
                lines.append(label)
            
            if depth >= max_depth:
                return lines
            
            children = tree.get(seq_id, [])
            for i, (child_seq, child_pc, child_disasm, child_reg) in enumerate(children):
                is_last = i == len(children) - 1
                connector = "└── " if is_last else "├── "
                extension = "    " if is_last else "│   "
                
                child_label = f"[{child_seq}] {child_pc} {child_disasm} (reg: {child_reg})"
                
                if child_seq in path:
                    lines.append(f"{prefix}{connector}{child_label} [cycle]")
                else:
                    lines.append(f"{prefix}{connector}{child_label}")
                    child_lines = helper(
                        child_seq, depth + 1, path | {child_seq}, prefix + extension
                    )
                    lines.extend(child_lines)
            
            return lines
        
        text_tree = "\n".join(helper(root_seq, 0, {root_seq}))
        return text_tree
