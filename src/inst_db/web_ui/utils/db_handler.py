"""Database handler for web UI."""
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
from inst_db.api import InstructionDB


class DBSession:
    """Manages a database session for the web UI."""

    def __init__(self, db_path: str):
        """Initialize database session.
        
        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        # Convert file path to SQLAlchemy URL format
        db_url = f"sqlite:///{db_path}"
        self.inst_db = InstructionDB(db_url)
        self._conn = None

    def get_connection(self) -> sqlite3.Connection:
        """Get or create SQLite connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def get_instructions(
        self,
        page: int = 1,
        page_size: int = 50,
        search: Optional[str] = None,
        register_filter: Optional[str] = None,
        order_by: str = "sequence_id",
        order_dir: str = "asc",
    ) -> Tuple[List[Dict], int]:
        """Get paginated instructions with optional filters.
        
        Args:
            page: Page number (1-indexed).
            page_size: Number of items per page.
            search: Search term for PC or disassembly.
            register_filter: Register name to filter by.
            order_by: Column to order by.
            order_dir: Order direction ('asc' or 'desc').
            
        Returns:
            Tuple of (instructions list, total count).
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Build query
        where_clauses = []
        params = []

        if search:
            where_clauses.append("(i.pc LIKE ? OR i.disassembly LIKE ?)")
            search_term = f"%{search}%"
            params.extend([search_term, search_term])

        if register_filter:
            where_clauses.append(
                """EXISTS (
                    SELECT 1 FROM register_dependencies rd 
                    WHERE rd.instruction_id = i.sequence_id 
                    AND rd.register_name = ?
                )"""
            )
            params.append(register_filter)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        # Get total count
        count_query = f"""
            SELECT COUNT(*) as total
            FROM instructions i
            {where_sql}
        """
        cursor.execute(count_query, params)
        total = cursor.fetchone()["total"]

        # Get paginated results
        offset = (page - 1) * page_size
        order_sql = f"ORDER BY i.{order_by} {order_dir.upper()}"

        query = f"""
            SELECT 
                i.sequence_id,
                i.pc,
                i.disassembly,
                i.instruction_code
            FROM instructions i
            {where_sql}
            {order_sql}
            LIMIT ? OFFSET ?
        """
        params.extend([page_size, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        instructions = []
        for row in rows:
            inst = dict(row)
            # Convert bytes to hex string for JSON serialization
            if inst.get('instruction_code') and isinstance(inst['instruction_code'], bytes):
                inst['instruction_code'] = inst['instruction_code'].hex()
            instructions.append(inst)

        return instructions, total

    def get_instruction_detail(self, sequence_id: int) -> Optional[Dict]:
        """Get detailed information about a specific instruction.
        
        Args:
            sequence_id: The instruction sequence ID.
            
        Returns:
            Dictionary with instruction details or None.
        """
        inst = self.inst_db.get_instruction_by_sequence_id(sequence_id)
        if not inst:
            return None

        # Get register dependencies
        reg_deps = self.inst_db.get_register_dependencies(sequence_id)
        
        # Get memory operations
        mem_ops = self.inst_db.get_memory_operations(sequence_id)

        return {
            "instruction": {
                "sequence_id": inst.sequence_id,
                "pc": inst.pc,
                "disassembly": inst.disassembly,
                "instruction_code": inst.instruction_code.hex() if inst.instruction_code else None,
            },
            "register_dependencies": [
                {
                    "register_name": rd.register_name,
                    "is_src": rd.is_src,
                    "is_dst": rd.is_dst,
                }
                for rd in reg_deps
            ],
            "memory_operations": [
                {
                    "operation_type": mo.operation_type,
                    "virtual_address": mo.virtual_address,
                    "physical_address": mo.physical_address,
                    "data_length": mo.data_length,
                }
                for mo in mem_ops
            ],
        }

    def get_all_registers(self) -> List[str]:
        """Get list of all unique register names in the database.
        
        Returns:
            Sorted list of register names.
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = """
            SELECT DISTINCT register_name 
            FROM register_dependencies 
            ORDER BY register_name
        """
        cursor.execute(query)
        
        return [row["register_name"] for row in cursor.fetchall()]

    def get_statistics(self) -> Dict:
        """Get database statistics.
        
        Returns:
            Dictionary with statistics.
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        stats = {}

        # Total instructions
        cursor.execute("SELECT COUNT(*) as count FROM instructions")
        stats["total_instructions"] = cursor.fetchone()["count"]

        # Total register dependencies
        cursor.execute("SELECT COUNT(*) as count FROM register_dependencies")
        stats["total_register_deps"] = cursor.fetchone()["count"]

        # Total memory operations
        cursor.execute("SELECT COUNT(*) as count FROM memory_operations")
        stats["total_memory_ops"] = cursor.fetchone()["count"]

        # Unique registers
        cursor.execute("SELECT COUNT(DISTINCT register_name) as count FROM register_dependencies")
        stats["unique_registers"] = cursor.fetchone()["count"]

        return stats

    def export_instructions(self, format: str = "json", filters: Optional[Dict] = None) -> str:
        """Export instructions to JSON or CSV format.
        
        Args:
            format: Export format ('json' or 'csv').
            filters: Optional filters (search, register_filter).
            
        Returns:
            Exported data as string.
        """
        filters = filters or {}
        # Get all matching instructions (no pagination)
        instructions, _ = self.get_instructions(
            page=1,
            page_size=999999,
            search=filters.get("search"),
            register_filter=filters.get("register_filter"),
        )

        if format == "json":
            return json.dumps(instructions, indent=2)
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            if instructions:
                fieldnames = instructions[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(instructions)
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format}")

    def close(self):
        """Close database connections."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
