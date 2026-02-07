"""High-level API for instruction database operations."""

from typing import List, Optional
from sqlalchemy.orm import Session

from inst_db.database.connection import DatabaseManager, init_database
from inst_db.disassembler.arm64 import ARM64Disassembler
from inst_db.models.instruction import (
    Instruction,
    RegisterDependency,
    MemoryOperation,
    MemoryOperationType,
)


class InstructionDB:
    """High-level API for managing instruction tracing data."""

    def __init__(self, database_url: str):
        """
        Initialize the instruction database.

        Args:
            database_url: SQLAlchemy database URL (e.g., "sqlite:///trace.db")
        """
        self.db_manager = init_database(database_url)
        self.disassembler = ARM64Disassembler()

    @staticmethod
    def _to_hex_text(value: int | str) -> str:
        if isinstance(value, str):
            value = value.strip().lower()
            if value.startswith("0x"):
                return value
            return f"0x{int(value, 16):016x}"
        return f"0x{value:016x}"

    def add_instruction(
        self,
        pc: int,
        instruction_code: bytes,
        sequence_id: int,
        register_state: Optional[dict] = None,
        session: Optional[Session] = None,
        flush: bool = True,
    ) -> Instruction:
        """
        Add a new instruction to the database with automatic register dependency extraction.

        Uses Capstone's semantic analysis to automatically extract all register reads
        and writes (including implicit ones).

        Args:
            pc: Program counter address
            instruction_code: Raw instruction bytes (usually 4 bytes for ARM64)
            sequence_id: Sequential order of execution

        Returns:
            Created Instruction object with register dependencies
        """
        # Disassemble and extract register semantics
        disasm_result = self.disassembler.disassemble(instruction_code, pc)
        disassembly = disasm_result.full_text if disasm_result else "unknown"
        regs_read = disasm_result.regs_read if disasm_result else set()
        regs_write = disasm_result.regs_write if disasm_result else set()
        mem_accesses = disasm_result.mem_accesses if disasm_result else []

        def compute_effective_address(mem_access) -> int:
            if not register_state or not mem_access.base_reg:
                return 0
            base_val = register_state.get(mem_access.base_reg)
            if base_val is None:
                return 0
            index_val = 0
            if mem_access.index_reg:
                index_val = register_state.get(mem_access.index_reg, 0)
            return base_val + (index_val * mem_access.index_scale) + mem_access.displacement

        def add_with_session(active_session: Session) -> Instruction:
            instruction = Instruction(
                pc=self._to_hex_text(pc),
                instruction_code=instruction_code,
                disassembly=disassembly,
                sequence_id=sequence_id,
            )
            active_session.add(instruction)

            # 自动添加所有寄存器依赖（避免额外查询）
            read_only = regs_read - regs_write
            write_only = regs_write - regs_read
            read_write = regs_read & regs_write

            for reg_name in sorted(read_only):
                reg_dep = RegisterDependency(
                    instruction=instruction,
                    register_name=reg_name,
                    is_src=True,
                    is_dst=False,
                )
                active_session.add(reg_dep)

            for reg_name in sorted(write_only):
                reg_dep = RegisterDependency(
                    instruction=instruction,
                    register_name=reg_name,
                    is_src=False,
                    is_dst=True,
                )
                active_session.add(reg_dep)

            for reg_name in sorted(read_write):
                reg_dep = RegisterDependency(
                    instruction=instruction,
                    register_name=reg_name,
                    is_src=True,
                    is_dst=True,
                )
                active_session.add(reg_dep)

            # 自动添加内存操作（仅根据指令语义，地址未知）
            for mem_access in mem_accesses:
                effective_address = compute_effective_address(mem_access)
                mem_op = MemoryOperation(
                    instruction=instruction,
                    operation_type=MemoryOperationType[mem_access.operation],
                    virtual_address=self._to_hex_text(effective_address),
                    physical_address=self._to_hex_text(effective_address),
                    base_reg=mem_access.base_reg,
                    index_reg=mem_access.index_reg,
                    displacement=mem_access.displacement,
                    index_scale=mem_access.index_scale,
                    data_content=None,
                    data_length=mem_access.size or 0,
                )
                active_session.add(mem_op)

            if flush:
                active_session.flush()

            return instruction

        if session is not None:
            return add_with_session(session)

        with self.db_manager.get_session() as scoped_session:
            return add_with_session(scoped_session)

    def add_register_dependency(
        self,
        sequence_id: int,
        register_name: str,
        register_id: Optional[int] = None,
        is_src: bool = False,
        is_dst: bool = False,
        session: Optional[Session] = None,
    ) -> RegisterDependency:
        """
        Add a register dependency for an instruction.

        Args:
            sequence_id: Sequence ID of the instruction
            register_name: Name of the register (e.g., "x0", "sp")
            is_src: Whether this is a source register
            is_dst: Whether this is a destination register

        Returns:
            Created RegisterDependency object

        Raises:
            ValueError: If sequence_id does not exist
        """
        def add_with_session(active_session: Session) -> RegisterDependency:
            instruction = active_session.query(Instruction).filter_by(sequence_id=sequence_id).first()
            if not instruction:
                raise ValueError(f"Instruction with sequence_id {sequence_id} not found")

            reg_dep = RegisterDependency(
                instruction_id=sequence_id,
                register_id=register_id,
                register_name=register_name,
                is_src=is_src,
                is_dst=is_dst,
            )
            active_session.add(reg_dep)
            return reg_dep

        if session is not None:
            return add_with_session(session)

        with self.db_manager.get_session() as scoped_session:
            return add_with_session(scoped_session)

    def add_memory_operation(
        self,
        sequence_id: int,
        operation_type: str,
        virtual_address: int | str,
        physical_address: int | str,
        base_reg: Optional[str] = None,
        index_reg: Optional[str] = None,
        displacement: int = 0,
        index_scale: int = 1,
        data_content: Optional[bytes] = None,
        data_length: Optional[int] = None,
        session: Optional[Session] = None,
    ) -> MemoryOperation:
        """
        Add a memory operation for an instruction.

        Args:
            sequence_id: Sequence ID of the instruction
            operation_type: "READ" or "WRITE"
            virtual_address: Virtual address accessed
            physical_address: Physical address accessed
            data_content: Actual data bytes (optional)
            data_length: Length of data accessed. If None, inferred from data_content

        Returns:
            Created MemoryOperation object

        Raises:
            ValueError: If sequence_id does not exist or operation_type is invalid
        """
        # Validate operation type
        try:
            op_type_enum = MemoryOperationType[operation_type.upper()]
        except KeyError:
            raise ValueError(
                f"Invalid operation_type: {operation_type}. Must be 'READ' or 'WRITE'."
            )

        # Infer data_length if not provided
        if data_length is None:
            if data_content is not None:
                data_length = len(data_content)
            else:
                data_length = 0

        def add_with_session(active_session: Session) -> MemoryOperation:
            instruction = active_session.query(Instruction).filter_by(sequence_id=sequence_id).first()
            if not instruction:
                raise ValueError(f"Instruction with sequence_id {sequence_id} not found")

            mem_op = MemoryOperation(
                instruction_id=sequence_id,
                operation_type=op_type_enum,
                virtual_address=self._to_hex_text(virtual_address),
                physical_address=self._to_hex_text(physical_address),
                base_reg=base_reg,
                index_reg=index_reg,
                displacement=displacement,
                index_scale=index_scale,
                data_content=data_content,
                data_length=data_length,
            )
            active_session.add(mem_op)
            return mem_op

        if session is not None:
            return add_with_session(session)

        with self.db_manager.get_session() as scoped_session:
            return add_with_session(scoped_session)

    def get_instruction_by_sequence_id(self, sequence_id: int) -> Optional[Instruction]:
        """Get instruction by sequence ID."""
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(sequence_id=sequence_id).first()
            return instruction

    def get_instruction_by_pc(self, pc: int | str) -> Optional[Instruction]:
        """Get instruction by program counter."""
        pc_text = self._to_hex_text(pc)
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(pc=pc_text).first()
            return instruction

    def get_register_dependency_by_instruction(self, sequence_id: int) -> List[RegisterDependency]:
        """Get all register dependencies for an instruction by sequence_id."""
        with self.db_manager.get_session() as session:
            deps = (
                session.query(RegisterDependency)
                .filter_by(instruction_id=sequence_id)
                .all()
            )
            return deps

    def get_memory_operation_by_instruction(self, sequence_id: int) -> List[MemoryOperation]:
        """Get all memory operations for an instruction by sequence_id."""
        with self.db_manager.get_session() as session:
            ops = (
                session.query(MemoryOperation)
                .filter_by(instruction_id=sequence_id)
                .all()
            )
            return ops

    def get_all_instructions(self, order_by_sequence: bool = True) -> List[Instruction]:
        """
        Get all instructions.

        Args:
            order_by_sequence: If True, order by sequence_id; otherwise by PC

        Returns:
            List of all Instruction objects
        """
        from sqlalchemy.orm import joinedload
        
        with self.db_manager.get_session() as session:
            query = session.query(Instruction).options(
                joinedload(Instruction.memory_operations),
                joinedload(Instruction.register_dependencies)
            )
            if order_by_sequence:
                query = query.order_by(Instruction.sequence_id)
            else:
                query = query.order_by(Instruction.pc)
            instructions = query.all()
            # Detach from session by converting to dict
            return instructions

    def get_instruction_trace(self) -> List[Instruction]:
        """
        Get the complete execution trace of all instructions in order.

        Returns:
            List of Instruction objects ordered by sequence_id
        """
        return self.get_all_instructions(order_by_sequence=True)

    def get_register_dependencies(
        self, sequence_id: int
    ) -> List[RegisterDependency]:
        """Get all register dependencies for an instruction."""
        with self.db_manager.get_session() as session:
            deps = (
                session.query(RegisterDependency)
                .filter_by(instruction_id=sequence_id)
                .all()
            )
            return deps

    def get_memory_operations(self, sequence_id: int) -> List[MemoryOperation]:
        """Get all memory operations for an instruction."""
        with self.db_manager.get_session() as session:
            ops = (
                session.query(MemoryOperation)
                .filter_by(instruction_id=sequence_id)
                .all()
            )
            return ops

    def delete_instruction(self, sequence_id: int) -> bool:
        """
        Delete an instruction and all its associated data.

        Args:
            sequence_id: Sequence ID of the instruction to delete

        Returns:
            True if deletion was successful, False if instruction not found
        """
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(sequence_id=sequence_id).first()
            if not instruction:
                return False
            session.delete(instruction)
            session.commit()
            return True

    def clear_all(self) -> None:
        """Clear all data from the database (USE WITH CAUTION)."""
        self.db_manager.drop_db()
        self.db_manager.init_db()
