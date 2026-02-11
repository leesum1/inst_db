"""High-level API for instruction database operations."""

from typing import List, Optional
from sqlalchemy.orm import Session

from inst_db.database.connection import init_database
from inst_db.disassembler import ARM64Disassembler, RISCVDisassembler
from inst_db.models.instruction import (
    Instruction,
    RegisterDependency,
    MemoryOperation,
)


class InstructionDB:
    """High-level API for managing instruction tracing data."""

    def __init__(self, database_url: str, architecture: str = "arm64"):
        """
        Initialize the instruction database.

        Args:
            database_url: SQLAlchemy database URL (e.g., "sqlite:///trace.db")
            architecture: Instruction set architecture ("arm64" or "riscv64")
        """
        self.db_path: Optional[str] = None
        use_in_memory = self._should_use_in_memory(database_url)
        if not use_in_memory:
            self.db_path = self._extract_sqlite_path(database_url)

        self.db_manager = init_database(database_url, use_in_memory=use_in_memory)
        self.disassembler = self._create_disassembler(architecture)

    @staticmethod
    def _create_disassembler(architecture: str):
        normalized_arch = architecture.strip().lower()
        if normalized_arch == "arm64":
            return ARM64Disassembler()
        if normalized_arch == "riscv64":
            return RISCVDisassembler()
        raise ValueError(
            f"Unsupported architecture: {architecture}. Supported: arm64, riscv64"
        )

    @staticmethod
    def _should_use_in_memory(database_url: str) -> bool:
        normalized = database_url.strip().lower()
        return normalized in {
            "sqlite:///:memory:",
            "sqlite+pysqlite:///:memory:",
        }

    @staticmethod
    def _to_hex_text(value: int | str) -> str:
        if isinstance(value, str):
            value = value.strip().lower()
            if value.startswith("0x"):
                return value
            return f"0x{int(value, 16):016x}"
        return f"0x{value:016x}"

    @staticmethod
    def _extract_sqlite_path(database_url: str) -> Optional[str]:
        if database_url.startswith("sqlite:////"):
            return database_url.replace("sqlite:////", "/", 1)
        if database_url.startswith("sqlite:///"):
            return database_url.replace("sqlite:///", "", 1)
        return None

    def add_instruction(
        self,
        pc: int,
        instruction_code: bytes,
        sequence_id: int,
        register_state: Optional[dict] = None,
        memory_operations: Optional[List[dict]] = None,
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

            if memory_operations:
                for mem_op in memory_operations:
                    operation_type = mem_op.get("operation_type")
                    virtual_address = mem_op.get("virtual_address")
                    physical_address = mem_op.get("physical_address")
                    data_length = mem_op.get("data_length")

                    if (
                        operation_type is None
                        or virtual_address is None
                        or physical_address is None
                    ):
                        raise ValueError(
                            "Memory operation requires type, virtual address, and physical address"
                        )

                    if data_length is None:
                        raise ValueError("Memory operation requires data_length")

                    memory_op = MemoryOperation(
                        instruction=instruction,
                        operation_type=str(operation_type),
                        virtual_address=self._to_hex_text(virtual_address),
                        physical_address=self._to_hex_text(physical_address),
                        data_length=int(data_length),
                    )
                    active_session.add(memory_op)

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
            instruction = (
                active_session.query(Instruction)
                .filter_by(sequence_id=sequence_id)
                .first()
            )
            if not instruction:
                raise ValueError(
                    f"Instruction with sequence_id {sequence_id} not found"
                )

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
        data_length: int,
        session: Optional[Session] = None,
    ):
        """Add a memory operation for an instruction."""

        def add_with_session(active_session: Session) -> MemoryOperation:
            instruction = (
                active_session.query(Instruction)
                .filter_by(sequence_id=sequence_id)
                .first()
            )
            if not instruction:
                raise ValueError(
                    f"Instruction with sequence_id {sequence_id} not found"
                )

            mem_op = MemoryOperation(
                instruction=instruction,
                operation_type=str(operation_type),
                virtual_address=self._to_hex_text(virtual_address),
                physical_address=self._to_hex_text(physical_address),
                data_length=int(data_length),
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
            instruction = (
                session.query(Instruction).filter_by(sequence_id=sequence_id).first()
            )
            return instruction

    def get_instruction_by_pc(self, pc: int | str) -> Optional[Instruction]:
        """Get instruction by program counter."""
        pc_text = self._to_hex_text(pc)
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(pc=pc_text).first()
            return instruction

    def get_register_dependency_by_instruction(
        self, sequence_id: int
    ) -> List[RegisterDependency]:
        """Get all register dependencies for an instruction by sequence_id."""
        with self.db_manager.get_session() as session:
            deps = (
                session.query(RegisterDependency)
                .filter_by(instruction_id=sequence_id)
                .all()
            )
            return deps

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
                joinedload(Instruction.register_dependencies),
                joinedload(Instruction.memory_operations),
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

    def get_register_dependencies(self, sequence_id: int) -> List[RegisterDependency]:
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

    def save_to_file(self, file_path: Optional[str] = None) -> None:
        """Persist the in-memory database to a SQLite file."""
        if file_path is None:
            file_path = self.db_path
        if not file_path:
            raise ValueError("file_path is required")
        self.db_manager.save_to_file(file_path)

    def delete_instruction(self, sequence_id: int) -> bool:
        """
        Delete an instruction and all its associated data.

        Args:
            sequence_id: Sequence ID of the instruction to delete

        Returns:
            True if deletion was successful, False if instruction not found
        """
        with self.db_manager.get_session() as session:
            instruction = (
                session.query(Instruction).filter_by(sequence_id=sequence_id).first()
            )
            if not instruction:
                return False
            session.delete(instruction)
            session.commit()
            return True

    def clear_all(self) -> None:
        """Clear all data from the database (USE WITH CAUTION)."""
        self.db_manager.drop_db()
        self.db_manager.init_db()
