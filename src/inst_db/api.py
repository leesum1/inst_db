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

    def add_instruction(
        self,
        pc: int,
        instruction_code: bytes,
        sequence_id: int,
    ) -> Instruction:
        """
        Add a new instruction to the database.

        Args:
            pc: Program counter address
            instruction_code: Raw instruction bytes (usually 4 bytes for ARM64)
            sequence_id: Sequential order of execution

        Returns:
            Created Instruction object
        """
        # Disassemble the instruction
        disasm_result = self.disassembler.disassemble(instruction_code, pc)
        disassembly = disasm_result.full_text if disasm_result else "unknown"

        with self.db_manager.get_session() as session:
            instruction = Instruction(
                pc=pc,
                instruction_code=instruction_code,
                disassembly=disassembly,
                sequence_id=sequence_id,
            )
            session.add(instruction)
            session.commit()
            # Object remains attached to session due to expire_on_commit=False
            return instruction

    def add_register_dependency(
        self,
        instruction_id: int,
        register_name: str,
        is_src: bool = False,
        is_dst: bool = False,
    ) -> RegisterDependency:
        """
        Add a register dependency for an instruction.

        Args:
            instruction_id: ID of the instruction
            register_name: Name of the register (e.g., "x0", "sp")
            is_src: Whether this is a source register
            is_dst: Whether this is a destination register

        Returns:
            Created RegisterDependency object

        Raises:
            ValueError: If register_id does not exist
        """
        with self.db_manager.get_session() as session:
            # Verify instruction exists
            instruction = session.query(Instruction).filter_by(id=instruction_id).first()
            if not instruction:
                raise ValueError(f"Instruction with ID {instruction_id} not found")

            reg_dep = RegisterDependency(
                instruction_id=instruction_id,
                register_name=register_name,
                is_src=is_src,
                is_dst=is_dst,
            )
            session.add(reg_dep)
            session.commit()
            return reg_dep

    def add_memory_operation(
        self,
        instruction_id: int,
        operation_type: str,
        virtual_address: int,
        physical_address: int,
        data_content: Optional[bytes] = None,
        data_length: Optional[int] = None,
    ) -> MemoryOperation:
        """
        Add a memory operation for an instruction.

        Args:
            instruction_id: ID of the instruction
            operation_type: "READ" or "WRITE"
            virtual_address: Virtual address accessed
            physical_address: Physical address accessed
            data_content: Actual data bytes (optional)
            data_length: Length of data accessed. If None, inferred from data_content

        Returns:
            Created MemoryOperation object

        Raises:
            ValueError: If instruction_id does not exist or operation_type is invalid
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

        with self.db_manager.get_session() as session:
            # Verify instruction exists
            instruction = session.query(Instruction).filter_by(id=instruction_id).first()
            if not instruction:
                raise ValueError(f"Instruction with ID {instruction_id} not found")

            mem_op = MemoryOperation(
                instruction_id=instruction_id,
                operation_type=op_type_enum,
                virtual_address=virtual_address,
                physical_address=physical_address,
                data_content=data_content,
                data_length=data_length,
            )
            session.add(mem_op)
            session.commit()
            return mem_op

    def get_instruction_by_id(self, instruction_id: int) -> Optional[Instruction]:
        """Get instruction by ID."""
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(id=instruction_id).first()
            return instruction

    def get_instruction_by_pc(self, pc: int) -> Optional[Instruction]:
        """Get instruction by program counter."""
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(pc=pc).first()
            return instruction

    def get_register_dependency_by_id(self, reg_dep_id: int) -> Optional[RegisterDependency]:
        """Get register dependency by ID."""
        with self.db_manager.get_session() as session:
            reg_dep = session.query(RegisterDependency).filter_by(id=reg_dep_id).first()
            return reg_dep

    def get_memory_operation_by_id(self, mem_op_id: int) -> Optional[MemoryOperation]:
        """Get memory operation by ID."""
        with self.db_manager.get_session() as session:
            mem_op = session.query(MemoryOperation).filter_by(id=mem_op_id).first()
            return mem_op

    def get_all_instructions(self, order_by_sequence: bool = True) -> List[Instruction]:
        """
        Get all instructions.

        Args:
            order_by_sequence: If True, order by sequence_id; otherwise by PC

        Returns:
            List of all Instruction objects
        """
        with self.db_manager.get_session() as session:
            query = session.query(Instruction)
            if order_by_sequence:
                query = query.order_by(Instruction.sequence_id)
            else:
                query = query.order_by(Instruction.pc)
            instructions = query.all()
            return instructions

    def get_instruction_trace(self) -> List[Instruction]:
        """
        Get the complete execution trace of all instructions in order.

        Returns:
            List of Instruction objects ordered by sequence_id
        """
        return self.get_all_instructions(order_by_sequence=True)

    def get_register_dependencies(
        self, instruction_id: int
    ) -> List[RegisterDependency]:
        """Get all register dependencies for an instruction."""
        with self.db_manager.get_session() as session:
            deps = (
                session.query(RegisterDependency)
                .filter_by(instruction_id=instruction_id)
                .all()
            )
            return deps

    def get_memory_operations(self, instruction_id: int) -> List[MemoryOperation]:
        """Get all memory operations for an instruction."""
        with self.db_manager.get_session() as session:
            ops = (
                session.query(MemoryOperation)
                .filter_by(instruction_id=instruction_id)
                .all()
            )
            return ops

    def delete_instruction(self, instruction_id: int) -> bool:
        """
        Delete an instruction and all its associated data.

        Args:
            instruction_id: ID of the instruction to delete

        Returns:
            True if deletion was successful, False if instruction not found
        """
        with self.db_manager.get_session() as session:
            instruction = session.query(Instruction).filter_by(id=instruction_id).first()
            if not instruction:
                return False
            session.delete(instruction)
            session.commit()
            return True

    def clear_all(self) -> None:
        """Clear all data from the database (USE WITH CAUTION)."""
        self.db_manager.drop_db()
        self.db_manager.init_db()
