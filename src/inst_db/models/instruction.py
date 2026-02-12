"""Data models for instruction tracing."""

from typing import List, Optional

from sqlalchemy import (
    String,
    Integer,
    Boolean,
    LargeBinary,
    ForeignKey,
)
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column

# Create declarative base class
Base = declarative_base()


class Instruction(Base):
    """Represents a single ARM64 instruction with metadata."""

    __tablename__ = "instructions"

    sequence_id: Mapped[int] = mapped_column(Integer, primary_key=True, nullable=False)
    core_id: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    virtual_pc: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    physical_pc: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    instruction_code: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # Raw bytes
    disassembly: Mapped[str] = mapped_column(String, nullable=False)  # Disassembled text (e.g., "mov x0, x1")

    # Relationships
    register_dependencies: Mapped[List["RegisterDependency"]] = relationship(
        "RegisterDependency",
        back_populates="instruction",
        cascade="all, delete-orphan",
    )

    memory_operations: Mapped[List["MemoryOperation"]] = relationship(
        "MemoryOperation",
        back_populates="instruction",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return (
            f"<Instruction(sequence_id={self.sequence_id}, "
            f"virtual_pc={self.virtual_pc}, physical_pc={self.physical_pc}, "
            f"disassembly='{self.disassembly}')>"
        )

    @property
    def pc(self) -> str:
        """Backward-compatible alias for virtual PC."""
        return self.virtual_pc

    @pc.setter
    def pc(self, value: str) -> None:
        self.virtual_pc = value


class RegisterDependency(Base):
    """Represents a register dependency for an instruction."""

    __tablename__ = "register_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instruction_id: Mapped[int] = mapped_column(Integer, ForeignKey("instructions.sequence_id"), nullable=False, index=True)
    register_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Capstone register ID
    register_name: Mapped[str] = mapped_column(String(16), nullable=False)  # e.g., "x0", "sp", "pc"
    is_src: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # Is source register
    is_dst: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)  # Is destination register

    # Relationship
    instruction: Mapped["Instruction"] = relationship(
        "Instruction",
        back_populates="register_dependencies",
    )

    def __repr__(self) -> str:
        flags = ""
        if self.is_src:
            flags += "SRC"
        if self.is_dst:
            if flags:
                flags += "|DST"
            else:
                flags = "DST"
        return (
            f"<RegisterDependency(id={self.id}, instruction_id={self.instruction_id}, register='{self.register_name}', "
            f"flags={flags})>"
        )


class MemoryOperation(Base):
    """Represents a memory operation for an instruction."""

    __tablename__ = "memory_operations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instruction_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("instructions.sequence_id"),
        nullable=False,
        index=True,
    )
    operation_type: Mapped[str] = mapped_column(String(16), nullable=False)
    virtual_address: Mapped[str] = mapped_column(String(32), nullable=False)
    physical_address: Mapped[str] = mapped_column(String(32), nullable=False)
    data_length: Mapped[int] = mapped_column(Integer, nullable=False)
    memory_value: Mapped[Optional[str]] = mapped_column(String(66), nullable=True)

    instruction: Mapped["Instruction"] = relationship(
        "Instruction",
        back_populates="memory_operations",
    )

    def __repr__(self) -> str:
        return (
            "<MemoryOperation(id={id}, instruction_id={instruction_id}, "
            "type={op_type}, vaddr={vaddr}, paddr={paddr}, len={length}, value={value})>"
        ).format(
            id=self.id,
            instruction_id=self.instruction_id,
            op_type=self.operation_type,
            vaddr=self.virtual_address,
            paddr=self.physical_address,
            length=self.data_length,
            value=self.memory_value,
        )
