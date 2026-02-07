"""Data models for instruction tracing."""

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    String,
    Integer,
    Boolean,
    LargeBinary,
    DateTime,
    ForeignKey,
    Enum,
)
from sqlalchemy.orm import declarative_base, relationship, Mapped, mapped_column
import enum

# Create declarative base class
Base = declarative_base()


class Instruction(Base):
    """Represents a single ARM64 instruction with metadata."""

    __tablename__ = "instructions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sequence_id: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    pc: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    instruction_code: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)  # Raw bytes
    disassembly: Mapped[str] = mapped_column(String, nullable=False)  # Disassembled text (e.g., "mov x0, x1")
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

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
            f"<Instruction(id={self.id}, sequence_id={self.sequence_id}, "
            f"pc=0x{self.pc:x}, disassembly='{self.disassembly}')>"
        )


class RegisterDependency(Base):
    """Represents a register dependency for an instruction."""

    __tablename__ = "register_dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instruction_id: Mapped[int] = mapped_column(Integer, ForeignKey("instructions.id"), nullable=False, index=True)
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
            f"<RegisterDependency(id={self.id}, register='{self.register_name}', "
            f"flags={flags})>"
        )


class MemoryOperationType(enum.Enum):
    """Enum for memory operation types."""

    READ = "READ"
    WRITE = "WRITE"


class MemoryOperation(Base):
    """Represents a memory operation (read or write) performed by an instruction."""

    __tablename__ = "memory_operations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    instruction_id: Mapped[int] = mapped_column(Integer, ForeignKey("instructions.id"), nullable=False, index=True)
    operation_type: Mapped[MemoryOperationType] = mapped_column(
        Enum(MemoryOperationType), nullable=False
    )  # READ or WRITE
    virtual_address: Mapped[int] = mapped_column(Integer, nullable=False, index=True)  # VA
    physical_address: Mapped[int] = mapped_column(Integer, nullable=False, index=True)  # PA
    data_content: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)  # Actual data bytes
    data_length: Mapped[int] = mapped_column(Integer, nullable=False)  # Length in bytes
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    # Relationship
    instruction: Mapped["Instruction"] = relationship(
        "Instruction",
        back_populates="memory_operations",
    )

    def __repr__(self) -> str:
        return (
            f"<MemoryOperation(id={self.id}, type={self.operation_type.value}, "
            f"va=0x{self.virtual_address:x}, pa=0x{self.physical_address:x}, "
            f"len={self.data_length})>"
        )
