"""Tests for the instruction database."""

import pytest
import os
import tempfile
from pathlib import Path

import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from inst_db.api import InstructionDB
from inst_db.models.instruction import (
    Instruction,
    RegisterDependency,
    MemoryOperation,
    MemoryOperationType,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.db")
        db_url = f"sqlite:///{db_path}"
        db = InstructionDB(db_url)
        yield db


class TestInstructionDB:
    """Test cases for InstructionDB API."""

    def test_add_instruction(self, temp_db):
        """Test adding a single instruction."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        assert instr.id is not None
        assert instr.pc == 0x1000
        assert instr.sequence_id == 1
        assert instr.instruction_code == bytes.fromhex("20000101aa")

    def test_add_multiple_instructions(self, temp_db):
        """Test adding multiple instructions."""
        instr1 = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        instr2 = temp_db.add_instruction(
            pc=0x1004,
            instruction_code=bytes.fromhex("f9400020"),
            sequence_id=2,
        )
        
        assert instr1.id != instr2.id
        assert instr1.sequence_id == 1
        assert instr2.sequence_id == 2

    def test_get_instruction_by_id(self, temp_db):
        """Test retrieving instruction by ID."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        retrieved = temp_db.get_instruction_by_id(instr.id)
        assert retrieved is not None
        assert retrieved.pc == instr.pc

    def test_get_instruction_by_pc(self, temp_db):
        """Test retrieving instruction by PC."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        retrieved = temp_db.get_instruction_by_pc(0x1000)
        assert retrieved is not None
        assert retrieved.id == instr.id

    def test_add_register_dependency(self, temp_db):
        """Test adding register dependencies."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        reg_dep = temp_db.add_register_dependency(
            instruction_id=instr.id,
            register_name="x0",
            is_src=False,
            is_dst=True,
        )
        
        assert reg_dep.id is not None
        assert reg_dep.instruction_id == instr.id
        assert reg_dep.register_name == "x0"
        assert reg_dep.is_src is False
        assert reg_dep.is_dst is True

    def test_add_register_dependency_invalid_instruction(self, temp_db):
        """Test adding register dependency to non-existent instruction."""
        with pytest.raises(ValueError):
            temp_db.add_register_dependency(
                instruction_id=9999,
                register_name="x0",
                is_src=True,
                is_dst=False,
            )

    def test_add_memory_operation(self, temp_db):
        """Test adding memory operations."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        mem_op = temp_db.add_memory_operation(
            instruction_id=instr.id,
            operation_type="READ",
            virtual_address=0x7fff0000,
            physical_address=0x3fff0000,
            data_content=b'\x01\x02\x03\x04',
            data_length=4,
        )
        
        assert mem_op.id is not None
        assert mem_op.instruction_id == instr.id
        assert mem_op.operation_type == MemoryOperationType.READ
        assert mem_op.virtual_address == 0x7fff0000
        assert mem_op.physical_address == 0x3fff0000
        assert mem_op.data_length == 4

    def test_add_memory_operation_infer_length(self, temp_db):
        """Test memory operation with inferred data length."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        data = b'\x01\x02\x03\x04'
        mem_op = temp_db.add_memory_operation(
            instruction_id=instr.id,
            operation_type="WRITE",
            virtual_address=0x7fff0000,
            physical_address=0x3fff0000,
            data_content=data,
        )
        
        assert mem_op.data_length == len(data)

    def test_add_memory_operation_invalid_type(self, temp_db):
        """Test memory operation with invalid operation type."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        with pytest.raises(ValueError):
            temp_db.add_memory_operation(
                instruction_id=instr.id,
                operation_type="INVALID",
                virtual_address=0x7fff0000,
                physical_address=0x3fff0000,
                data_length=4,
            )

    def test_get_register_dependencies(self, temp_db):
        """Test retrieving register dependencies."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        temp_db.add_register_dependency(
            instruction_id=instr.id,
            register_name="x0",
            is_src=False,
            is_dst=True,
        )
        temp_db.add_register_dependency(
            instruction_id=instr.id,
            register_name="x1",
            is_src=True,
            is_dst=False,
        )
        
        deps = temp_db.get_register_dependencies(instr.id)
        assert len(deps) == 2

    def test_get_memory_operations(self, temp_db):
        """Test retrieving memory operations."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        temp_db.add_memory_operation(
            instruction_id=instr.id,
            operation_type="READ",
            virtual_address=0x7fff0000,
            physical_address=0x3fff0000,
            data_length=4,
        )
        temp_db.add_memory_operation(
            instruction_id=instr.id,
            operation_type="WRITE",
            virtual_address=0x7fff0004,
            physical_address=0x3fff0004,
            data_length=8,
        )
        
        ops = temp_db.get_memory_operations(instr.id)
        assert len(ops) == 2

    def test_get_instruction_trace(self, temp_db):
        """Test getting complete execution trace."""
        for i in range(5):
            temp_db.add_instruction(
                pc=0x1000 + i * 4,
                instruction_code=bytes.fromhex("20000101aa"),
                sequence_id=i + 1,
            )
        
        trace = temp_db.get_instruction_trace()
        assert len(trace) == 5
        # Verify correct sequence
        for i, instr in enumerate(trace):
            assert instr.sequence_id == i + 1

    def test_delete_instruction(self, temp_db):
        """Test deleting an instruction."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        instr_id = instr.id
        
        # Verify it exists
        assert temp_db.get_instruction_by_id(instr_id) is not None
        
        # Delete it
        assert temp_db.delete_instruction(instr_id) is True
        
        # Verify it's gone
        assert temp_db.get_instruction_by_id(instr_id) is None

    def test_delete_nonexistent_instruction(self, temp_db):
        """Test deleting non-existent instruction."""
        result = temp_db.delete_instruction(9999)
        assert result is False

    def test_cascade_delete(self, temp_db):
        """Test that deleting instruction cascades to dependencies and operations."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        reg_dep = temp_db.add_register_dependency(
            instruction_id=instr.id,
            register_name="x0",
            is_src=False,
            is_dst=True,
        )
        
        mem_op = temp_db.add_memory_operation(
            instruction_id=instr.id,
            operation_type="READ",
            virtual_address=0x7fff0000,
            physical_address=0x3fff0000,
            data_length=4,
        )
        
        # Delete instruction
        temp_db.delete_instruction(instr.id)
        
        # Verify dependencies are also deleted
        assert temp_db.get_register_dependency_by_id(reg_dep.id) is None
        assert temp_db.get_memory_operation_by_id(mem_op.id) is None


class TestDisassembly:
    """Test cases for ARM64 disassembly."""

    def test_disassembly_included_in_instruction(self, temp_db):
        """Test that disassembly is automatically performed."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        # Disassembly should be included
        assert instr.disassembly is not None
        assert len(instr.disassembly) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
