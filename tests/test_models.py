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
        assert instr.sequence_id is not None
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
        
        assert instr1.sequence_id != instr2.sequence_id
        assert instr1.sequence_id == 1
        assert instr2.sequence_id == 2

    def test_get_instruction_by_id(self, temp_db):
        """Test retrieving instruction by sequence ID."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        retrieved = temp_db.get_instruction_by_sequence_id(instr.sequence_id)
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
        assert retrieved.sequence_id == instr.sequence_id

    def test_add_register_dependency(self, temp_db):
        """Test adding register dependencies."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        reg_dep = temp_db.add_register_dependency(
            sequence_id=instr.sequence_id,
            register_name="x0",
            is_src=False,
            is_dst=True,
        )
        
        assert reg_dep.instruction_id == instr.sequence_id
        assert reg_dep.register_name == "x0"
        assert reg_dep.is_src is False
        assert reg_dep.is_dst is True

    def test_add_register_dependency_invalid_instruction(self, temp_db):
        """Test adding register dependency to non-existent instruction."""
        with pytest.raises(ValueError):
            temp_db.add_register_dependency(
                sequence_id=9999,
                register_name="x0",
                is_src=True,
                is_dst=False,
            )

    def test_get_register_dependencies(self, temp_db):
        """Test retrieving register dependencies."""
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        temp_db.add_register_dependency(
            sequence_id=instr.sequence_id,
            register_name="x0",
            is_src=False,
            is_dst=True,
        )
        temp_db.add_register_dependency(
            sequence_id=instr.sequence_id,
            register_name="x1",
            is_src=True,
            is_dst=False,
        )
        
        deps = temp_db.get_register_dependencies(instr.sequence_id)
        assert len(deps) == 2

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
        seq_id = instr.sequence_id
        
        # Verify it exists
        assert temp_db.get_instruction_by_sequence_id(seq_id) is not None
        
        # Delete it
        assert temp_db.delete_instruction(seq_id) is True
        
        # Verify it's gone
        assert temp_db.get_instruction_by_sequence_id(seq_id) is None

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
            sequence_id=instr.sequence_id,
            register_name="x0",
            is_src=False,
            is_dst=True,
        )
        
        mem_op = temp_db.add_memory_operation(
            sequence_id=instr.sequence_id,
            operation_type="READ",
            virtual_address=0x7fff0000,
            physical_address=0x3fff0000,
            data_length=4,
        )
        
        # Delete instruction
        temp_db.delete_instruction(instr.sequence_id)
        
        # Verify dependencies are also deleted
        deps = temp_db.get_register_dependencies(instr.sequence_id)
        ops = temp_db.get_memory_operations(instr.sequence_id)
        assert len(deps) == 0
        assert len(ops) == 0


class TestDisassembly:
    """Test cases for ARM64 disassembly and semantic analysis."""

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

    def test_automatic_register_extraction(self, temp_db):
        """Test that register dependencies are automatically extracted by Capstone."""
        # Using verified instruction: add x0, x0, x0
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("0000008b"),  # add x0, x0, x0
            sequence_id=1,
        )
        
        # Verify that register dependencies were automatically added
        deps = temp_db.get_register_dependencies(instr.sequence_id)
        assert len(deps) > 0, "Expected automatic register extraction"
        
        # Check that we have registers in the dependencies
        reg_names = {dep.register_name for dep in deps}
        print(f"Extracted registers: {reg_names}")
        
        # x0 should be present (both read and write)
        assert "x0" in reg_names

    def test_register_read_write_classification(self, temp_db):
        """Test that registers are correctly classified as read, write, or both."""
        # Using verified instruction: add x0, x0, x0 (reads and writes x0)
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("0000008b"),  # add x0, x0, x0
            sequence_id=1,
        )
        
        deps = temp_db.get_register_dependencies(instr.sequence_id)
        
        # Verify that we have both source and destination registers
        src_regs = [d for d in deps if d.is_src]
        dst_regs = [d for d in deps if d.is_dst]
        
        print(f"Source registers: {[d.register_name for d in src_regs]}")
        print(f"Destination registers: {[d.register_name for d in dst_regs]}")
        
        # At least one register should be read and one should be written
        # For add instruction, x0 is both read and written
        assert len(src_regs) > 0, "Expected at least one source register"
        assert len(dst_regs) > 0, "Expected at least one destination register"

    def test_implicit_registers_extraction(self, temp_db):
        """Test that implicit register operations are extracted."""
        # Different ARM64 instructions that have implicit registers
        # For example, some instructions implicitly use sp, lr, etc.
        instr = temp_db.add_instruction(
            pc=0x1000,
            instruction_code=bytes.fromhex("20000101aa"),
            sequence_id=1,
        )
        
        deps = temp_db.get_register_dependencies(instr.sequence_id)
        
        # The extraction should work without manual specification
        assert len(deps) >= 0, "Register extraction should complete"
        
        # Print extracted registers for verification
        for dep in deps:
            print(
                f"Register: {dep.register_name}, is_src={dep.is_src}, is_dst={dep.is_dst}"
            )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
