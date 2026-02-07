#!/usr/bin/env python3
"""Basic usage example of the instruction database."""

import os
import sys

# Add src to path to import inst_db
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from inst_db.api import InstructionDB

def main():
    """Demonstrate basic usage of the InstructionDB API."""
    # Create or open database
    db_url = "sqlite:///example_trace.db"
    db = InstructionDB(db_url)
    
    print("=== ARM64 Instruction Trace Database Example ===\n")
    
    # Example 1: Add a simple ARM64 instruction
    # This is: mov x0, x1 (encoded as 0x20 0x00 0x01 0xaa in little-endian)
    print("1. Adding instructions...")
    instr1 = db.add_instruction(
        pc=0x1000,
        instruction_code=bytes.fromhex("20000101aa"),  # mov x0, x1
        sequence_id=1
    )
    print(f"   Added: {instr1}")
    
    # Add another instruction
    # ldr x0, [x1] (0xf9 0x40 0x00 0x20 in little-endian, but shown as bytes)
    instr2 = db.add_instruction(
        pc=0x1004,
        instruction_code=bytes.fromhex("f9400020"),  # ldr x0, [x1]
        sequence_id=2
    )
    print(f"   Added: {instr2}")
    
    # Example 2: Add register dependencies
    print("\n2. Adding register dependencies...")
    reg_dep1 = db.add_register_dependency(
        instruction_id=instr1.id,
        register_name="x1",
        is_src=True,
        is_dst=False
    )
    print(f"   Added: {reg_dep1}")
    
    reg_dep2 = db.add_register_dependency(
        instruction_id=instr1.id,
        register_name="x0",
        is_src=False,
        is_dst=True
    )
    print(f"   Added: {reg_dep2}")
    
    # Add dependencies for second instruction
    db.add_register_dependency(
        instruction_id=instr2.id,
        register_name="x1",
        is_src=True,
        is_dst=False
    )
    db.add_register_dependency(
        instruction_id=instr2.id,
        register_name="x0",
        is_src=False,
        is_dst=True
    )
    
    # Example 3: Add memory operations
    print("\n3. Adding memory operations...")
    mem_op = db.add_memory_operation(
        instruction_id=instr2.id,
        operation_type="READ",
        virtual_address=0x7fff_0000,
        physical_address=0x3fff_0000,
        data_content=b'\x01\x02\x03\x04',
        data_length=4
    )
    print(f"   Added: {mem_op}")
    
    # Example 4: Query and display data
    print("\n4. Querying data...")
    all_instructions = db.get_all_instructions(order_by_sequence=True)
    print(f"   Total instructions: {len(all_instructions)}")
    
    for instr in all_instructions:
        print(f"\n   Instruction: {instr}")
        print(f"     PC: 0x{instr.pc:x}")
        print(f"     Code: {instr.instruction_code.hex()}")
        print(f"     Disassembly: {instr.disassembly}")
        
        # Show register dependencies
        reg_deps = db.get_register_dependencies(instr.id)
        if reg_deps:
            print(f"     Registers ({len(reg_deps)}):")
            for dep in reg_deps:
                flags = []
                if dep.is_src:
                    flags.append("SRC")
                if dep.is_dst:
                    flags.append("DST")
                print(f"       - {dep.register_name} [{', '.join(flags)}]")
        
        # Show memory operations
        mem_ops = db.get_memory_operations(instr.id)
        if mem_ops:
            print(f"     Memory Operations ({len(mem_ops)}):")
            for mem_op in mem_ops:
                print(f"       - {mem_op.operation_type.value}: VA=0x{mem_op.virtual_address:x}, "
                      f"PA=0x{mem_op.physical_address:x}, len={mem_op.data_length}")
    
    # Example 5: Get complete trace
    print("\n5. Complete execution trace:")
    trace = db.get_instruction_trace()
    for seq_id, instr in enumerate(trace, 1):
        print(f"   {seq_id}. [0x{instr.pc:x}] {instr.disassembly}")
    
    print("\n✓ Example completed successfully!")
    print(f"Database saved to: example_trace.db")

if __name__ == "__main__":
    main()
