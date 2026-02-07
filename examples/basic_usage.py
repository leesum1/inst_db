#!/usr/bin/env python3
"""Basic usage example of the instruction database with automatic register extraction."""

import os
import sys

# Add src to path to import inst_db
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from inst_db.api import InstructionDB

def main():
    """Demonstrate instruction database with automatic semantic analysis."""
    # Create or open database
    db_url = "sqlite:///example_trace.db"
    db = InstructionDB(db_url)
    
    print("=== ARM64 Instruction Trace Database with Semantic Analysis ===\n")
    
    # Example 1: Add instructions - Capstone automatically extracts register semantics
    print("1. Adding instructions (Capstone automatically extracts register dependencies)...")
    
    # add x0, x0, x0 - reads and writes x0
    instr1 = db.add_instruction(
        pc=0x1000,
        instruction_code=bytes.fromhex("0000008b"),  # add x0, x0, x0
        sequence_id=1
    )
    print(f"   Added: {instr1}")
    
    # ldr x0, [x1] - writes x0, reads x1 (and possibly sp for base address)
    instr2 = db.add_instruction(
        pc=0x1004,
        instruction_code=bytes.fromhex("00048fa8"),  # ldp x0, x1, [sp]
        sequence_id=2
    )
    print(f"   Added: {instr2}")
    
    # Example 2: Display automatically extracted register dependencies
    print("\n2. Automatically extracted register dependencies:")
    all_instructions = db.get_all_instructions(order_by_sequence=True)
    
    for instr in all_instructions:
        print(f"\n   Instruction: {instr}")
        print(f"     PC: 0x{instr.pc:x}")
        print(f"     Code: {instr.instruction_code.hex()}")
        print(f"     Disassembly: {instr.disassembly}")
        
        # Show automatically extracted register dependencies
        reg_deps = db.get_register_dependencies(instr.id)
        if reg_deps:
            print(f"     Registers ({len(reg_deps)}):")
            for dep in reg_deps:
                flags = []
                if dep.is_src:
                    flags.append("READ")
                if dep.is_dst:
                    flags.append("WRITE")
                print(f"       - {dep.register_name} [{', '.join(flags)}]")
        else:
            print(f"     Registers: (none)")
    
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
    
    # Example 4: Get complete trace
    print("\n4. Complete execution trace:")
    trace = db.get_instruction_trace()
    for seq_id, instr in enumerate(trace, 1):
        print(f"   {seq_id}. [0x{instr.pc:x}] {instr.disassembly}")
    
    print("\n✓ Example completed successfully!")
    print(f"Database saved to: example_trace.db")
    print(f"\n📌 Note: All register dependencies were automatically extracted by Capstone,")
    print(f"   including both explicit operands and implicit register operations.")

if __name__ == "__main__":
    main()

