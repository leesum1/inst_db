#!/usr/bin/env python3
"""
QEMU 指令流导入 - 快速入门

这个脚本演示如何：
1. 生成 QEMU 指令跟踪
2. 导入到数据库
3. 查询和分析结果
"""

import subprocess
import sys
from pathlib import Path

# 添加 src 到 path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from inst_db.parsers import TraceImporter
from inst_db.api import InstructionDB


def generate_test_program():
    """创建简单的测试程序"""
    asm_code = """
.global _start
.text

_start:
    // Simple arithmetic
    mov x0, #5          // x0 = 5
    mov x1, #10         // x1 = 10
    add x2, x0, x1      // x2 = x0 + x1 = 15
    
    // Memory operations
    sub sp, sp, #16     // Allocate stack space
    str x2, [sp]        // Store x2 to stack
    ldr x3, [sp]        // Load from stack to x3
    add sp, sp, #16     // Restore stack
    
    // Loop example
    mov x4, #0          // counter = 0
loop:
    add x4, x4, #1      // counter++
    cmp x4, #3          // compare with 3
    b.lt loop           // if counter < 3, loop
    
    // Exit
    mov x0, #0
    mov x8, #93
    svc #0
"""
    
    print("Creating test program...")
    with open("test_program.s", "w") as f:
        f.write(asm_code)
    
    # Compile
    print("Compiling...")
    result = subprocess.run(
        ["aarch64-linux-gnu-gcc", "-static", "-nostdlib", "test_program.s", "-o", "test_program"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Compilation failed: {result.stderr}")
        return False
    
    print("✓ Test program created: test_program")
    return True


def generate_qemu_trace():
    """生成 QEMU 指令跟踪"""
    print("\nGenerating QEMU trace...")
    result = subprocess.run(
        ["qemu-aarch64-static", "-d", "in_asm", "-D", "trace.log", "./test_program"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"QEMU execution failed: {result.stderr}")
        return False
    
    # Check trace file
    trace_file = Path("trace.log")
    if not trace_file.exists():
        print("Trace file not generated")
        return False
    
    print(f"✓ Trace file generated: trace.log ({trace_file.stat().st_size} bytes)")
    return True


def import_trace():
    """导入跟踪到数据库"""
    print("\nImporting trace to database...")
    
    importer = TraceImporter("trace.log", "demo.db")
    count = importer.import_trace(max_instructions=50)  # Limit for demo
    
    print(f"✓ Imported {count} instructions")
    return count > 0


def analyze_results():
    """分析导入的结果"""
    print("\n" + "="*70)
    print("ANALYSIS RESULTS")
    print("="*70)
    
    db = InstructionDB("sqlite:///demo.db")
    
    # Get all instructions
    instructions = db.get_instruction_trace(limit=20)
    
    print(f"\nFirst 20 instructions:\n")
    
    for instr in instructions:
        print(f"[{instr.sequence_id:3d}] {instr.pc:#018x}: {instr.disassembly:30s}", end="")
        
        # Get register dependencies
        deps = db.get_register_dependencies(instr.id)
        reads = [d.register_name for d in deps if d.is_src]
        writes = [d.register_name for d in deps if d.is_dst]
        
        if reads or writes:
            dep_str = []
            if reads:
                dep_str.append(f"R:{','.join(reads)}")
            if writes:
                dep_str.append(f"W:{','.join(writes)}")
            print(f" | {' '.join(dep_str)}")
        else:
            print()
    
    # Statistics
    all_instrs = db.get_instruction_trace()
    unique_pcs = len(set(i.pc for i in all_instrs))
    
    print(f"\n{'='*70}")
    print("STATISTICS")
    print("="*70)
    print(f"Total instructions executed: {len(all_instrs)}")
    print(f"Unique PC addresses:         {unique_pcs}")
    print(f"Average executions per PC:   {len(all_instrs) / unique_pcs:.2f}")
    
    # Find most executed  PC
    from collections import Counter
    pc_counts = Counter(i.pc for i in all_instrs)
    most_common = pc_counts.most_common(5)
    
    print(f"\nMost executed instructions:")
    for pc, count in most_common:
        # Find instruction
        instr = db.get_instruction_by_pc(pc)
        if instr:
            print(f"  {pc:#018x}: {instr.disassembly:30s} (executed {count}x)")


def main():
    """主函数"""
    print("="*70)
    print("QEMU Instruction Trace Import - Quick Start Demo")
    print("="*70)
    
    # Step 1: Check prerequisites
    print("\nChecking prerequisites...")
    
    # Check for aarch64-linux-gnu-gcc
    result = subprocess.run(["which", "aarch64-linux-gnu-gcc"], capture_output=True)
    if result.returncode != 0:
        print("✗ aarch64-linux-gnu-gcc not found")
        print("  Install: sudo apt-get install gcc-aarch64-linux-gnu")
        return 1
    print("✓ aarch64-linux-gnu-gcc found")
    
    # Check for qemu-aarch64-static
    result = subprocess.run(["which", "qemu-aarch64-static"], capture_output=True)
    if result.returncode != 0:
        print("✗ qemu-aarch64-static not found")
        print("  Install: sudo apt-get install qemu-user-static")
        return 1
    print("✓ qemu-aarch64-static found")
    
    # Step 2: Generate test program
    if not generate_test_program():
        return 1
    
    # Step 3: Generate QEMU trace
    if not generate_qemu_trace():
        return 1
    
    # Step 4: Import trace
    if not import_trace():
        return 1
    
    # Step 5: Analyze results
    analyze_results()
    
    print(f"\n{'='*70}")
    print("✓ Demo completed successfully!")
    print("="*70)
    print("\nDatabase saved as: demo.db")
    print("You can explore it with:")
    print("  sqlite3 demo.db")
    print("  SELECT * FROM instruction LIMIT 10;")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
