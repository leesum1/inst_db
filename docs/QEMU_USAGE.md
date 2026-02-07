# QEMU 指令流跟踪快速入门

## 功能简介

从 QEMU `-d in_asm` 输出解析指令流，并导入到数据库：
- ✅ 自动提取 PC 地址和指令字节码
- ✅ 自动反汇编（使用 Capstone）
- ✅ 自动提取寄存器依赖（读/写）
- ✅ 支持浮点寄存器（CS_OP_FP）

## 快速使用

### 1. 生成 QEMU 跟踪文件

```bash
# 运行 ARM64 程序并生成跟踪
qemu-aarch64-static -d in_asm -D trace.log ./your_program

# 或使用提供的脚本
./scripts/generate_qemu_trace.sh ./your_program trace.log
```

### 2. 导入到数据库

```python
from inst_db.parsers import TraceImporter

# 导入跟踪文件
importer = TraceImporter('trace.log', 'mydb.db')
count = importer.import_trace()

print(f"Imported {count} instructions")
```

### 3. 查询和分析

```python
from inst_db.api import InstructionDB

db = InstructionDB('sqlite:///mydb.db')

# 获取指令序列
for instr in db.get_instruction_trace(limit=20):
    print(f"[{instr.sequence_id}] {instr.pc:#x}: {instr.disassembly}")
    
    # 查看寄存器依赖
    deps = db.get_register_dependencies(instr.id)
    reads = [d.register_name for d in deps if d.is_src]
    writes = [d.register_name for d in deps if d.is_dst]
    
    if reads:
        print(f"  Reads: {', '.join(reads)}")
    if writes:
        print(f"  Writes: {', '.join(writes)}")
```

## 完整流程示例

```bash
# 1. 生成测试程序
cat > /tmp/test.s << 'EOF'
.global _start
.text
_start:
    mov x0, #5
    mov x1, #10
    add x2, x0, x1
    mov x0, #0
    mov x8, #93
    svc #0
EOF

aarch64-linux-gnu-gcc -static -nostdlib /tmp/test.s -o /tmp/test_program

# 2. 生成 QEMU 跟踪
qemu-aarch64-static -d in_asm -D /tmp/trace.log /tmp/test_program

# 3. 导入数据库
python -c "from inst_db.parsers import TraceImporter; TraceImporter('/tmp/trace.log', 'trace.db').import_trace()"
```

## QEMU 输出格式

解析器处理的格式：

```
----------------
IN: 
0x004000d4:  
OBJD-T: a00080d2410180d20200018bff4300d1
OBJD-T: e20300f9e30340f9000080d2a80b80d2
OBJD-T: 010000d4
```

- `0x004000d4:` - 起始 PC 地址
- `OBJD-T: ...` - 指令字节码（小端序，ARM64 原生格式）
- 每8个十六进制字符 = 1条指令（4字节）

## API 参考

### QEMUTraceParser

```python
from inst_db.parsers import QEMUTraceParser

parser = QEMUTraceParser('trace.log')

# 解析所有指令
for pc, instruction_bytes in parser.parse():
    print(f"PC={pc:#x}, bytes={instruction_bytes.hex()}")
```

### TraceImporter

```python
from inst_db.parsers import TraceImporter

importer = TraceImporter('trace.log', 'database.db')

# 导入所有指令
count = importer.import_trace()

# 限制导入数量
count = importer.import_trace(max_instructions=1000)
```

## 注意事项

1. **字节序**：QEMU 输出已经是正确的小端序（ARM64 原生格式），解析器直接使用，无需转换

2. **PC 地址推算**：解析器从 TB 起始地址开始，每条指令 PC += 4

3. **寄存器依赖**：自动通过 Capstone 的 operand.access 标志提取

4. **性能**：大文件建议使用 `max_instructions` 参数分批导入

## 故障排查

### 反汇编失败

如果指令显示为 "unknown"，检查：
- Capstone 版本（需要 >= 5.0）
- 指令字节码是否完整（4字节）

### 导入错误

如果提示 "Could not parse SQLAlchemy URL"：
- 确保数据库路径正确
- 使用 `sqlite:///path/to/db.db` 格式

### QEMU 跟踪为空

检查：
- 程序是否正常执行
- 使用 `-d in_asm` 而不是 `-d exec`
- 程序是否是 ARM64 架构

## 扩展功能

未来可能添加的功能：
- [ ] 内存操作跟踪（从寄存器值推断）
- [ ] 分支跟踪统计
- [ ] 热点分析
- [ ] 导出为其他格式（JSON, CSV）
