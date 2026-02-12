# QEMU execlog 指令流跟踪快速入门

## 功能简介

从 QEMU `execlog` 插件输出解析指令流，并导入数据库：
- ✅ 解析 PC 与指令机器码
- ✅ 自动反汇编（Capstone）
- ✅ 自动提取寄存器依赖（读/写）
- ✅ 解析并入库内存访问（类型/地址/长度/值）
- ✅ 支持 ARM64 与 RISC-V

## 快速使用

### 1) 生成 QEMU execlog 日志

```bash
# ARM64
qemu_log/build/master/qemu-aarch64 \
  -d plugin \
  -D trace.log \
  -plugin qemu_log/build/master/libexeclog.so \
  ./your_arm64_program

# RISC-V
qemu_log/build/master/qemu-riscv64 \
  -d plugin \
  -D trace.log \
  -plugin qemu_log/build/master/libexeclog.so \
  ./your_riscv64_program
```

或直接使用统一脚本：

```bash
uv run python scripts/runners/run_qemu_trace.py qsort
uv run python scripts/runners/run_qemu_trace.py sve
uv run python scripts/runners/run_qemu_trace.py riscv_min
```

### 2) 导入数据库

```python
from inst_db.parsers import TraceImporter

count = TraceImporter('trace.log', 'trace.db', architecture='arm64').import_trace()
print(f"Imported {count} instructions")
```

### 3) 查询与分析

```python
from inst_db.api import InstructionDB

db = InstructionDB('sqlite:///trace.db', architecture='arm64')

for instr in db.get_instruction_trace()[:20]:
    print(f"[{instr.sequence_id}] {instr.pc}: {instr.disassembly}")

mem_ops = db.get_memory_operations(1)
for mem in mem_ops:
    print(mem.operation_type, mem.virtual_address, mem.data_length, mem.memory_value)
```

## execlog 日志格式

解析器支持如下行格式（可含多次内存操作）：

```text
0, 0x400590, 0xf94003e1, "ldr x1, [sp]", m=L8, v=0x0000000000000001, va=0x7f...
0, 0x4008e0, 0xa9b77bfd, "stp ...", m=S16, v=0x..., va=0x7f..., m=S8, v=0x..., va=0x7f...
```

字段说明：
- `m=L<size>` / `m=S<size>`：读/写与访问字节数
- `v=0x...`：访问值（入库为 `memory_value`）
- `va=0x...`：虚拟地址
- `pa=0x...`（可选）：物理地址；缺失时使用 `va`

## API 参考

### `QEMUTraceParser`

```python
from inst_db.parsers import QEMUTraceParser

parser = QEMUTraceParser('trace.log', architecture='arm64')

for pc, instruction_bytes in parser.parse():
    print(hex(pc), instruction_bytes.hex())

for pc, insn, reg_state, memory_ops in parser.parse_with_details():
    print(hex(pc), memory_ops)
```

### `TraceImporter`

```python
from inst_db.parsers import TraceImporter

importer = TraceImporter('trace.log', 'trace.db', architecture='riscv64')
count = importer.import_trace(max_instructions=10000)
```

## 注意事项

1. 必须使用 `-d plugin` + `-plugin .../libexeclog.so`
2. ARM64 指令固定 4 字节；RISC-V 自动识别 2/4 字节指令
3. 如果日志来自旧格式（仅 `load/store, addr`），不会产生 `memory_value`

## 故障排查

### 导入后 `memory_operations` 为空
- 确认日志行中包含 `m=...` 与 `v=...`（新格式）
- 确认使用的是 `qemu_log/build/master/libexeclog.so`

### 导入失败（URL 格式）
- 数据库路径请用 `sqlite:///path/to/file.db`
