# Instruction DB

该项目提供一套 ARM64 指令数据库结构，并提供统一的插入接口用于构建指令跟踪库。

## 目录结构

```
inst_db/
├── src/inst_db/         # 核心库
│   ├── api.py           # 统一插入接口
│   ├── models/          # 数据模型
│   ├── database/        # 数据库连接
│   ├── disassembler/    # 反汇编与语义提取
│   └── parsers/         # QEMU 跟踪解析
├── scripts/             # 工具脚本
│   └── runners/         # 跟踪生成/导入脚本
├── tests/               # 测试
└── pyproject.toml
```

## 数据库结构

### instructions
- `sequence_id` (INTEGER, PK) - 指令执行序列号
- `pc` (TEXT, hex string, 例如 "0x0000000000400580")
- `instruction_code` (BLOB)
- `disassembly` (TEXT)

### register_dependencies
- `id` (INTEGER, PK, AUTOINCREMENT)
- `instruction_id` (INTEGER, FK -> instructions.sequence_id, INDEX)
- `register_id` (INTEGER, nullable) - Capstone register ID
- `register_name` (TEXT)
- `is_src` (BOOLEAN)
- `is_dst` (BOOLEAN)

### memory_operations
- `id` (INTEGER, PK, AUTOINCREMENT)
- `instruction_id` (INTEGER, FK -> instructions.sequence_id, INDEX)
- `operation_type` (ENUM: READ/WRITE)
- `virtual_address` (TEXT, hex string, INDEX)
- `physical_address` (TEXT, hex string)
- `base_reg` (TEXT, nullable)
- `index_reg` (TEXT, nullable)
- `displacement` (INTEGER)
- `index_scale` (INTEGER)
- `data_content` (BLOB, nullable)
- `data_length` (INTEGER)

关系说明：
- `instructions` 1:N `register_dependencies`
- `instructions` 1:N `memory_operations`

## 统一插入接口

```python
from inst_db.api import InstructionDB

db = InstructionDB("sqlite:///trace.db")

instr = db.add_instruction(
  pc=0x400580,
  instruction_code=bytes.fromhex("a00080d2"),
  sequence_id=1,
)

db.add_register_dependency(
  sequence_id=instr.sequence_id,
  register_name="x0",
  is_src=True,
  is_dst=False,
)

db.add_memory_operation(
  sequence_id=instr.sequence_id,
  operation_type="READ",
  virtual_address=0x7fff0000,
  physical_address=0x3fff0000,
  data_length=4,
)
```

## QEMU 跟踪导入

```python
from inst_db.parsers import TraceImporter

TraceImporter("trace.log", "trace.db").import_trace()
```

### 使用跟踪脚本

统一的跟踪脚本支持多个演示程序：

```bash
# 运行 quicksort 演示的跟踪
python scripts/runners/run_qemu_trace.py qsort

# 运行 SVE 演示的跟踪
python scripts/runners/run_qemu_trace.py sve

# 跳过构建，只运行跟踪和导入
python scripts/runners/run_qemu_trace.py qsort --no-build

# 跳过导入数据库
python scripts/runners/run_qemu_trace.py qsort --no-import

# 跳过统计信息输出
python scripts/runners/run_qemu_trace.py qsort --no-stats
```

参数说明：
- `qsort|sve` - 选择要运行的演示程序
- `--no-build` - 跳过二进制文件构建
- `--no-trace` - 跳过 QEMU 跟踪执行
- `--no-import` - 跳过导入到数据库
- `--no-stats` - 跳过打印统计信息

## 备注

- 所有地址字段以 hex 字符串存储（`0x...`），不是整数类型。
- 如果需要导出文本分析，使用 [docs/EXPORT_TOOL.md](docs/EXPORT_TOOL.md) 中的工具脚本。
