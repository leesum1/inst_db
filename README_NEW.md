# ARM64 指令跟踪数据库系统

一个基于 Python、SQLAlchemy 和 Capstone 的 ARM64 指令执行跟踪和分析系统。

## 功能特性

- 📊 **完整的指令记录**：存储 PC、指令码、反汇编结果和执行顺序
- 📝 **寄存器依赖追踪**：自动提取每条指令的源/目的寄存器（整数+浮点）
- 🔍 **内存操作追踪**：记录虚拟地址、物理地址、读写数据和长度
- 🗄️ **轻量级数据库**：基于 SQLite，易于部署和分享
- 🔧 **易用的 Python API**：简洁的高级接口用于数据录入和查询
- 🚀 **QEMU 指令流导入**：自动解析 QEMU `-d in_asm` 输出
- 🤖 **自动语义分析**：使用 Capstone 自动提取寄存器依赖关系

## 项目结构

```
inst_db/
├── src/inst_db/
│   ├── models/          # 数据模型定义
│   ├── database/        # 数据库连接和管理
│   ├── disassembler/    # ARM64 反汇编模块
│   ├── parsers/         # 指令流解析器（QEMU 等）
│   ├── utils/           # 工具函数
│   └── api.py           # 高级 API 接口
├── tests/               # 测试用例（26个测试全部通过）
├── examples/            # 使用示例
├── scripts/             # 工具脚本
├── docs/                # 文档
└── pyproject.toml       # 项目配置
```

## 安装

使用 uv 管理项目依赖：

```bash
# 克隆项目
git clone <repository>
cd inst_db

# 安装依赖
uv sync
```

## 快速开始

### 方式1：从 QEMU 导入指令流（推荐）

```bash
# 1. 生成 QEMU 指令跟踪
qemu-aarch64-static -d in_asm -D trace.log ./your_arm64_program

# 或使用提供的脚本
./scripts/generate_qemu_trace.sh ./your_arm64_program trace.log

# 2. 导入到数据库
python examples/qemu_import_example.py
```

Python 代码：

```python
from inst_db.parsers import TraceImporter
from inst_db.api import InstructionDB

# 导入 QEMU 跟踪
importer = TraceImporter('trace.log', 'mydb.db')
count = importer.import_trace()
print(f"Imported {count} instructions")

# 查询和分析
db = InstructionDB('sqlite:///mydb.db')
for instr in db.get_instruction_trace(limit=10):
    print(f"[{instr.sequence_id}] {instr.pc:#x}: {instr.disassembly}")
    
    # 查看自动提取的寄存器依赖
    deps = db.get_register_dependencies(instr.id)
    reads = [d.register_name for d in deps if d.is_src]
    writes = [d.register_name for d in deps if d.is_dst]
    
    if reads:
        print(f"  Reads:  {', '.join(reads)}")
    if writes:
        print(f"  Writes: {', '.join(writes)}")
```

### 方式2：手动 API 录入

```python
from inst_db.api import InstructionDB

# 初始化数据库
db = InstructionDB("sqlite:///trace.db")

# 添加指令（自动反汇编 + 自动提取寄存器依赖）
instr = db.add_instruction(
    pc=0x4000d4,
    instruction_code=bytes.fromhex("a00080d2"),  # mov x0, #5
    sequence_id=1
)

print(f"Disassembly: {instr.disassembly}")  # 自动生成：mov x0, #5

# 寄存器依赖已自动添加
deps = db.get_register_dependencies(instr.id)
for dep in deps:
    print(f"Register: {dep.register_name}, dst={dep.is_dst}, src={dep.is_src}")
# 输出：Register: x0, dst=True, src=False

# 手动添加内存操作
db.add_memory_operation(
    instruction_id=instr.id,
    operation_type="WRITE",
    virtual_address=0x7fff0000,
    data_content=b'\x05\x00\x00\x00',
    data_length=4
)
```

## 核心功能

### 1. 自动语义分析

使用 Capstone 自动分析指令的寄存器读写：

```python
# 示例：add x2, x0, x1
db.add_instruction(
    pc=0x4000dc,
    instruction_code=bytes.fromhex("0200018b"),
    sequence_id=3
)

# 自动提取的依赖关系：
# - Reads: x0, x1
# - Writes: x2
```

支持的操作数类型：
- ✅ 整数寄存器（x0-x30, sp, xzr 等）
- ✅ 浮点寄存器（v0-v31, d0-d31 等）
- ✅ 隐式寄存器读写

### 2. QEMU 跟踪解析

自动解析 QEMU `-d in_asm` 输出：

```
----------------
IN: 
0x004000d4:  
OBJD-T: a00080d2410180d20200018b
```

解析器会：
1. 提取 PC 地址
2. 提取指令字节码（自动处理小端序）
3. 按4字节分割为单条指令
4. 递增 PC 地址（+4）

### 3. 数据查询

```python
# 按 PC 查找指令
instr = db.get_instruction_by_pc(0x4000d4)

# 按 ID 查找
instr = db.get_instruction_by_id(1)

# 获取指令序列
trace = db.get_instruction_trace(limit=100)

# 获取寄存器依赖
deps = db.get_register_dependencies(instr.id)

# 获取内存操作
mem_ops = db.get_memory_operations(instr.id)

# 删除指令（级联删除相关数据）
db.delete_instruction(instr.id)
```

## 数据模型

### Instruction（指令表）
- `pc`: 程序计数器
- `instruction_code`: 原始字节码（BLOB）
- `sequence_id`: 执行顺序（UNIQUE）
- `disassembly`: 反汇编字符串（自动生成）
- `created_at`: 创建时间

### RegisterDependency（寄存器依赖表）
- `instruction_id`: 外键 → Instruction.id
- `register_name`: 寄存器名称（VARCHAR(16)）
- `is_src`: 是否为源寄存器（读取）
- `is_dst`: 是否为目标寄存器（写入）

### MemoryOperation（内存操作表）
- `instruction_id`: 外键 → Instruction.id
- `operation_type`: "READ" 或 "WRITE"
- `virtual_address`: 虚拟地址
- `physical_address`: 物理地址（可选）
- `data_content`: 读写的数据（BLOB）
- `data_length`: 数据长度

外键关系：
- `ON DELETE CASCADE`：删除指令时自动删除相关依赖和内存操作

## 测试

```bash
# 运行所有测试（26个测试）
PYTHONPATH=src pytest tests/ -v

# 运行特定测试
PYTHONPATH=src pytest tests/test_qemu_parser.py -v
PYTHONPATH=src pytest tests/test_models.py -v

# 带覆盖率
PYTHONPATH=src pytest tests/ --cov=inst_db --cov-report=html
```

测试覆盖：
- ✅ 数据库模型（Instruction, RegisterDependency, MemoryOperation）
- ✅ API 接口（添加、查询、删除）
- ✅ 自动反汇编
- ✅ 自动寄存器依赖提取
- ✅ QEMU trace 解析
- ✅ 级联删除
- ✅ 边界条件处理

## 依赖库

- **SQLAlchemy 2.0+**: ORM 框架
- **Capstone 5.0+**: 多架构反汇编引擎
- **Pydantic 2.0+**: 数据验证

## 文档

- [QEMU 使用指南](docs/QEMU_USAGE.md) - 详细的 QEMU 集成说明
- [语义分析说明](SEMANTIC_ANALYSIS.md) - Capstone 集成细节

## 示例

查看 `examples/` 目录：
- `basic_usage.py` - 基本的 API 使用
- `qemu_import_example.py` - QEMU 跟踪导入示例

## 许可证

MIT
