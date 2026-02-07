# ARM64 指令跟踪数据库系统

一个基于 Python、SQLAlchemy 和 Capstone 的 ARM64 指令执行跟踪和分析系统。

## 功能特性

- 📊 **完整的指令记录**：存储 PC、指令码、反汇编结果和执行顺序
- 📝 **寄存器依赖追踪**：记录每条指令的源/目的寄存器
- 🔍 **内存操作追踪**：记录虚拟地址、物理地址、读写数据和长度
- 🗄️ **轻量级数据库**：基于 SQLite，易于部署和分享
- 🔧 **易用的 Python API**：简洁的高级接口用于数据录入和查询

## 项目结构

```
inst_db/
├── src/inst_db/
│   ├── models/          # 数据模型定义
│   ├── database/        # 数据库连接和管理
│   ├── disassembler/    # ARM64 反汇编模块
│   ├── utils/           # 工具函数
│   └── api.py           # 高级 API 接口
├── tests/               # 测试用例
├── examples/            # 使用示例
├── scripts/             # 初始化脚本
└── pyproject.toml       # 项目配置
```

## 安装

使用 uv 管理项目依赖：

```bash
# 安装项目
uv sync

# 开发模式安装（带开发依赖）
uv sync --with dev
```

## 快速开始

### 初始化数据库

```bash
python scripts/init_db.py
```

### 使用 API 录入数据

```python
from inst_db.api import InstructionDB

# 初始化数据库
db = InstructionDB("trace.db")

# 添加指令
instr = db.add_instruction(
    pc=0x1000,
    instruction_code=b'\x11\x00\x00\x94',  # 原始指令字节
    sequence_id=1
)

# 添加寄存器依赖
db.add_register_dependency(
    instruction_id=instr.id,
    register_name="x0",
    is_src=True,
    is_dst=False
)

# 添加内存操作
db.add_memory_operation(
    instruction_id=instr.id,
    operation_type="READ",
    virtual_address=0x7fff0000,
    physical_address=0x3fff0000,
    data_content=b'\x01\x02\x03\x04',
    data_length=4
)
```

## 数据模型

### Instruction（指令表）
- `id`: 主键
- `sequence_id`: 指令执行顺序
- `pc`: 程序计数器
- `instruction_code`: 指令的原始字节（HEX）
- `disassembly`: 反汇编结果
- `created_at`: 创建时间

### RegisterDependency（寄存器依赖表）
- `id`: 主键
- `instruction_id`: 关联指令（外键）
- `register_name`: 寄存器名称 (如 "x0", "sp"等)
- `is_src`: 是否为源寄存器
- `is_dst`: 是否为目的寄存器

### MemoryOperation（内存操作表）
- `id`: 主键
- `instruction_id`: 关联指令（外键）
- `operation_type`: 操作类型 ("READ" 或 "WRITE")
- `virtual_address`: 虚拟地址
- `physical_address`: 物理地址
- `data_content`: 操作数据（二进制）
- `data_length`: 数据长度
- `created_at`: 创建时间

## 依赖库

- **SQLAlchemy 2.0+**: ORM 框架
- **Capstone 5.0+**: 多架构反汇编引擎
- **Pydantic 2.0+**: 数据验证

## 测试

```bash
# 运行所有测试
pytest

# 运行带覆盖率的测试
pytest --cov=src/inst_db
```

## 许可证

MIT
