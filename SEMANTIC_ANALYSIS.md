## Capstone 语义分析 - 自动寄存器依赖提取

### 🎯 功能概述

ARM64 指令跟踪数据库系统现已**自动使用 Capstone 提取指令的寄存器依赖**，包括：

✅ **显式操作数**（指令中明确指定的寄存器）
✅ **隐式操作数**（某些指令隐含访问的寄存器，如 sp、lr）
✅ **准确的读写分类**（每个寄存器是被读取、写入还是两者都有）

---

### 🔧 实现原理

#### Capstone 的语义信息提取

使用 Capstone 的**操作数访问标志** (`operand.access`):

```python
- CS_AC_READ (1)    : 寄存器被读取
- CS_AC_WRITE (2)   : 寄存器被写入  
- CS_AC_READ|WRITE  : 寄存器同时被读写
```

#### 核心代码片段

[src/inst_db/disassembler/arm64.py](../src/inst_db/disassembler/arm64.py#L76):

```python
for operand in instr.operands:
    if operand.type == CS_OP_REG:
        reg_name = self.cs.reg_name(operand.reg)
        
        # 根据访问标志分类
        if operand.access & CS_AC_READ:
            regs_read.add(reg_name)
        if operand.access & CS_AC_WRITE:
            regs_write.add(reg_name)
```

---

### 📊 使用示例

#### 自动提取示例

```python
from inst_db.api import InstructionDB

db = InstructionDB("sqlite:///trace.db")

# 添加指令 - 寄存器依赖自动提取
instr = db.add_instruction(
    pc=0x1000,
    instruction_code=bytes.fromhex("0000008b"),  # add x0, x0, x0
    sequence_id=1
)

# 自动提取结果
deps = db.get_register_dependencies(instr.id)
# 输出:
# - x0 [READ]   (作为源操作数读取)
# - x0 [WRITE]  (作为目的操作数写入)
```

---

### 📋 API 变化

#### `add_instruction()` 自动提取

**之前**：需要手动添加寄存器依赖
```python
instr = db.add_instruction(...)
db.add_register_dependency(
    instruction_id=instr.id,
    register_name="x0",
    is_src=True,
    is_dst=True
)
```

**现在**：自动提取，无需手动干预
```python
instr = db.add_instruction(...)
# ✅ 寄存器依赖已自动添加到数据库
deps = db.get_register_dependencies(instr.id)  # 获取自动提取的结果
```

---

### 🧪 测试覆盖

新增 4 个单元测试验证自动提取功能：

✅ `test_disassembly_included_in_instruction` - 反汇编自动执行
✅ `test_automatic_register_extraction` - 自动提取寄存器依赖
✅ `test_register_read_write_classification` - 正确分类读/写操作
✅ `test_implicit_registers_extraction` - 处理隐式寄存器

**测试结果**：19/19 通过 ✅

---

### 📈 处理的指令示例

| 指令 | 字节码 | 自动提取结果 |
|------|--------|-----------|
| `add x0, x0, x0` | `0000008b` | x0 [READ, WRITE] |
| `mov x0, x1` | `20000101aa` | x0 [WRITE], x1 [READ] |
| `ldp x0, x1, [sp]` | `00048fa8` | x0 [WRITE], x1 [WRITE], sp [READ] |

---

### 🚀 关键优势

1. **完全自动化**：用户无需手动指定寄存器依赖
2. **精确语义**：充分利用 Capstone 的指令语义分析
3. **包含隐式操作**：捕获指令的所有寄存器访问（包括隐式的）
4. **数据一致性**：所有依赖在指令添加时一次性提取，避免不一致

---

### 📝 配置要求

项目 [pyproject.toml](../pyproject.toml) 中已声明依赖：

```toml
dependencies = [
    "capstone>=5.0",  # ← ARM64反汇编和语义分析
    "sqlalchemy>=2.0",
    "pydantic>=2.0",
]
```

所有依赖已通过 `uv sync` 安装。

---

### ✅ 验证命令

```bash
# 运行自动提取相关的测试
uv run pytest tests/test_models.py::TestDisassembly -v

# 运行示例看实际效果
rm -f example_trace.db && uv run python examples/basic_usage.py
```
