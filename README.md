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

关系说明：
- `instructions` 1:N `register_dependencies`

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
```

## QEMU execlog 跟踪导入

```python
from inst_db.parsers import TraceImporter

TraceImporter("trace.log", "trace.db", architecture="arm64").import_trace()

# RISC-V
TraceImporter("trace.log", "trace.db", architecture="riscv64").import_trace()
```

### 使用跟踪脚本

统一的 QEMU `execlog` 跟踪脚本支持多个演示程序：

```bash
# 运行 quicksort 演示的跟踪
python scripts/runners/run_qemu_trace.py qsort

# 运行 SVE 演示的跟踪
python scripts/runners/run_qemu_trace.py sve

# 运行 RISC-V 最小演示的跟踪
python scripts/runners/run_qemu_trace.py riscv_min

# 跳过构建，只运行跟踪和导入
python scripts/runners/run_qemu_trace.py qsort --no-build

# 跳过导入数据库
python scripts/runners/run_qemu_trace.py qsort --no-import

# 跳过统计信息输出
python scripts/runners/run_qemu_trace.py qsort --no-stats
```

参数说明：
- `qsort|sve|riscv_min` - 选择要运行的演示程序
- `--no-build` - 跳过二进制文件构建
- `--no-trace` - 跳过 QEMU 跟踪执行
- `--no-import` - 跳过导入到数据库
- `--no-stats` - 跳过打印统计信息

脚本依赖：
- 编译器：`aarch64-linux-gnu-gcc`（ARM64）/ `riscv64-linux-gnu-gcc`（RISC-V）
- QEMU 二进制：`qemu_log/build/master/qemu-aarch64`、`qemu_log/build/master/qemu-riscv64`
- 插件：`qemu_log/build/master/libexeclog.so`

## DB 查询工具（独立 Python 脚本）

新增一组基于 SQL 的离线分析工具，输入仅为 `.db` 文件，支持表格输出和 `--json`。

```bash
# 1) 统一依赖链查询（默认 reg；根节点有访存时自动切换 mem）
uv run python scripts/db_tools/query_reg_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --max-depth 10

# 1.1) 指令寄存器依赖树形输出（便于快速浏览链路）
uv run python scripts/db_tools/query_reg_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --max-depth 10 --tree

# 1.2) 强制使用 mem 引擎（可选）
uv run python scripts/db_tools/query_reg_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --mode mem --max-depth 10 --tree

# 1.3) reg 引擎下子节点策略（默认 load_to_mem）
uv run python scripts/db_tools/query_reg_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --mode reg --reg-query-logic load_to_mem
uv run python scripts/db_tools/query_reg_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --mode reg --reg-query-logic reg_only

# 2) 内存 RAW 依赖链（READ 追最近 WRITE）
uv run python scripts/db_tools/query_mem_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --max-depth 10

# 2.1) 内存 RAW 依赖树形输出
uv run python scripts/db_tools/query_mem_dep_chain.py tmp/quicksort_trace.db --seq-id 4420 --max-depth 10 --tree

# 3) 指令自修改检测（地址命中 + 字节变化）
uv run python scripts/db_tools/query_self_modifying.py tmp/quicksort_trace.db --window 2000

# 4) Loop 检测（重复窗口 + 回边混合）
uv run python scripts/db_tools/detect_loops.py tmp/quicksort_trace.db --min-iter 3 --min-body 2 --max-body 64
```

常用参数：
- `--json`：JSON 输出
- `--limit N`：限制输出条数（默认 `100`）
- `--verbose`：输出额外诊断信息

详细说明见：`docs/DB_TOOLS.md`

## Spike (RISC-V) 跟踪导入

RISC-V 支持使用 Spike 执行日志作为指令流输入（无 `riscv-pk` 模式）。

```python
from inst_db.parsers import SpikeTraceImporter

SpikeTraceImporter("riscv_trace.log", "riscv_trace.db").import_trace()
```

### 使用 Spike 跟踪脚本（无 `pk`）

```bash
# 一键执行：构建 + Spike 跟踪 + 导入（默认运行 1 秒，默认导入上限 50000）
uv run python scripts/runners/run_spike_trace.py

# 自定义 Spike 运行时长（秒）
uv run python scripts/runners/run_spike_trace.py --run-seconds 0.5

# 自定义导入上限
uv run python scripts/runners/run_spike_trace.py --import-limit 10000

# 只导入已有日志
uv run python scripts/runners/run_spike_trace.py --no-build --no-trace --import-limit 20000
```

脚本依赖：
- `riscv64-linux-gnu-gcc`
- `spike`

## Web UI 可视化

项目提供两种可视化方案：

### 1. Flask Web UI（当前版本）
基于 Flask + HTML/JavaScript 的 Web 界面，功能完整。

```bash
# 启动 Web UI
python start_web_ui.py

# 访问 http://127.0.0.1:5000
```

详见：[WEB_UI_IMPLEMENTATION.md](WEB_UI_IMPLEMENTATION.md)

### 2. 纯 Python UI 框架（推荐）
使用纯 Python 编写的 UI 框架，无需编写 HTML/JavaScript。

**🏆 推荐：Streamlit** - 数据可视化专用框架
```bash
# 安装
pip install streamlit

# 运行示例
streamlit run streamlit_demo.py

# 访问 http://localhost:8501
```

**其他选择：**
- **Gradio** - ML 应用友好
- **NiceGUI** - 现代美观界面

**快速测试所有框架：**
```bash
# 列出可用框架
python test_frameworks.py --list

# 测试 Streamlit
python test_frameworks.py streamlit

# 测试 Gradio
python test_frameworks.py gradio

# 安装所有框架
python test_frameworks.py --install-all
```

详细对比和迁移指南：[PYTHON_UI_FRAMEWORKS.md](PYTHON_UI_FRAMEWORKS.md)

**对比总结：**

| 方案 | 代码量 | 学习难度 | 数据可视化 | 推荐度 |
|------|--------|---------|-----------|--------|
| Flask + HTML/JS | 680+ 行 | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| Streamlit | ~130 行 | ⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| Gradio | ~200 行 | ⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| NiceGUI | ~250 行 | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |

## 备注

- 所有地址字段以 hex 字符串存储（`0x...`），不是整数类型。
- 如果需要导出文本分析，使用 [docs/EXPORT_TOOL.md](docs/EXPORT_TOOL.md) 中的工具脚本。
