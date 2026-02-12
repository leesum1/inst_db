# QEMU execlog (AArch64 + RISC-V)

本目录统一使用 `build/master/` 产物：

- `build/master/qemu-aarch64`
- `build/master/qemu-riscv64`
- `build/master/libexeclog.so`

## 1) 基本运行方式（输出 execlog 指令流）

> 必须使用 `-d plugin -D <日志文件>`，插件输出才会落盘。

### AArch64

```bash
./build/master/qemu-aarch64 \
  -d plugin \
  -D logs/aarch64_execlog.txt \
  -plugin ./build/master/libexeclog.so \
  ./your_aarch64_binary
```

### RISC-V 64

```bash
./build/master/qemu-riscv64 \
  -d plugin \
  -D logs/riscv64_execlog.txt \
  -plugin ./build/master/libexeclog.so \
  ./your_riscv64_binary
```

程序标准输出仍会打印到终端；指令流在 `logs/*_execlog.txt`。

## 2) 内存访问日志格式

内存访问追加字段：

- `m=L<size>`：load（例如 `m=L8`）
- `m=S<size>`：store（例如 `m=S16`）
- `v=0x...`：本次读/写的数据值
- `va=0x...`：虚拟地址
- system 模式下额外可能出现：`pa=0x...` 与 `dev=...`

示例：

```text
0, 0x400590, 0xf94003e1, "ldr x1, [sp]", m=L8, v=0x0000000000000001, va=0x7f...
0, 0x4008e0, 0xa9b77bfd, "stp ...", m=S16, v=0x..., va=0x7f...
```

## 3) 常用插件参数（可选）

`execlog` 支持以下过滤参数（追加在 `-plugin` 后）：

- `ifilter=<insn_prefix>`：按反汇编指令前缀过滤（例如 `ifilter=jal`）
- `afilter=<hex_vaddr>`：按虚拟地址过滤（16 进制，可不带 `0x`）
- `reg=<glob_pattern>`：跟踪匹配寄存器变化（例如 `reg=a*`）
- `rdisas=on|off`：辅助寄存器匹配

示例（RISC-V，仅看 `jal`）：

```bash
./build/master/qemu-riscv64 \
  -d plugin \
  -D logs/riscv64_jal.txt \
  -plugin ./build/master/libexeclog.so,ifilter=jal \
  ./your_riscv64_binary
```

## 4) 最小可验证流程

```bash
make test-min
```

该目标会：

- 运行 AArch64/RISC-V 最小程序
- 生成 `logs/aarch64_execlog.txt` 与 `logs/riscv64_execlog.txt`
- 校验日志中同时存在 load/store 且包含 `m=`, `v=`, `va=` 字段

快速查看：

```bash
wc -l logs/aarch64_execlog.txt
head -n 30 logs/aarch64_execlog.txt
```

## 5) 重新编译插件

如果修改了 `qemu-master-src/contrib/plugins/execlog.c`：

```bash
cd qemu-master-src/build
ninja contrib/plugins/libexeclog.so
cp -f contrib/plugins/libexeclog.so ../../build/master/libexeclog.so
```

## 6) 构建配置记录

```bash
./configure \
  --target-list=aarch64-linux-user,riscv64-linux-user \
  --enable-plugins \
  --disable-system \
  --disable-tools \
  --disable-docs \
  --disable-werror
```
