# QEMU execlog (AArch64 + RISC-V)

本目录已放置可直接运行的编译产物：

- `qemu-aarch64`
- `qemu-riscv64`
- `libexeclog.so`

它们来自 QEMU 10.2.0，启用了插件支持（`--enable-plugins`），可用于输出指令流。

## 1) 基本运行方式（输出 execlog 指令流）

> 关键点：需要 `-d plugin -D <日志文件>`，插件输出才会落盘。

### AArch64

```bash
./qemu-aarch64 \
  -d plugin \
  -D aarch64_execlog.txt \
  -plugin ./libexeclog.so \
  ./your_aarch64_binary
```

### RISC-V 64

```bash
./qemu-riscv64 \
  -d plugin \
  -D riscv64_execlog.txt \
  -plugin ./libexeclog.so \
  ./your_riscv64_binary
```

程序标准输出仍会打印到终端；指令流在 `*_execlog.txt` 文件中。

## 2) 常用插件参数（可选）

`execlog` 支持以下过滤参数（用逗号追加在 `-plugin` 后）：

- `ifilter=<insn_prefix>`：按反汇编指令前缀过滤（例如 `ifilter=jal`）
- `afilter=<hex_vaddr>`：按虚拟地址过滤（16 进制，不带 `0x` 也可）
- `reg=<glob_pattern>`：跟踪匹配寄存器变化（例如 `reg=a*`）
- `rdisas=on|off`：辅助寄存器匹配

示例（RISC-V，仅看 `jal`）：

```bash
./qemu-riscv64 \
  -d plugin \
  -D riscv64_jal.txt \
  -plugin ./libexeclog.so,ifilter=jal \
  ./your_riscv64_binary
```

## 3) 最小可验证流程

先确认二进制可用：

```bash
./qemu-aarch64 --version
./qemu-riscv64 --version
```

再运行目标程序并查看日志：

```bash
wc -l aarch64_execlog.txt
head -n 30 aarch64_execlog.txt
```

## 4) 本次编译配置（记录）

构建时使用的核心配置如下：

```bash
../qemu-10.2.0/configure \
  --target-list=aarch64-linux-user,riscv64-linux-user \
  --enable-plugins \
  --disable-system \
  --disable-tools \
  --disable-docs \
  --disable-werror
```

