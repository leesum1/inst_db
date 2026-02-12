QEMU_AARCH64 ?= ./build/master/qemu-aarch64
QEMU_RISCV64 ?= ./build/master/qemu-riscv64
EXECLOG_PLUGIN ?= ./build/master/libexeclog.so

AARCH64_CC ?= aarch64-linux-gnu-gcc
RISCV64_CC ?= riscv64-linux-gnu-gcc

BUILD_DIR ?= build
LOG_DIR ?= logs
SHOW_N ?= 30

AARCH64_SRC := tests/min/aarch64_min.c
RISCV64_SRC := tests/min/riscv64_min.c

AARCH64_BIN := $(BUILD_DIR)/aarch64_min
RISCV64_BIN := $(BUILD_DIR)/riscv64_min

.PHONY: all test-min test-aarch64-min test-riscv64-min show-logs clean

all: test-min

$(BUILD_DIR) $(LOG_DIR):
	mkdir -p $@

$(AARCH64_BIN): $(AARCH64_SRC) | $(BUILD_DIR)
	$(AARCH64_CC) -O0 -g -static -o $@ $<

$(RISCV64_BIN): $(RISCV64_SRC) | $(BUILD_DIR)
	$(RISCV64_CC) -O0 -g -static -o $@ $<

test-min: test-aarch64-min test-riscv64-min

test-aarch64-min: $(AARCH64_BIN) | $(LOG_DIR)
	$(QEMU_AARCH64) -d plugin -D $(LOG_DIR)/aarch64_execlog.txt -plugin $(EXECLOG_PLUGIN) $(AARCH64_BIN) > $(LOG_DIR)/aarch64_stdout.txt
	grep -q '^ok-aarch64$$' $(LOG_DIR)/aarch64_stdout.txt
	test -s $(LOG_DIR)/aarch64_execlog.txt
	rg -q 'm=L[0-9]+, v=0x[0-9a-f]+, va=0x[0-9a-f]+' $(LOG_DIR)/aarch64_execlog.txt
	rg -q 'm=S[0-9]+, v=0x[0-9a-f]+, va=0x[0-9a-f]+' $(LOG_DIR)/aarch64_execlog.txt

test-riscv64-min: $(RISCV64_BIN) | $(LOG_DIR)
	$(QEMU_RISCV64) -d plugin -D $(LOG_DIR)/riscv64_execlog.txt -plugin $(EXECLOG_PLUGIN) $(RISCV64_BIN) > $(LOG_DIR)/riscv64_stdout.txt
	grep -q '^ok-riscv64$$' $(LOG_DIR)/riscv64_stdout.txt
	test -s $(LOG_DIR)/riscv64_execlog.txt
	rg -q 'm=L[0-9]+, v=0x[0-9a-f]+, va=0x[0-9a-f]+' $(LOG_DIR)/riscv64_execlog.txt
	rg -q 'm=S[0-9]+, v=0x[0-9a-f]+, va=0x[0-9a-f]+' $(LOG_DIR)/riscv64_execlog.txt

show-logs:
	test -f $(LOG_DIR)/aarch64_execlog.txt
	test -f $(LOG_DIR)/riscv64_execlog.txt
	@echo '== aarch64 execlog (head -n $(SHOW_N)) =='
	head -n $(SHOW_N) $(LOG_DIR)/aarch64_execlog.txt
	@echo
	@echo '== riscv64 execlog (head -n $(SHOW_N)) =='
	head -n $(SHOW_N) $(LOG_DIR)/riscv64_execlog.txt

clean:
	rm -rf $(BUILD_DIR) $(LOG_DIR)
