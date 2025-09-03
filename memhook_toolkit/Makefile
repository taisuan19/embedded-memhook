# Makefile (root)
# 目录结构：
#   src/memhook_dump.c
#   tools/memhook_csv_analyze.c
# 生成：
#   bin/memhook_dump
#   bin/memhook_csv_analyze

CC      ?= gcc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -Wno-unused-parameter

BIN_DIR    := bin
SRC_DIR    := src
TOOLS_DIR  := tools

DUMP_SRC   := $(SRC_DIR)/memhook_dump.c
CSVANA_SRC := $(TOOLS_DIR)/memhook_csv_analyze.c

DUMP_BIN   := $(BIN_DIR)/memhook_dump
CSVANA_BIN := $(BIN_DIR)/memhook_csv_analyze

.PHONY: all clean rebuild

all: $(DUMP_BIN) $(CSVANA_BIN)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(DUMP_BIN): $(DUMP_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(CSVANA_BIN): $(CSVANA_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(DUMP_BIN) $(CSVANA_BIN)

rebuild: clean all
