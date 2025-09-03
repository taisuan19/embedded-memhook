#!/usr/bin/env bash
set -euo pipefail

# 项目根目录（脚本所在目录的上一级）
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT_DIR/memhook_dump.c"
OUT_DIR="$ROOT_DIR/bin"
OUT_BIN="$OUT_DIR/memhook_dump"

mkdir -p "$OUT_DIR"

if [[ ! -f "$SRC" ]]; then
  echo "Error: cannot find memhook_dump.c at: $SRC" >&2
  exit 1
fi

echo "[build] gcc -O2 -Wall -Wextra -std=c11 $SRC -o $OUT_BIN"
gcc -O2 -Wall -Wextra -std=c11 "$SRC" -o "$OUT_BIN"

echo "[build] done -> $OUT_BIN"
