#!/usr/bin/env bash
set -euo pipefail

# 默认参数
OUT_BASE_DIR="out"
MIN_SIZE="0"
LIVE_MODE="--live-top 20"   # 或者用 --live-all
DO_CSV=1
TOOL_DEFAULT="bin/memhook_dump"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] <memhook.bin ...>

Options:
  --out DIR           输出根目录 (default: out)
  --min-size N        只统计/列出大小 >= N 字节的泄漏 (default: 0)
  --live-all          输出全部泄漏 (默认 top20)
  --live-top N        输出前 N 个最大泄漏 (默认 20)
  --no-csv            不生成 CSV（默认生成）
  --tool PATH         memhook_dump 可执行文件路径 (default: bin/memhook_dump)

Examples:
  $(basename "$0") memhook_*.bin
  $(basename "$0") --min-size 1024 --live-all memhook.bin
  $(basename "$0") --out results --live-top 50 logs/memhook.bin
EOF
}

# 解析参数
TOOL="$TOOL_DEFAULT"
ARGS=()
while (($#)); do
  case "$1" in
    --out)        OUT_BASE_DIR="$2"; shift 2;;
    --min-size)   MIN_SIZE="$2"; shift 2;;
    --live-all)   LIVE_MODE="--live-all"; shift 1;;
    --live-top)   LIVE_MODE="--live-top ${2:-20}"; shift 2;;
    --no-csv)     DO_CSV=0; shift 1;;
    --tool)       TOOL="$2"; shift 2;;
    -h|--help)    usage; exit 0;;
    --) shift; break;;
    -*) echo "Unknown option: $1" >&2; usage; exit 1;;
    *)  ARGS+=("$1"); shift;;
  esac
done

# 收集剩余位置参数（文件）
if ((${#ARGS[@]}==0)); then
  echo "Error: please provide at least one memhook .bin file" >&2
  usage; exit 1
fi

# 检查工具
if [[ ! -x "$TOOL" ]]; then
  echo "Error: tool not found or not executable: $TOOL" >&2
  echo "Hint: run scripts/build.sh first." >&2
  exit 1
fi

# 运行时检测是否支持 --leak-out
HAS_LEAK_OUT=0
if "$TOOL" --help 2>&1 | grep -q -- '--leak-out'; then
  HAS_LEAK_OUT=1
fi

echo "[gen] tool=$TOOL  out_base=$OUT_BASE_DIR  min_size=$MIN_SIZE  live_mode='$LIVE_MODE'  csv=$DO_CSV  leak_out=$HAS_LEAK_OUT"

# 逐个文件处理
for BIN in "${ARGS[@]}"; do
  if [[ ! -f "$BIN" ]]; then
    echo "[skip] not a file: $BIN" >&2
    continue
  fi
  # 取纯文件名 & 去扩展名
  base="$(basename -- "$BIN")"
  name="$base"               # 目录名=完整文件名，保留 .bin.1
  # 如果文件刚好以 .bin 结尾（没有轮次后缀），可以可选地去掉 .bin：
  [[ "$name" == *.bin ]] && name="${name%.bin}"

  # 目录组织：out/<name>/{summary,leaks,csv}
  OUT_DIR="$OUT_BASE_DIR/$name"
  SUM_DIR="$OUT_DIR/summary"
  LEA_DIR="$OUT_DIR/leaks"
  CSV_DIR="$OUT_DIR/csv"
  mkdir -p "$SUM_DIR" "$LEA_DIR" "$CSV_DIR"

  SUMMARY_FILE="$SUM_DIR/summary.txt"
  LEAKS_FILE="$LEA_DIR/leaks.txt"
  CSV_FILE="$CSV_DIR/records.csv"

  echo "[gen] $BIN -> $OUT_DIR"

  if (( HAS_LEAK_OUT == 1 )); then
    # 方式一：优先使用 --leak-out（更干净）
    # 1) 只生成泄漏明细（静音其余输出）
    "$TOOL" "$BIN" $LIVE_MODE --min-size "$MIN_SIZE" --leak-out "$LEAKS_FILE" >/dev/null 2>/dev/null

    # 2) 只生成汇总/统计（不含泄漏明细）
    "$TOOL" "$BIN" $LIVE_MODE --min-size "$MIN_SIZE" --leak-out /dev/null >/dev/null 2>"$SUMMARY_FILE"
  else
    # 方式二：不支持 --leak-out，生成带泄漏的完整 summary，再从中提取泄漏段
    TMP_SUM="$SUM_DIR/.summary_full.tmp"
    "$TOOL" "$BIN" $LIVE_MODE --min-size "$MIN_SIZE" >/dev/null 2>"$TMP_SUM"

    # 保存完整 summary（含泄漏）
    cp "$TMP_SUM" "$SUMMARY_FILE"

    # 从完整 summary 中抽取泄漏段：从行开头匹配 "== leaks" 起，到空行后的 "Hint:" 或文件结尾
    awk '
      BEGIN{inleak=0}
      /^== leaks \(unfreed blocks\)/{inleak=1; print; next}
      /^Hint: addr2line/ && inleak==1 {print; inleak=0; next}
      inleak==1 {print}
    ' "$TMP_SUM" > "$LEAKS_FILE" || true

    rm -f "$TMP_SUM"
  fi

  # CSV（可选）
  if (( DO_CSV == 1 )); then
    "$TOOL" "$BIN" --min-size "$MIN_SIZE" --csv "$CSV_FILE" >/dev/null 2>/dev/null || true
  fi

  echo "[ok ] wrote:"
  printf "      - %s\n" "$SUMMARY_FILE"
  printf "      - %s\n" "$LEAKS_FILE"
  if (( DO_CSV == 1 )); then
    printf "      - %s\n" "$CSV_FILE"
  fi
done

echo "[gen] all done."
