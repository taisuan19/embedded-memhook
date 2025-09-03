#!/usr/bin/env bash
set -euo pipefail

# scripts/gen_reports.sh
# 目录约定：
#   - 原始 .bin：logs/*.bin          （输入）
#   - 可执行：   bin/*               （memhook_dump / memhook_csv_analyze）
#   - 输出：     out/<name>/...      （结果）
#
# 示例：
#   scripts/gen_reports.sh --live-all --time-asc --peak memhook_*.bin
#   scripts/gen_reports.sh --min-size 1024 --live-top 100 --peak --approx-mem 120000000 memhook_001.bin
#
# 说明：
#   * 位置参数可以是文件名（例如 memhook_001.bin），脚本会优先尝试 logs/<name>；
#     也可以传绝对/相对路径（如 logs/memhook_001.bin 或 /tmp/x.bin）

# ---------- 默认参数 ----------
OUT_BASE_DIR="out"
LOGS_DIR="logs"

MIN_SIZE="0"
LIVE_MODE="--live-top 20"   # 或 --live-all
DO_CSV=1

TIME_ASC=0                 # --time-asc 影响 leaks 排序 & summary 的 order 提示
DO_PEAK=0                  # --peak 开启峰值统计
APPROX_MEM=""              # 传给 CSV 分析器的近似上限（字节）
CSV_TOP=100                # CSV 分析器排行 TOP
CSV_DOWNSAMPLE=400         # CSV 分析器 time-series 抽样点数

TOOL_DUMP="bin/memhook_dump"
TOOL_CSV="bin/memhook_csv_analyze"

# ---------- 帮助 ----------
usage() {
  cat <<EOF
Usage: $(basename "$0") [options] <memhook.bin ...>

Options:
  --out DIR             输出根目录 (default: out/)
  --logs DIR            输入 .bin 根目录 (default: logs/)
  --min-size N          只统计/列出大小 >= N 字节的泄漏 (default: 0)
  --live-all            输出全部泄漏（默认 top20）
  --live-top N          输出前 N 个最大泄漏（默认 20）
  --time-asc            leaks/summary 按时间升序（默认按 size 降序）
  --peak                在 summary 输出在存峰值与时间
  --no-csv              不生成 CSV 与后续分析
  --approx-mem BYTES    提示 CSV 分析器“近似内存上限”，用于标注首次越阈值时刻
  --csv-top N           CSV 分析排行 TOP（默认 100）
  --csv-downsample N    CSV 抽样点数（默认 400）
  --tool-dump PATH      memhook_dump 路径（默认 bin/memhook_dump）
  --tool-csv PATH       memhook_csv_analyze 路径（默认 bin/memhook_csv_analyze）
  -h, --help            显示帮助

Examples:
  $(basename "$0") --live-all --time-asc --peak memhook_*.bin
  $(basename "$0") --min-size 1024 --live-top 50 --approx-mem 120000000 memhook_001.bin
EOF
}

# ---------- 解析参数 ----------
ARGS=()
while (($#)); do
  case "$1" in
    --out)              OUT_BASE_DIR="$2"; shift 2;;
    --logs)             LOGS_DIR="$2"; shift 2;;
    --min-size)         MIN_SIZE="$2"; shift 2;;
    --live-all)         LIVE_MODE="--live-all"; shift 1;;
    --live-top)         LIVE_MODE="--live-top ${2:-20}"; shift 2;;
    --time-asc)         TIME_ASC=1; shift 1;;
    --peak)             DO_PEAK=1; shift 1;;
    --no-csv)           DO_CSV=0; shift 1;;
    --approx-mem)       APPROX_MEM="$2"; shift 2;;
    --csv-top)          CSV_TOP="${2:-100}"; shift 2;;
    --csv-downsample)   CSV_DOWNSAMPLE="${2:-400}"; shift 2;;
    --tool-dump)        TOOL_DUMP="$2"; shift 2;;
    --tool-csv)         TOOL_CSV="$2"; shift 2;;
    -h|--help)          usage; exit 0;;
    --)                 shift; break;;
    -*) echo "Unknown option: $1" >&2; usage; exit 1;;
    *)  ARGS+=("$1"); shift;;
  esac
done

if ((${#ARGS[@]}==0)); then
  echo "Error: please provide at least one memhook .bin file (bare name or path)" >&2
  usage; exit 1
fi

# ---------- 工具检查 ----------
if [[ ! -x "$TOOL_DUMP" ]]; then
  echo "Error: tool not found or not executable: $TOOL_DUMP" >&2
  echo "Hint: make -j" >&2
  exit 1
fi

HAS_LEAK_OUT=0
if "$TOOL_DUMP" --help 2>&1 | grep -q -- '--leak-out'; then
  HAS_LEAK_OUT=1
fi

# 汇总参数以传递给 memhook_dump
TOOL_ARGS=()
TOOL_ARGS+=($LIVE_MODE --min-size "$MIN_SIZE")
(( TIME_ASC == 1 )) && TOOL_ARGS+=(--time-asc)
(( DO_PEAK  == 1 )) && TOOL_ARGS+=(--peak)

echo "[gen] dump=$TOOL_DUMP  csv_ana=$TOOL_CSV"
echo "[gen] out_base=$OUT_BASE_DIR  logs=$LOGS_DIR"
echo "[gen] min_size=$MIN_SIZE  live_mode='$LIVE_MODE'  time_asc=$TIME_ASC  peak=$DO_PEAK  csv=$DO_CSV"

# ---------- 逐个输入处理 ----------
for NAME in "${ARGS[@]}"; do
  BIN="$NAME"
  # 如果不是现存路径，且不含 / ，则尝试 logs/<name>
  if [[ ! -f "$BIN" && "$NAME" != */* ]]; then
    if [[ -f "$LOGS_DIR/$NAME" ]]; then
      BIN="$LOGS_DIR/$NAME"
    fi
  fi
  if [[ ! -f "$BIN" ]]; then
    echo "[skip] not found: $NAME  (also tried: $LOGS_DIR/$NAME)" >&2
    continue
  fi

  base="$(basename -- "$BIN")"
  name="$base"
  [[ "$name" == *.bin ]] && name="${name%.bin}"

  OUT_DIR="$OUT_BASE_DIR/$base"
  SUM_DIR="$OUT_DIR/summary"
  LEA_DIR="$OUT_DIR/leaks"
  CSV_DIR="$OUT_DIR/csv"
  ANA_DIR="$OUT_DIR/analysis"
  mkdir -p "$SUM_DIR" "$LEA_DIR" "$CSV_DIR" "$ANA_DIR"

  SUMMARY_FILE="$SUM_DIR/summary.txt"
  LEAKS_FILE="$LEA_DIR/leaks.txt"
  CSV_FILE="$CSV_DIR/records.csv"

  echo "[gen] $BIN -> $OUT_DIR"

  if (( HAS_LEAK_OUT == 1 )); then
    # 1) 只写 leaks 到文件（静音 stdout/stderr）
    "$TOOL_DUMP" "$BIN" "${TOOL_ARGS[@]}" --leak-out "$LEAKS_FILE" >/dev/null 2>/dev/null
    # 2) 只写 summary 到文件（把 leaks 丢到 /dev/null）
    "$TOOL_DUMP" "$BIN" "${TOOL_ARGS[@]}" --leak-out /dev/null >/dev/null 2>"$SUMMARY_FILE"
  else
    # 旧版兼容：整块输出抓到临时文件，再抽取 leaks 段
    TMP_SUM="$SUM_DIR/.summary_full.tmp"
    "$TOOL_DUMP" "$BIN" "${TOOL_ARGS[@]}" >/dev/null 2>"$TMP_SUM"
    cp "$TMP_SUM" "$SUMMARY_FILE"
    awk '
      BEGIN{inleak=0}
      /^== leaks \(unfreed blocks\)/{inleak=1; print; next}
      /^== leaks .* order=/{inleak=1; print; next}
      /^Hint: addr2line/ && inleak==1 {print; inleak=0; next}
      inleak==1 {print}
    ' "$TMP_SUM" > "$LEAKS_FILE" || true
    rm -f "$TMP_SUM"
  fi

  if (( DO_CSV == 1 )); then
    # CSV（与排序无关；含 wall_time）
    "$TOOL_DUMP" "$BIN" --min-size "$MIN_SIZE" --csv "$CSV_FILE" >/dev/null 2>/dev/null || true

    # CSV 分析（如果有编译）
    if [[ -x "$TOOL_CSV" ]]; then
      if [[ -n "$APPROX_MEM" ]]; then
        "$TOOL_CSV" "$CSV_FILE" --out "$ANA_DIR" --top "$CSV_TOP" --downsample "$CSV_DOWNSAMPLE" --approx-mem "$APPROX_MEM" >/dev/null
      else
        "$TOOL_CSV" "$CSV_FILE" --out "$ANA_DIR" --top "$CSV_TOP" --downsample "$CSV_DOWNSAMPLE" >/dev/null
      fi
    fi
  fi

  echo "[ok ] wrote:"
  printf "      - %s\n" "$SUMMARY_FILE"
  printf "      - %s\n" "$LEAKS_FILE"
  if (( DO_CSV == 1 )); then
    printf "      - %s\n" "$CSV_FILE"
    [[ -d "$ANA_DIR" ]] && printf "      - %s/{overview.csv,top_tids_by_peak.csv,top_sites_by_peak.csv,live_blocks_at_end.csv,timeseries_downsampled.csv}\n" "$ANA_DIR"
  fi
done

echo "[gen] all done."
