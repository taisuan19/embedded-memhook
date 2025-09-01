#!/bin/sh
# mem_watch.sh - Lightweight memory sampler for small devices (POSIX/busybox sh)
# Usage:
#   ./mem_watch.sh [process_name] [interval_sec] [--lite]
#   process_name   : default "cardv"
#   interval_sec   : default 30
#   --lite         : skip smaps (lower overhead)
#
# Env:
#   MEM_WATCH_LOG=/path/to/log         (default: /tmp/mem_watch.log)
#   SMAPS_SNAP_DIR=/path/for/snapshots (default: /tmp)

PNAME="${1:-cardv}"
INTERVAL="${2:-30}"
LITE=0
[ "$3" = "--lite" ] && LITE=1

LOG="${MEM_WATCH_LOG:-/mnt/mmc/mem_watch.log}"
SMAPS_SNAP_DIR="${SMAPS_SNAP_DIR:-/tmp}"

ts() { date "+%F %T"; }

get_pid() {
  pidof "$PNAME" 2>/dev/null | awk '{print $1}'
}

print_hints_once() {
cat <<'EOF'
[Hints]
- VmRSS 持续上涨且 RssAnon 增长明显：更像匿名内存泄漏/匿名 mmap（检查 Get/Release 成对、异常释放）。
- RssFile 较大但稳定：多为 SO/模型映射，不一定是泄漏。
- Cached 下降而进程 RSS 稳定：更像页缓存/IO 压力（录像/写盘/大文件 mmap）。
- slab 某项持续增长：怀疑驱动或内核对象泄漏。
EOF
echo
}

print_meminfo() {
  echo "== $(ts) =="
  free -m 2>/dev/null || true
  echo
  awk '/MemTotal:|MemFree:|Buffers:|Cached:|SReclaimable:|Shmem:/ {print}' /proc/meminfo
  echo
}

print_proc_status() {
  PID="$1"
  if [ -n "$PID" ] && [ -r "/proc/$PID/status" ]; then
    echo "[/proc/$PID/status]"
    awk '/Name:|Pid:|Threads:|VmSize:|VmRSS:|RssAnon:|RssFile:|RssShmem:/ {print}' "/proc/$PID/status"
    echo
  else
    echo "[proc status] process '$PNAME' not found"
    echo
  fi
}

print_pmap_top() {
  PID="$1"
  if [ -n "$PID" ] && command -v pmap >/dev/null 2>&1; then
    echo "[pmap -x top RSS segments]"
    pmap -x "$PID" 2>/dev/null | awk 'NR>1{print}' | sort -k3 -n | tail -15
    echo
  fi
}

print_smaps_summary() {
  PID="$1"
  SMAPS="/proc/$PID/smaps"
  [ -r "$SMAPS" ] || return 0

  echo "[/proc/$PID/smaps summary (kB)]"
  grep -E '^(Size|Rss|Pss|Shared_Clean|Shared_Dirty|Private_Clean|Private_Dirty|Referenced|Anonymous|FilePages|Shmem):' "$SMAPS" \
  | awk '{sum[$1]+=$2} END{for (k in sum) printf "%-16s %10d kB\n", k, sum[k]}'
  echo

  echo "[top anon segments by Rss]"
  awk '
    BEGIN {RS=""; FS="\n"}
    {
      hdr=$1; rss=0; anon=0;
      for(i=1;i<=NF;i++){
        if($i ~ /^Rss:/){ split($i,a," "); rss=a[2]; }
        else if($i ~ /^Anonymous:/){ split($i,b," "); anon=b[2]; }
      }
      if(hdr ~ /rw-p/){
        path=""; if(hdr ~ /\/.*/){ path=substr(hdr, index(hdr,"/")); }
        if(path==""){ if(hdr ~ /\[ heap \]/){ path="[heap]"; } else { path="[anon]"; } }
        printf "%010d %010d %s\n", rss, anon, path;
      }
    }
  ' "$SMAPS" | sort -r | head -5 | awk '{printf "Rss=%d kB  Anon=%d kB  %s\n",$1,$2,$3}'
  echo

  echo "[top file-backed segments by Rss]"
  awk '
    BEGIN {RS=""; FS="\n"}
    {
      hdr=$1; rss=0; filep=0; path="";
      for(i=1;i<=NF;i++){
        if($i ~ /^Rss:/){ split($i,a," "); rss=a[2]; }
        else if($i ~ /^FilePages:/){ split($i,b," "); filep=b[2]; }
      }
      if(hdr ~ /\/.*/){ path=substr(hdr, index(hdr,"/")); }
      if(path!=""){ printf "%010d %010d %s\n", rss, filep, path; }
    }
  ' "$SMAPS" | sort -r | head -5 | awk '{printf "Rss=%d kB  FilePages=%d kB  %s\n",$1,$2,$3}'
  echo
}

snapshot_smaps_rss() {
  # $1 = pid, 输出 "addr path<TAB>rss_kB"
  PID="$1"
  SMAPS="/proc/$PID/smaps"
  [ -r "$SMAPS" ] || return 1
  awk '
    BEGIN {RS=""; FS="\n"}
    {
      hdr=$1; rss=0; path="";
      for(i=1;i<=NF;i++){
        if($i ~ /^Rss:/){ split($i,a," "); rss=a[2]; }
      }
      if(hdr ~ /\/.*/){ path=substr(hdr, index(hdr,"/")); }
      else if(hdr ~ /\[ heap \]/){ path="[heap]"; }
      else { path="[anon]"; }
      split(hdr,h," "); addr=h[1];
      printf "%s %s\t%d\n", addr, path, rss;
    }
  ' "$SMAPS"
}

print_smaps_delta() {
  PID="$1"
  [ -n "$PID" ] || return 0
  CUR="${SMAPS_SNAP_DIR}/smaps_${PID}_cur.txt"
  PRE="${SMAPS_SNAP_DIR}/smaps_${PID}_pre.txt"

  snapshot_smaps_rss "$PID" | sort -k2,2 -k1,1 > "$CUR" || return 0

  if [ -f "$PRE" ]; then
    echo "[ΔRss top 5 segments (kB)]"
    # 用临时文件 join，避免 bash 扩展
    join -j 1 -t '	' \
      "$CUR" "$PRE" \
      | awk -F'	' '{delta=$3-$4; if(delta>0) printf "%8d  %s\n", delta, $2;}' \
      | sort -nr | head -5
    echo
  fi

  mv -f "$CUR" "$PRE" >/dev/null 2>&1
}

print_slab_top() {
  if [ -r /proc/slabinfo ]; then
    echo "[slab top by obj count]"
    awk 'NR>2{printf "%-24s %10s\n",$1,$3}' /proc/slabinfo | sort -k2 -n | tail -10
    echo
  fi
}

# ---- main loop ----
PID=""
FIRST=1
echo "Start mem watch for process='$PNAME', interval=${INTERVAL}s, lite=${LITE}" > "$LOG"

while true; do
  PID_CUR=$(get_pid)
  if [ "$PID_CUR" != "$PID" ]; then
    PID="$PID_CUR"
    echo "[$(ts)] Tracking PID: ${PID:-N/A}" >> "$LOG"
  fi

  {
    print_meminfo
    print_proc_status "$PID"
    print_pmap_top "$PID"
    [ "$LITE" -eq 0 ] && print_smaps_summary "$PID"
    [ "$LITE" -eq 0 ] && print_smaps_delta "$PID"
    print_slab_top
    if [ $FIRST -eq 1 ]; then print_hints_once; FIRST=0; fi
  } >> "$LOG" 2>&1

  sleep "$INTERVAL"
done
