#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析 memhook CSV（idx,ts_ns,wall_ns,wall_time,tid,op,ptr,arg,retaddr）：
- 重放事件流，维护 live 映射 (ptr -> size, tid, ra)
- 计算整体在存曲线、峰值时间点
- 计算按 TID 的在存峰值排行
- 计算按 RA 的在存峰值排行
- 导出结束时仍在存的大块
- 导出时间序列（可抽样）
"""

import csv
import argparse
from collections import defaultdict, namedtuple

Row = namedtuple("Row", "idx ts_ns wall_ns wall_time tid op ptr arg ra")

def parse_int(s):
    # 支持 0x 前缀
    s = s.strip()
    if s.startswith(("0x","0X")):
        return int(s, 16)
    return int(s)

def read_rows(csv_path):
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        # 兼容列顺序：要求至少包含这些列
        name2i = {name: i for i, name in enumerate(header)}
        required = ["idx","ts_ns","wall_ns","wall_time","tid","op","ptr","arg","retaddr"]
        for r in required:
            if r not in name2i:
                raise ValueError(f"missing column: {r}; header={header}")

        for cols in reader:
            try:
                row = Row(
                    idx       = int(cols[name2i["idx"]]),
                    ts_ns     = int(cols[name2i["ts_ns"]]),
                    wall_ns   = int(cols[name2i["wall_ns"]]) if cols[name2i["wall_ns"]] else 0,
                    wall_time = cols[name2i["wall_time"]],
                    tid       = int(cols[name2i["tid"]]),
                    op        = cols[name2i["op"]],
                    ptr       = parse_int(cols[name2i["ptr"]]),
                    arg       = int(cols[name2i["arg"]]) if cols[name2i["arg"]] else 0,
                    ra        = parse_int(cols[name2i["retaddr"]]),
                )
                rows.append(row)
            except Exception as e:
                # 忽略坏行（也可以改成 raise）
                # print("skip bad row:", e, cols)
                continue
    return rows

def analyze(rows, approx_mem=None):
    """
    返回：
      overview: dict
      tids_peak: list[dict]  (降序)
      sites_peak: list[dict] (降序)
      live_end_blocks: list[dict] (按 size 降序)
      ts_series: list[dict] (完整序列)
    """
    # live map: ptr -> (size, tid, ra, ts_ns, wall_ns, wall_time_first)
    live = {}

    cur_live_bytes = 0
    peak_live_bytes = 0
    peak_idx = -1
    peak_ts_ns = 0
    peak_wall_ns = 0
    peak_wall_time = ""

    # per-tid in-mem bytes & peaks
    tid_live = defaultdict(int)
    tid_peak = defaultdict(int)
    tid_peak_idx = {}
    tid_peak_tsns = {}
    tid_peak_wtime = {}

    # per-site (ra) in-mem & peaks
    ra_live = defaultdict(int)
    ra_peak = defaultdict(int)
    ra_peak_idx = {}
    ra_peak_tsns = {}
    ra_peak_wtime = {}

    # time series
    ts_series = []

    # 近似内存上限时刻
    approx_cross = None

    for r in rows:
        # 记录序列
        ts_series.append({
            "idx": r.idx,
            "ts_ns": r.ts_ns,
            "wall_time": r.wall_time,
            "cur_live_bytes": cur_live_bytes
        })

        if r.op == "malloc" or r.op == "calloc":
            size = r.arg
            if size <= 0:
                size = 0
            # 如果该 ptr 已存在，先扣旧值（防御日志异常）
            if r.ptr in live:
                old = live[r.ptr][0]
                cur_live_bytes -= old
                tid_live[live[r.ptr][1]] -= old
                ra_live[live[r.ptr][2]] -= old
            live[r.ptr] = (size, r.tid, r.ra, r.ts_ns, r.wall_ns, r.wall_time)
            cur_live_bytes += size
            tid_live[r.tid] += size
            ra_live[r.ra] += size

        elif r.op == "realloc":
            # 视为：先 free 旧 ptr，再 alloc 新 size 到同 ptr
            old = live.get(r.ptr)
            if old:
                old_size, old_tid, old_ra, *_ = old
                cur_live_bytes -= old_size
                tid_live[old_tid] -= old_size
                ra_live[old_ra] -= old_size
            new_size = r.arg if r.arg > 0 else 0
            live[r.ptr] = (new_size, r.tid, r.ra, r.ts_ns, r.wall_ns, r.wall_time)
            cur_live_bytes += new_size
            tid_live[r.tid] += new_size
            ra_live[r.ra] += new_size

        elif r.op == "free":
            old = live.pop(r.ptr, None)
            if old:
                old_size, old_tid, old_ra, *_ = old
                cur_live_bytes -= old_size
                tid_live[old_tid] -= old_size
                ra_live[old_ra] -= old_size
            # 否则：free 丢失，忽略

        # 刷新整体峰值
        if cur_live_bytes > peak_live_bytes:
            peak_live_bytes = cur_live_bytes
            peak_idx = r.idx
            peak_ts_ns = r.ts_ns
            peak_wall_ns = r.wall_ns
            peak_wall_time = r.wall_time

        # 刷新 tid 峰值
        if tid_live[r.tid] > tid_peak[r.tid]:
            tid_peak[r.tid] = tid_live[r.tid]
            tid_peak_idx[r.tid] = r.idx
            tid_peak_tsns[r.tid] = r.ts_ns
            tid_peak_wtime[r.tid] = r.wall_time

        # 刷新 ra 峰值
        if ra_live[r.ra] > ra_peak[r.ra]:
            ra_peak[r.ra] = ra_live[r.ra]
            ra_peak_idx[r.ra] = r.idx
            ra_peak_tsns[r.ra] = r.ts_ns
            ra_peak_wtime[r.ra] = r.wall_time

        # 记录在本行处理后的序列（覆盖前面预写的占位）
        ts_series[-1]["cur_live_bytes"] = cur_live_bytes

        # 近似内存上限交叉
        if approx_mem and not approx_cross and cur_live_bytes >= approx_mem:
            approx_cross = {
                "idx": r.idx,
                "ts_ns": r.ts_ns,
                "wall_time": r.wall_time,
                "cur_live_bytes": cur_live_bytes
            }

    # 汇总 live 末尾大块
    live_end_blocks = []
    for p, (size, tid, ra, ts_ns, wall_ns, wall_time) in live.items():
        live_end_blocks.append({
            "ptr": f"0x{p:016x}",
            "size": size,
            "tid": tid,
            "ra": f"0x{ra:016x}",
            "alloc_ts_ns": ts_ns,
            "alloc_wall_time": wall_time
        })
    live_end_blocks.sort(key=lambda x: x["size"], reverse=True)

    # TID/RA 排行（取峰值）
    tids_peak = []
    for tid, peak in tid_peak.items():
        tids_peak.append({
            "tid": tid,
            "peak_live_bytes": peak,
            "peak_idx": tid_peak_idx.get(tid, -1),
            "peak_ts_ns": tid_peak_tsns.get(tid, 0),
            "peak_wall_time": tid_peak_wtime.get(tid, "")
        })
    tids_peak.sort(key=lambda x: x["peak_live_bytes"], reverse=True)

    sites_peak = []
    for ra, peak in ra_peak.items():
        sites_peak.append({
            "retaddr": f"0x{ra:016x}",
            "peak_live_bytes": peak,
            "peak_idx": ra_peak_idx.get(ra, -1),
            "peak_ts_ns": ra_peak_tsns.get(ra, 0),
            "peak_wall_time": ra_peak_wtime.get(ra, "")
        })
    sites_peak.sort(key=lambda x: x["peak_live_bytes"], reverse=True)

    overview = {
        "records": len(rows),
        "peak_live_bytes": peak_live_bytes,
        "peak_idx": peak_idx,
        "peak_ts_ns": peak_ts_ns,
        "peak_wall_ns": peak_wall_ns,
        "peak_wall_time": peak_wall_time,
        "end_live_blocks": len(live_end_blocks),
        "end_live_bytes": sum(x["size"] for x in live_end_blocks),
        "approx_cross": approx_cross
    }

    return overview, tids_peak, sites_peak, live_end_blocks, ts_series

def write_csv(path, rows, header):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([r.get(h,"") for h in header])

def downsample_series(series, n=500):
    if n <= 0 or len(series) <= n:
        return series
    step = len(series) / n
    out = []
    i = 0.0
    while int(i) < len(series):
        out.append(series[int(i)])
        i += step
    if out[-1] is not series[-1]:
        out.append(series[-1])
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", help="memhook records.csv")
    ap.add_argument("--out", default="out_report", help="output dir")
    ap.add_argument("--downsample", type=int, default=400, help="downsample points for time series")
    ap.add_argument("--top", type=int, default=50, help="top-N for rankings")
    ap.add_argument("--approx-mem", type=float, default=0.0, help="approximate memory ceiling in bytes (optional)")
    args = ap.parse_args()

    import os
    os.makedirs(args.out, exist_ok=True)

    rows = read_rows(args.csv)
    overview, tids_peak, sites_peak, live_end_blocks, ts_series = analyze(
        rows, approx_mem=(args.approx_mem if args.approx_mem>0 else None)
    )

    # 概览
    ov_path = os.path.join(args.out, "overview.csv")
    write_csv(ov_path, [overview], [
        "records","peak_live_bytes","peak_idx","peak_ts_ns","peak_wall_ns","peak_wall_time",
        "end_live_blocks","end_live_bytes","approx_cross"
    ])

    # TID 峰值排行
    top_tids = tids_peak[:args.top]
    tid_path = os.path.join(args.out, "top_tids_by_peak.csv")
    write_csv(tid_path, top_tids, ["tid","peak_live_bytes","peak_idx","peak_ts_ns","peak_wall_time"])

    # 调用点(ra) 峰值排行
    top_sites = sites_peak[:args.top]
    site_path = os.path.join(args.out, "top_sites_by_peak.csv")
    write_csv(site_path, top_sites, ["retaddr","peak_live_bytes","peak_idx","peak_ts_ns","peak_wall_time"])

    # 结束时仍在存的大块（泄漏候选）
    leaks_path = os.path.join(args.out, "live_blocks_at_end.csv")
    write_csv(leaks_path, live_end_blocks, ["ptr","size","tid","ra","alloc_ts_ns","alloc_wall_time"])

    # 时间序列（抽样）
    ds = downsample_series(ts_series, args.downsample)
    ts_path = os.path.join(args.out, "timeseries_downsampled.csv")
    write_csv(ts_path, ds, ["idx","ts_ns","wall_time","cur_live_bytes"])

    # 控制台给出关键摘要
    print(f"[ok] overview -> {ov_path}")
    print(f"     peak_live_bytes={overview['peak_live_bytes']} at {overview['peak_wall_time']} (idx={overview['peak_idx']})")
    if overview["approx_cross"]:
        ac = overview["approx_cross"]
        print(f"     crossed approx-mem at {ac['wall_time']} (bytes={ac['cur_live_bytes']}, idx={ac['idx']})")
    print(f"[ok] top tids -> {tid_path} (TOP {len(top_tids)})")
    print(f"[ok] top sites -> {site_path} (TOP {len(top_sites)})")
    print(f"[ok] live-at-end blocks -> {leaks_path} (n={len(live_end_blocks)})")
    print(f"[ok] time series (downsampled) -> {ts_path} (points={len(ds)}/{len(ts_series)})")

if __name__ == "__main__":
    main()
