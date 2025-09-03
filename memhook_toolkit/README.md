# memhook_toolkit

内存追踪分析工具链：解码 `memhook_xxx.bin` 二进制日志、生成汇总与泄漏信息、导出 CSV，并基于 CSV 做峰值与 TID/调用点分析。

---

## 📂 目录结构

memhook_toolkit/
├─ bin/ # 编译生成的二进制工具
│ ├─ memhook_dump # 解码 .bin -> summary/leaks/csv
│ └─ memhook_csv_analyze # 从 CSV 重放，输出峰值/TID/调用点/时间序列
│
├─ scripts/
│ └─ gen_reports.sh # 自动化导出入口
│
├─ python/ # (可选) Python 脚本，扩展分析/画图
│ ├─ analyze_peaks.py
│ ├─ plot_timeseries.py
│ ├─ compare_runs.py
│ └─ utils.py
│
├─ src/
│ └─ memhook_dump.c # 解码器源码
│
├─ tools/
│ └─ memhook_csv_analyze.c # CSV 分析器源码
│
├─ logs/ # 存放运行时生成的追踪二进制文件 (.bin)
│ ├─ memhook_001.bin
│ └─ ...
│
├─ out/ # 导出的结果
│ └─ memhook_001.bin/
│ ├─ summary/summary.txt
│ ├─ leaks/leaks.txt
│ ├─ csv/records.csv
│ └─ analysis/*.csv
│
├─ Makefile
└─ README.md

yaml
复制代码

---

## ⚙️ 编译

需要 GCC / Clang (C11):

```bash
make -j
生成可执行文件：

bin/memhook_dump

bin/memhook_csv_analyze

🚀 使用方法
1. 准备数据
把设备生成的内存追踪文件拷贝到 logs/：

bash
复制代码
logs/memhook_001.bin
logs/memhook_002.bin
2. 一键导出
运行脚本：

bash
复制代码
scripts/gen_reports.sh --live-all --time-asc --peak memhook_001.bin
脚本会在 out/memhook_001.bin/ 下生成：

summary/summary.txt ：统计信息（malloc/free/峰值等）

leaks/leaks.txt ：未释放内存列表

csv/records.csv ：逐条事件记录

analysis/*.csv ：CSV 二次分析结果

3. 常用参数
--live-all ：导出全部未释放块（默认 top20）

--time-asc ：leaks/summary 按时间升序

--peak ：在 summary 中输出峰值内存和时间

--min-size N ：过滤小于 N 字节的块

--approx-mem BYTES ：在 CSV 分析器中标记近似内存上限

--no-csv ：只生成 summary/leaks，不生成 CSV

--csv-top N ：CSV 分析输出排行 TOP N（默认 100）

示例：

bash
复制代码
scripts/gen_reports.sh --live-top 50 --peak --approx-mem 120000000 memhook_002.bin
4. 批量导出
支持通配符：

bash
复制代码
scripts/gen_reports.sh --live-all --peak logs/memhook_*.bin
📊 输出文件说明
summary.txt

总记录数

malloc/free/calloc/realloc 次数

总分配/释放字节数

在存峰值 (--peak)

时间跨度

leaks.txt

最终仍未释放的内存块

包含大小、指针、tid、调用点、分配时间

records.csv

所有事件，含系统时间戳、tid、操作、指针、大小、返回地址

analysis/

overview.csv：整体峰值、首次超过 --approx-mem 时刻

top_tids_by_peak.csv：线程在存峰值排行

top_sites_by_peak.csv：调用点在存峰值排行

live_blocks_at_end.csv：结束时仍存活的块

timeseries_downsampled.csv：在存曲线抽样

🛠️ 调试/开发
用 addr2line -e <elf> 0xRETADDR 映射调用点到源码行。

Python 脚本可选：python/analyze_peaks.py 等，用于可视化或进一步分析。

📌 提示
建议保持目录清晰：

logs/ 只放原始 .bin 数据

out/ 自动生成分析结果

bin/ 只放可执行工具

如果 summary 里“最晚未释放时间”停留在开机时刻，说明后来触发 OOM 的是瞬时峰值而不是长期泄漏；请结合 overview.csv 和 top_tids_by_peak.csv 定位原因。