# Embedded Memhook / 内存泄漏追踪工具

## 📖 Overview / 简介
**Embedded Memhook** is a lightweight **memory leak tracking framework** designed for C/C++ projects and embedded Linux systems.  
**Embedded Memhook** 是一个轻量级的 **内存泄漏追踪框架**，适用于 C/C++ 项目和嵌入式 Linux 系统。  

It works by **intercepting `malloc/free`** calls, recording allocation information into a binary log file (`.bin`).  
它通过 **拦截 `malloc/free`** 调用，把分配信息记录到二进制日志文件（`.bin`）中。  

A dump utility can parse the log and generate **human-readable reports** (`.txt`, `.csv`) for leak analysis.  
配套的 dump 工具可以解析日志，生成 **可读报告**（`.txt`, `.csv`），用于内存泄漏分析。  

---

## 🚀 Quick Start / 快速开始
```bash
### 1. Build with linker wrap / 使用 `--wrap` 编译
```bash
gcc -Wl,--wrap=malloc -Wl,--wrap=free -o your_program your_program.c memhook.c

2.编译memhook_dump
gcc -O2 memhook_dump.c -o memhook_dump

# 3. Dump and analyze logs / 转储并分析日志
./memhook_dump memhook.bin > summary.txt

# 最常用：打印汇总 + 前20条泄漏（按size降序）
./memhook_dump memhook.bin 2>summary.txt

# 打印所有泄漏
./memhook_dump memhook.bin --live-all 2>summary.txt

# 只看 >= 1024B 的泄漏，并导出逐条CSV
./memhook_dump memhook.bin --min-size 1024 --csv records.csv 2>summary.txt

# 只看前50条最大泄漏
./memhook_dump memhook.bin --live-top 50 2>summary.txt


Example Output / 示例输出
== leaks (unfreed blocks) [ALL] ==
1) size=128B   ptr=0x12345678  tid=1024  ra=0x08004567
2) size=64B    ptr=0x23456789  tid=1024  ra=0x08004890
Hint: addr2line -e <elf> 0xRETADDR   # map ra to source:line

🛠️ Features / 特性
Implemented with GNU Linker --wrap, no macro conflicts
基于 GNU Linker --wrap，避免宏替换带来的问题
Track malloc/free with minimal intrusion
最小化代码侵入，业务代码无需修改
Export binary logs, dump to text/CSV
输出二进制日志，可转储为文本/CSV
Compatible with C/C++ projects and embedded Linux
兼容 C/C++ 项目及嵌入式 Linux 环境



# 1) 编译
chmod +x scripts/build.sh scripts/gen_reports.sh
scripts/build.sh

分析records.csv
python3 csv_analyze_memhook.py  out/memhook_oom_572_up19273ms/csv/records.csv  --out out_report --downsample 200 --top 50 --approx-mem 2e6

按时间输出，summary和leaks
scripts/gen_reports.sh --live-all --time-asc  memhook_oom_572_up19273ms.bin

默认输出
scripts/gen_reports.sh --live-all  memhook_oom_572_up19273ms.bin