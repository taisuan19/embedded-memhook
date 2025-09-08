# leakhook

Simple LD_PRELOAD library for tracking heap allocations on Linux.

## Build

```bash
make
```
This produces `libleakhook.so` in the same directory.

## Usage

```bash
LD_PRELOAD=./libleakhook.so your_program
# generate a leak report
kill -USR1 <pid>
```

The report prints live allocations to stderr.
