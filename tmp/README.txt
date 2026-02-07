Temporary artifacts for the quicksort + QEMU trace pipeline.

- qsort_demo.c: ARM64 quicksort demo source
- qsort_demo: compiled ARM64 binary
- qsort_trace.log: QEMU -d in_asm,exec,cpu,nochain trace output
- quicksort_trace.db: SQLite database populated from trace
- run_qsort_trace.py: build, run, import, and print stats
