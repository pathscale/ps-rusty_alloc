rounds=7 raw=results/parity-final-raw-2026-10-11T08-05-38-028Z.jsonl base=ra_galloc
min over rounds; ratio vs base in parens (lower better)

| workload | alloc | wall ms | instr (G) | cycles (G) | max RSS MB | footprint MB | n |
|---|---|---:|---:|---:|---:|---:|---:|
| tasks:1 | ra_galloc | 252.3 (1.00) | 4.667 (1.00) | 0.997 (1.00) | 3.1 (1.00) | 2.6 (1.00) | 7 |
| tasks:1 | ra_dbgtp | 253.8 (1.01) | 4.667 (1.00) | 0.998 (1.00) | 3.1 (1.00) | 2.6 (1.00) | 7 |
| small:1 | ra_galloc | 78.1 (1.00) | 1.285 (1.00) | 0.312 (1.00) | 1.9 (1.00) | 1.4 (1.00) | 7 |
| small:1 | ra_dbgtp | 78.2 (1.00) | 1.285 (1.00) | 0.311 (1.00) | 1.9 (1.00) | 1.4 (1.00) | 7 |
| realistic:1 | ra_galloc | 51.9 (1.00) | 0.966 (1.00) | 0.209 (1.00) | 4.9 (1.00) | 4.4 (1.00) | 7 |
| realistic:1 | ra_dbgtp | 51.8 (1.00) | 0.966 (1.00) | 0.210 (1.00) | 5.0 (1.03) | 4.5 (1.03) | 7 |
