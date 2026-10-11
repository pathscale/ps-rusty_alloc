rounds=5 raw=results/debug-overhead-raw-2026-10-11T08-05-43-788Z.jsonl base=rusty_alloc
min over rounds; ratio vs base in parens (lower better)

| workload | alloc | wall ms | instr (G) | cycles (G) | max RSS MB | footprint MB | n |
|---|---|---:|---:|---:|---:|---:|---:|
| tasks:1 | rusty_alloc | 254.1 (1.00) | 4.676 (1.00) | 1.004 (1.00) | 3.1 (1.00) | 2.6 (1.00) | 5 |
| tasks:1 | debug | 892.5 (3.51) | 17.462 (3.73) | 3.470 (3.46) | 5.2 (1.69) | 4.6 (1.81) | 5 |
| small:1 | rusty_alloc | 78.6 (1.00) | 1.286 (1.00) | 0.313 (1.00) | 1.9 (1.00) | 1.4 (1.00) | 5 |
| small:1 | debug | 1967.0 (25.04) | 30.472 (23.70) | 7.506 (23.95) | 3.8 (1.94) | 3.2 (2.23) | 5 |
| realistic:1 | rusty_alloc | 52.9 (1.00) | 0.966 (1.00) | 0.211 (1.00) | 4.5 (1.00) | 3.9 (1.00) | 5 |
| realistic:1 | debug | 193.1 (3.65) | 4.050 (4.19) | 0.761 (3.61) | 5.8 (1.30) | 5.3 (1.33) | 5 |
