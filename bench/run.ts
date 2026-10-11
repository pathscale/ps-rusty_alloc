// Interleaved A/B runner. Reports MIN over rounds of: wall ms, instructions retired,
// cycles, max RSS, peak footprint (all from /usr/bin/time -l on macOS).
// Usage: bun run.ts <rounds> <allocs> <cfgs> [tag]
//   allocs: comma list of bin names, optional env variant: rusty_alloc+RUSTY_ALLOC_PURGE_DELAY=10
//   cfgs:   comma list of workload:threads, e.g. tasks:1,small:1
import { mkdirSync, appendFileSync } from "fs";
const ROUNDS = Number(process.argv[2] ?? 5);
const ALLOCS = (process.argv[3] ?? "system,mimalloc,rusty_alloc,smalloc").split(",");
const CFGS = (process.argv[4] ?? "tasks:1").split(",").map(c => { const [w, t] = c.split(":"); return [w, Number(t ?? 1)]; });
const TAG = process.argv[5] ?? "run";
const TIMEOUT_MS = 60000;
mkdirSync("results", { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const raw = "results/" + TAG + "-raw-" + stamp + ".jsonl";
const best = {};
const dead = new Set();
const num = (s, re) => Number((s.match(re) || [])[1] || 0);
for (let r = 0; r < ROUNDS; r++) {
  for (const [wl, t] of CFGS) {
    let order = ALLOCS.map((_, i) => ALLOCS[(i + r) % ALLOCS.length]);
    if (r % 2) order.reverse();
    for (const spec of order) {
      const [bin, ...envs] = spec.split("+");
      const env = { ...process.env };
      for (const e of envs) { const [k, v] = e.split("="); env[k] = v; }
      const key = spec + "|" + wl + "|" + t;
      if (dead.has(key)) continue;
      const p = Bun.spawnSync(["/usr/bin/time", "-l", "./bin/" + bin, wl, String(t)], { timeout: TIMEOUT_MS, env });
      const out = p.stdout.toString(), err = p.stderr.toString();
      const m = out.match(/ms=([\d.]+)/);
      const rec = { round: r, alloc: spec, wl, t, ok: !!m && p.exitCode === 0, ms: m ? Number(m[1]) : null,
        rss: num(err, /(\d+)\s+maximum resident set size/), instr: num(err, /(\d+)\s+instructions retired/),
        cycles: num(err, /(\d+)\s+cycles elapsed/), foot: num(err, /(\d+)\s+peak memory footprint/), code: p.exitCode, sig: p.signalCode ?? null };
      appendFileSync(raw, JSON.stringify(rec) + "\n");
      if (!rec.ok) { dead.add(key); best[key] = { fail: p.signalCode ? "TIMEOUT" : "rc=" + p.exitCode }; console.log("FAIL", key); continue; }
      const b = best[key] ?? { ms: Infinity, rss: Infinity, instr: Infinity, cycles: Infinity, foot: Infinity, n: 0 };
      best[key] = { ms: Math.min(b.ms, rec.ms), rss: Math.min(b.rss, rec.rss), instr: Math.min(b.instr, rec.instr), cycles: Math.min(b.cycles, rec.cycles), foot: Math.min(b.foot, rec.foot), n: b.n + 1 };
    }
  }
  console.log("round " + (r + 1) + "/" + ROUNDS);
}
const BASE = ALLOCS.includes("mimalloc") ? "mimalloc" : ALLOCS[0];
let md = "rounds=" + ROUNDS + " raw=" + raw + " base=" + BASE + "\nmin over rounds; ratio vs base in parens (lower better)\n\n| workload | alloc | wall ms | instr (G) | cycles (G) | max RSS MB | footprint MB | n |\n|---|---|---:|---:|---:|---:|---:|---:|\n";
for (const [wl, t] of CFGS) {
  const b0 = best[BASE + "|" + wl + "|" + t];
  for (const a of ALLOCS) {
    const b = best[a + "|" + wl + "|" + t];
    if (!b || b.fail) { md += "| " + wl + ":" + t + " | " + a + " | " + (b?.fail ?? "-") + " ||||||\n"; continue; }
    const f = (k, d, s) => (b[k] / d).toFixed(s) + (b0 && !b0.fail ? " (" + (b[k] / b0[k]).toFixed(2) + ")" : "");
    md += "| " + wl + ":" + t + " | " + a + " | " + f("ms", 1, 1) + " | " + f("instr", 1e9, 3) + " | " + f("cycles", 1e9, 3) + " | " + f("rss", 1048576, 1) + " | " + f("foot", 1048576, 1) + " | " + b.n + " |\n";
  }
}
await Bun.write("results/" + TAG + "-summary-" + stamp + ".md", md);
console.log(md);
