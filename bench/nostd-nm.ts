// Assert that binaries link no Rust std: run `nm` over every symbol, defined
// and undefined, and fail on any that belongs to std or its panic runtime.
// This is the check a no_std consumer runs on its own binaries.
// Usage: bun nostd-nm.ts <binary>...
const PATTERNS: [string, RegExp][] = [
  ["demangled std path", /(^|[^A-Za-z0-9_])std::/],
  ["legacy-mangled std item", /_ZN3std/],
  ["v0-mangled std crate", /[_C]3std([0-9A-Z_]|$)/],
  ["std-internal symbol", /__rust_std|std_internal/],
  ["std panic runtime", /panic_unwind|__rust_start_panic|__rust_panic_cleanup|__rust_foreign_exception/],
];
const bins = process.argv.slice(2);
if (!bins.length) { console.log("usage: bun nostd-nm.ts <binary>..."); process.exit(2); }
let bad = 0;
for (const bin of bins) {
  const r = Bun.spawnSync(["nm", bin]);
  if (r.exitCode !== 0) { console.log("nm failed on " + bin + "\n" + r.stderr.toString()); bad++; continue; }
  const syms = r.stdout.toString().split("\n").filter(Boolean).map(l => l.trim().split(/\s+/).pop()!);
  const hits = [];
  for (const s of syms) for (const [why, re] of PATTERNS) if (re.test(s)) hits.push(why + ": " + s);
  if (hits.length) { bad++; console.log("nm: " + bin + ": " + hits.length + " std symbols"); for (const h of hits.slice(0, 20)) console.log("  " + h); }
  else console.log("nm: " + bin + ": " + syms.length + " symbols, none from std");
}
process.exit(bad ? 1 : 0);
