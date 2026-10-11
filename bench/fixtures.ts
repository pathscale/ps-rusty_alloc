// Debug-mode fixtures: build bench/src/bin/debug_demo.rs with the `debug`
// feature, run it, and compare its stdout byte for byte with
// fixtures/debug_demo.expected. On a mismatch, every differing key is listed.
// Usage: bun fixtures.ts           check
//        bun fixtures.ts --regen   rewrite the expected file from this run
const EXPECTED = "fixtures/debug_demo.expected";
const TARGET = "target/debug";
const b = Bun.spawnSync(["cargo", "build", "--release", "--no-default-features", "--features", "debug",
  "--bin", "debug_demo", "--target-dir", TARGET], { stdout: "inherit", stderr: "inherit" });
if (b.exitCode !== 0) { console.log("fixtures: build failed"); process.exit(1); }
const r = Bun.spawnSync([TARGET + "/release/debug_demo"]);
if (r.exitCode !== 0) { console.log("fixtures: debug_demo exited " + r.exitCode + "\n" + r.stderr.toString()); process.exit(1); }
const got = r.stdout.toString();
if (process.argv.includes("--regen")) {
  await Bun.write(EXPECTED, got);
  console.log("fixtures: wrote " + EXPECTED + " (" + got.split("\n").filter(Boolean).length + " keys)");
  process.exit(0);
}
const want = await Bun.file(EXPECTED).text();
const keys = (s) => new Map(s.split("\n").filter(Boolean).map(l => { const i = l.indexOf(": "); return [l.slice(0, i), l.slice(i + 2)]; }));
const g = keys(got), w = keys(want);
let bad = 0;
for (const [k, v] of w) {
  if (!g.has(k)) { console.log("missing " + k); bad++; }
  else if (g.get(k) !== v) { console.log("changed " + k + "\n  want " + v + "\n  got  " + g.get(k)); bad++; }
}
for (const k of g.keys()) if (!w.has(k)) { console.log("extra " + k); bad++; }
if (!bad && got !== want) { console.log("order or whitespace differs"); bad++; }
console.log(bad ? "fixtures: FAIL (" + bad + ")" : "fixtures: ok, " + w.size + " keys match byte for byte");
process.exit(bad ? 1 : 0);
