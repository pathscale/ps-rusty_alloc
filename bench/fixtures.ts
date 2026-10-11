// Debug-mode fixtures: build bench/src/bin/debug_demo.rs with the `debug`
// feature, run it, and compare its stdout byte for byte with
// fixtures/debug_demo.expected. On a mismatch, every differing key is listed.
// Call stacks come out of the demo as {image+offset@address;...}; each is
// symbolized with tools/symbolize.ts and replaced by the first function that
// is not the allocator or the runtime ("none" when nothing was captured), so
// the expected file names call sites and holds no addresses or paths. The
// build forces frame pointers, as every debug_checks consumer must.
// Usage: bun fixtures.ts           check
//        bun fixtures.ts --regen   rewrite the expected file from this run
const EXPECTED = "fixtures/debug_demo.expected";
const TARGET = "target/debug";
const b = Bun.spawnSync(["cargo", "build", "--release", "--no-default-features", "--features", "debug",
  "--bin", "debug_demo", "--target-dir", TARGET], {
  stdout: "inherit", stderr: "inherit",
  env: { ...process.env, RUSTFLAGS: ((process.env.RUSTFLAGS ?? "") + " -C force-frame-pointers=yes").trim() },
});
if (b.exitCode !== 0) { console.log("fixtures: build failed"); process.exit(1); }
const r = Bun.spawnSync([TARGET + "/release/debug_demo"]);
if (r.exitCode !== 0) { console.log("fixtures: debug_demo exited " + r.exitCode + "\n" + r.stderr.toString()); process.exit(1); }
const got = await sites(r.stdout.toString());

// Frames of the allocator, the standard library and the Rust runtime.
function internal(name) {
  return /^<?(rusty_alloc|alloc|core|std)::/.test(name) || /^__r(ust|g)_/.test(name) || /^_?_?rust_/.test(name);
}

async function sites(text) {
  const STACK = /\{((?:[^{}@;]*@0x[0-9a-f]+;?)*)\}/g;
  const stacks = [...text.matchAll(STACK)].map(m => m[1] ? m[1].split(";") : []);
  // One report for the symbolizer, one frame line per entry.
  const report = [];
  stacks.forEach((fr, i) => fr.forEach((e, j) => {
    const at = e.lastIndexOf("@");
    const img = e.slice(0, at), addr = e.slice(at + 1);
    const plus = img.lastIndexOf("+0x");
    report.push(plus > 0
      ? "s" + i + " #" + j + " 0x" + addr.slice(2).padStart(16, "0") + " (" + img + ")"
      : "s" + i + " #" + j + " " + addr);
  }));
  const tmp = TARGET + "/sites.txt";
  await Bun.write(tmp, report.join("\n") + "\n");
  const y = Bun.spawnSync([process.execPath, "../tools/symbolize.ts", tmp]);
  if (y.exitCode !== 0) { console.log("fixtures: symbolize failed\n" + y.stderr.toString()); process.exit(1); }
  const names = stacks.map(() => []);
  for (const l of y.stdout.toString().split("\n")) {
    const m = /^s(\d+) #\d+ 0x[0-9a-f]+(?: in (.*?)(?: \[inlined\])? \(|)/.exec(l);
    if (!m) continue;
    const fn = m[2] ? m[2].replace(/ [^ ]*:\d+(:\d+)?$/, "") : "?";
    names[+m[1]].push(fn);
  }
  let k = 0;
  return text.replace(STACK, () => {
    const n = names[k++];
    if (!n.length) return "none";
    return n.find(x => x !== "?" && !internal(x)) ?? "?";
  });
}
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
