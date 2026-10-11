// The no_std multi-threaded proof: build nostd-mt/ four ways, check each with
// nostd-nm.ts, run each many times and compare its stdout byte for byte with
// fixtures/nostd_mt.expected. The debug build must also stop a double free.
//
//   abort    release, panic = "abort"
//   checked  release with debug assertions and overflow checks
//   debug    release with the debug layer (debug_checks)
//   unwind   release, panic = "unwind" (nightly: the eh_personality lang item)
//
// Usage: bun nostd.ts [--runs N] [--regen]
const EXPECTED = "fixtures/nostd_mt.expected";
const i = process.argv.indexOf("--runs");
const RUNS = i > 0 ? Number(process.argv[i + 1]) : 50;
const DIR = "nostd-mt";
const variants = [
  { name: "abort", args: ["--release"], out: "release" },
  { name: "checked", args: ["--profile", "checked"], out: "checked" },
  { name: "debug", args: ["--release", "--features", "debug"], out: "release" },
  { name: "unwind", nightly: true, args: ["--profile", "unwind"], out: "unwind" },
];
let bad = 0;
const fail = (m: string) => { console.log("FAIL " + m); bad++; };
const want = process.argv.includes("--regen") ? null : await Bun.file(EXPECTED).text();
for (const v of variants) {
  const target = "target/" + v.name;
  // The nightly toolchain by path, so a rustc earlier on PATH cannot stand in.
  let env = process.env;
  if (v.nightly) {
    const w = Bun.spawnSync(["rustup", "which", "--toolchain", "nightly", "rustc"]);
    if (w.exitCode !== 0) { fail(v.name + ": no nightly toolchain (rustup toolchain install nightly)"); continue; }
    const rustc = w.stdout.toString().trim();
    env = { ...process.env, RUSTC: rustc, PATH: rustc.replace(/\/rustc$/, "") + ":" + process.env.PATH };
  }
  const b = Bun.spawnSync(["cargo", "build", "-q", ...v.args, "--target-dir", target], { cwd: DIR, env, stdout: "inherit", stderr: "inherit" });
  if (b.exitCode !== 0) { fail(v.name + ": build"); continue; }
  const bin = DIR + "/" + target + "/" + v.out + "/nostd-mt";
  const nm = Bun.spawnSync(["bun", "nostd-nm.ts", bin], { stdout: "inherit", stderr: "inherit" });
  if (nm.exitCode !== 0) fail(v.name + ": std symbols linked");
  if (want === null) {
    const r = Bun.spawnSync([bin]);
    await Bun.write(EXPECTED, r.stdout.toString());
    console.log("wrote " + EXPECTED + " from " + v.name);
    process.exit(r.exitCode ?? 1);
  }
  let ok = 0;
  const t0 = performance.now();
  for (let n = 0; n < RUNS; n++) {
    const r = Bun.spawnSync([bin]);
    const got = r.stdout.toString();
    if (r.exitCode === 0 && got === want) { ok++; continue; }
    fail(v.name + ": run " + (n + 1) + " exited " + (r.exitCode ?? r.signalCode) + "\n" + got + r.stderr.toString());
    break;
  }
  console.log(v.name + ": " + ok + "/" + RUNS + " runs match " + EXPECTED + " (" + Math.round((performance.now() - t0) / RUNS) + " ms/run)");
  if (v.name === "debug") {
    const r = Bun.spawnSync([bin, "doublefree"]);
    const err = r.stderr.toString();
    if (r.signalCode === "SIGABRT" && err.startsWith("rusty_alloc: error: double free of block ")) console.log("debug: double free on a spawned thread: reported and aborted");
    else fail("debug: double free: " + (r.exitCode ?? r.signalCode) + " " + err);
  }
}
console.log(bad ? "nostd: FAIL (" + bad + ")" : "nostd: ok");
process.exit(bad ? 1 : 0);
