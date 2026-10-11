// Build one release binary per allocator into bin/<name>.
// Usage: bun build.ts [names...]
import { mkdirSync, copyFileSync } from "fs";
export const ALL = ["system", "mimalloc", "rusty_alloc", "smalloc", "baby_mimalloc", "rlsf", "dlmalloc"];
const names = process.argv.slice(2).length ? process.argv.slice(2) : ALL;
mkdirSync("bin", { recursive: true });
let failed = [];
for (const n of names) {
  const p = Bun.spawnSync(["cargo", "build", "--release", "--no-default-features", "--features", n, "--target-dir", "target/" + n], { stdout: "inherit", stderr: "pipe" });
  if (p.exitCode !== 0) {
    failed.push(n);
    console.log("BUILD FAIL " + n + "\n" + p.stderr.toString().split("\n").filter(l => /error|warning: unused/.test(l) || l.startsWith("  ")).slice(0, 25).join("\n"));
    continue;
  }
  copyFileSync("target/" + n + "/release/ps-rusty_alloc-bench", "bin/" + n);
  console.log("built " + n);
}
if (failed.length) console.log("failed: " + failed.join(","));
