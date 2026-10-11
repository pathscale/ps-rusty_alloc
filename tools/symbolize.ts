// Symbolize a rusty_alloc debug report. The report prints each frame as a raw
// return address with its image and offset (it cannot symbolize without std):
//
//   rusty_alloc:     #2 0x0000000100003f2c (/path/to/app+0x3f2c)
//
// This rewrites each such line with the function and source line, the way
// the ASan offline symbolizer does:
//
//   rusty_alloc:     #2 0x0000000100003f2c in app::load config.rs:41 (/path/to/app+0x3f2c)
//
// macOS uses atos, Linux uses addr2line (binutils or llvm-addr2line). Build
// with debug info for file and line; without it only names are shown, and
// without a symbol table (strip) the line is left unchanged.
// Usage: bun tools/symbolize.ts [report.txt]   (reads stdin without a file)
import { readFileSync } from "fs";

const FRAME = /^(.*#\d+ )(0x[0-9a-fA-F]+) \((.+)\+(0x[0-9a-fA-F]+)\)\s*$/;
const text = process.argv[2] ? readFileSync(process.argv[2], "utf8") : await Bun.stdin.text();
const lines = text.split("\n");

type Frame = { line: number; head: string; addr: bigint; path: string; off: bigint };
const frames: Frame[] = [];
lines.forEach((l, i) => {
  const m = FRAME.exec(l);
  if (m) frames.push({ line: i, head: m[1], addr: BigInt(m[2]), path: m[3], off: BigInt(m[4]) });
});

const hex = (v: bigint) => "0x" + v.toString(16);
// Demangle Rust v0 symbols (the tools print them raw) and drop the per-item
// hash of legacy mangling ("::h0123456789abcdef").
const tidy = (s: string) =>
  s.replace(/\b_{0,2}_R[0-9A-Za-z_$.]+/g, m => demangleV0(m) ?? m).replace(/::h[0-9a-f]{16}/g, "").trim();

// Rust v0 mangling (RFC 2603), enough to name a frame: paths, impls,
// closures, generic arguments and the common types. Crate disambiguators are
// dropped, as rustc-demangle does in its short form.
function demangleV0(sym: string): string | null {
  const start = sym.indexOf("_R");
  const t = sym.slice(start + 2);
  let i = 0;
  const peek = () => t[i] ?? "";
  const eat = (c: string) => (t[i] === c ? (i++, true) : false);
  const fail = () => { throw new Error("v0"); };
  const b62 = (): number => {
    if (eat("_")) return 0;
    let v = 0;
    for (;;) {
      const c = t[i++];
      if (c === undefined) fail();
      if (c === "_") return v + 1;
      const d = c >= "0" && c <= "9" ? c.charCodeAt(0) - 48 : c >= "a" && c <= "z" ? c.charCodeAt(0) - 87 : c >= "A" && c <= "Z" ? c.charCodeAt(0) - 29 : fail();
      v = v * 62 + (d as number);
    }
  };
  const disamb = () => { if (eat("s")) b62(); };
  const ident = (): string => {
    const puny = eat("u");
    let n = "";
    while (peek() >= "0" && peek() <= "9") n += t[i++];
    if (!n) fail();
    eat("_");
    const id = t.slice(i, i + Number(n));
    i += Number(n);
    return puny ? "punycode{" + id + "}" : id;
  };
  const backref = <T,>(f: () => T): T => {
    const at = b62();
    const save = i;
    i = at;
    const r = f();
    i = save;
    return r;
  };
  const BASIC: Record<string, string> = {
    a: "i8", b: "bool", c: "char", d: "f64", e: "str", f: "f32", h: "u8", i: "isize", j: "usize",
    l: "i32", m: "u32", n: "i128", o: "u128", s: "i16", t: "u16", u: "()", v: "...", x: "i64",
    y: "u64", z: "!", p: "_",
  };
  const binder = () => { if (eat("G")) b62(); };
  const lifetime = () => { b62(); return "'_"; };
  const konst = (): string => {
    if (eat("B")) return backref(konst);
    if (eat("p")) return "_";
    const ty = t[i++];
    const neg = eat("n");
    let h = "";
    while (peek() !== "_") { if (!peek()) fail(); h += t[i++]; }
    i++;
    if (ty === "b") return h === "1" ? "true" : "false";
    const v = h ? BigInt("0x" + h) : 0n;
    return (neg ? "-" : "") + v.toString();
  };
  const generic = (): string => {
    if (eat("L")) return lifetime();
    if (eat("K")) return konst();
    return type();
  };
  const type = (): string => {
    const c = peek();
    if (BASIC[c] !== undefined && c !== "") { i++; return BASIC[c]; }
    if (eat("A")) { const e = type(); return "[" + e + "; " + konst() + "]"; }
    if (eat("S")) return "[" + type() + "]";
    if (eat("T")) { const a: string[] = []; while (!eat("E")) a.push(type()); return "(" + a.join(", ") + (a.length === 1 ? ",)" : ")"); }
    if (eat("R")) { if (eat("L")) lifetime(); return "&" + type(); }
    if (eat("Q")) { if (eat("L")) lifetime(); return "&mut " + type(); }
    if (eat("P")) return "*const " + type();
    if (eat("O")) return "*mut " + type();
    if (eat("F")) {
      binder();
      const unsafe_ = eat("U");
      let abi = "";
      if (eat("K")) abi = eat("C") ? "extern \"C\" " : "extern \"" + ident().replace(/_/g, "-") + "\" ";
      const a: string[] = [];
      while (!eat("E")) a.push(type());
      const r = type();
      return (unsafe_ ? "unsafe " : "") + abi + "fn(" + a.join(", ") + ")" + (r === "()" ? "" : " -> " + r);
    }
    if (eat("D")) {
      binder();
      const tr: string[] = [];
      while (!eat("E")) {
        let p = path();
        const binds: string[] = [];
        while (eat("p")) { const n = ident(); binds.push(n + " = " + type()); }
        if (binds.length) p = p.endsWith(">") ? p.slice(0, -1) + ", " + binds.join(", ") + ">" : p + "<" + binds.join(", ") + ">";
        tr.push(p);
      }
      if (eat("L")) lifetime();
      return "dyn " + tr.join(" + ");
    }
    if (eat("B")) return backref(type);
    return path();
  };
  const path = (): string => {
    const c = t[i++];
    switch (c) {
      case "C": disamb(); return ident();
      case "M": { disamb(); path(); return "<" + type() + ">"; }
      case "X": { disamb(); path(); const ty = type(); return "<" + ty + " as " + path() + ">"; }
      case "Y": { const ty = type(); return "<" + ty + " as " + path() + ">"; }
      case "N": {
        const ns = t[i++];
        const inner = path();
        let dis = 0;
        if (eat("s")) dis = b62() + 1;
        const id = ident();
        if (ns >= "a" && ns <= "z") return inner + "::" + id;
        const kind = ns === "C" ? "closure" : ns === "S" ? "shim" : ns;
        return inner + "::{" + kind + (id ? ":" + id : "") + "#" + (dis ? dis - 1 : 0) + "}";
      }
      case "I": {
        const p = path();
        const a: string[] = [];
        while (!eat("E")) a.push(generic());
        return p + "::<" + a.join(", ") + ">";
      }
      case "B": return backref(path);
      default: return fail();
    }
  };
  try {
    while (peek() >= "0" && peek() <= "9") i++;
    return path();
  } catch {
    return null;
  }
}

function have(cmd: string): boolean {
  return Bun.spawnSync(["sh", "-c", "command -v " + cmd]).exitCode === 0;
}

// An ELF executable that is not position independent (e_type EXEC) is
// symbolized at its absolute address, everything else at the image offset.
function elfIsExec(path: string): boolean {
  try {
    const b = readFileSync(path);
    return b[0] === 0x7f && b[1] === 0x45 && b[16] === 2 && b[17] === 0;
  } catch {
    return false;
  }
}

// One lookup per image. A return address points after the call, so look up
// the byte before it (as ASan does) to land on the line of the call itself.
function symbolize(path: string, fs: Frame[]): (string[] | null)[] {
  if (process.platform === "darwin") {
    const base = fs[0].addr - fs[0].off;
    const r = Bun.spawnSync(["atos", "-o", path, "-l", hex(base), ...fs.map(f => hex(f.addr - 1n))]);
    if (r.exitCode !== 0) return fs.map(() => null);
    const out = r.stdout.toString().split("\n");
    return fs.map((_, i) => {
      const s = out[i] ?? "";
      const m = /^(.*) \(in [^)]*\)(?: \(([^)]*)\))?/.exec(s);
      if (!m) return null;
      return [tidy(m[1]) + (m[2] ? " " + m[2] : "")];
    });
  }
  const tool = have("addr2line") ? "addr2line" : have("llvm-addr2line") ? "llvm-addr2line" : null;
  if (!tool) return fs.map(() => null);
  const abs = elfIsExec(path);
  const r = Bun.spawnSync([tool, "-a", "-f", "-C", "-i", "-p", "-e", path, ...fs.map(f => hex((abs ? f.addr : f.off) - 1n))]);
  if (r.exitCode !== 0) return fs.map(() => null);
  // -a -p prints "0xADDR: func at file:line", then " (inlined by) func at
  // file:line" for each caller the compiler inlined into it.
  const fmt = (s: string) => {
    const [fn, at] = s.split(" at ");
    const loc = at && !at.startsWith("??") ? " " + at.replace(/ \(discriminator \d+\)$/, "") : "";
    return tidy(fn) + loc;
  };
  const res: string[][] = [];
  for (const l of r.stdout.toString().split("\n")) {
    const top = /^0x[0-9a-fA-F]+: (.*)$/.exec(l);
    if (top) res.push([fmt(top[1])]);
    else if (l.startsWith(" (inlined by) ") && res.length) res[res.length - 1].push(fmt(l.slice(14)));
  }
  return fs.map((_, i) => {
    const s = res[i];
    return s && !s[0].startsWith("??") ? s : null;
  });
}

const byImage = new Map<string, Frame[]>();
for (const f of frames) {
  const k = f.path + "@" + hex(f.addr - f.off);
  if (!byImage.has(k)) byImage.set(k, []);
  byImage.get(k)!.push(f);
}
const repl = new Map<number, string>();
for (const fs of byImage.values()) {
  const syms = symbolize(fs[0].path, fs);
  fs.forEach((f, i) => {
    const s = syms[i];
    if (!s) return;
    const tail = " (" + f.path + "+" + hex(f.off) + ")";
    const addr = "0x" + f.addr.toString(16).padStart(16, "0");
    // Inlined calls keep the frame number; all but the outermost are marked.
    repl.set(f.line, s.map((x, j) => f.head + addr + " in " + x + (j < s.length - 1 ? " [inlined]" : "") + tail).join("\n"));
  });
}
process.stdout.write(lines.map((l, i) => repl.get(i) ?? l).join("\n"));
