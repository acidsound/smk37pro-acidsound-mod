#!/usr/bin/env python3
"""Reconstruct r0/r1/r2 at every call site of the storage ABI wrappers in a
Ghidra listing, by forward symbolic execution from the containing function's
entry up to the call.

This answers handoff P0 #1: does each WRITE/READ site pass a fixed address or a
runtime-derived one, and what is the length?

Ghidra quirks this handles (learned the hard way, see §6.3 of the handoff):
  * the text column repeats the mnemonic: `mov  mov r0,#0x1c33260`
  * dst and src are separated by a SPACE, not a comma: `mov r0,#...`
  * the same instruction class prints both with and without '#':
    `add r0,r0,#0x3a0` and `add r1,r1,0x9200`
  * memory operands print bare, not bracketed: `ldw r1,r0,#0x160`
  * the first line of the file is a header row

Deliberately conservative: only simple, unambiguous writers are modelled. A
register written by anything else (a call, a store, arithmetic we cannot fold)
becomes `?` and stays `?`. Loops are NOT unrolled -- a linear pass over a
function body is an under-approximation of the true state, so a FIXED verdict is
trustworthy but UNKNOWN only means "not proven".

Verdicts:
  FIXED   - all three args folded to constants
  DERIVED - args resolved but at least one is a runtime pointer ([reg+off])
  UNKNOWN - the walk hit something we do not model
"""
import argparse
import gzip
import re
import sys

REC = ("baselines/v15/analysis/quarkslab/results/"
       "quarkslab-recursive-listing.tsv.gz")
EXH = ("baselines/v15/analysis/quarkslab/results/"
       "quarkslab-exhaustive-listing.tsv.gz")

STORAGE_WRAP = {"02004b02": "write", "02004870": "read", "02004a7a": "inner"}


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def load(path):
    """listing TSV -> {int addr: fields tuple}"""
    out = {}
    with open_text(path) as f:
        for line in f:
            fl = line.rstrip("\n").split("\t")
            if len(fl) < 4:
                continue
            try:
                a = int(fl[0], 16)
            except ValueError:
                continue          # header row
            out[a] = fl
    return out


UNKNOWN = "?"


def norm_imm(s):
    s = s.strip().lstrip("#")
    if s.lower().startswith("0x"):
        return int(s, 16)
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return None


class Sym:
    """constant int, ('mem', base, off), or unknown."""

    __slots__ = ("val", "unknown")

    def __init__(self, val=None, unknown=False):
        self.val = val
        self.unknown = unknown

    def __repr__(self):
        if self.unknown:
            return UNKNOWN
        if self.val is None:
            return "none"
        if isinstance(self.val, tuple):
            base, off = self.val[1], self.val[2]
            b = f"r{base}" if 0 <= base < 32 else f"{base:#x}"
            return f"[{b}+{off:#x}]"
        return f"{self.val:#x}" if self.val >= 0 else f"-{-self.val:#x}"

    def const(self):
        return self.val if isinstance(self.val, int) else None


def load_from(state, base, off):
    """Symbolic value of mem[base + off]."""
    bs = state.get(base, Sym())
    if isinstance(bs.val, tuple):
        return Sym(val=("mem", bs.val[1], bs.val[2] + off))
    if isinstance(bs.val, int):
        return Sym(val=("mem", bs.val, off))
    return Sym(unknown=True)


def add_sym(a, b):
    if isinstance(a, int) and isinstance(b, int):
        return a + b
    if isinstance(a, tuple) and isinstance(b, int):
        return ("mem", a[1], a[2] + b)
    if isinstance(b, tuple) and isinstance(a, int):
        return ("mem", b[1], b[2] + a)
    if isinstance(a, tuple) and isinstance(b, tuple) and a[1] == b[1]:
        return ("mem", a[1], a[2] + b[2])
    return None


WRITE_MNEMS = {
    "mov", "movz", "movn", "mova", "ldw", "lwu", "ld", "ldd", "sdb",
    "add", "addi", "sub", "subi", "andi", "ori", "xori", "and", "or", "xor",
    "nor", "sll", "srl", "sra", "ext", "sext", "zext", "mul", "mac", "div",
    "mod", "neg", "not", "clz", "ctz", "abs", "min", "max", "minu", "maxu",
    "asr", "sext16", "zext16", "sel", "orbs", "bf", "rotl", "rotr",
}
NO_WRITE = {
    "sw", "sb", "sh", "sdw", "nop", "break", "sync", "rts", "rti", "halt",
    "trap", "sysop", "flush", "wait", "yield", "push",
}


def parse_row(fields):
    """-> (mnemonic, operand-string) with the duplicated mnemonic stripped."""
    mnem = fields[3].strip().lower()
    text = fields[4].strip() if len(fields) > 4 else ""
    parts = text.split(None, 1)
    if parts and parts[0].lower() == mnem:
        text = parts[1] if len(parts) > 1 else ""
    return mnem, text


def toks(ops):
    ops = ops.replace(",", " ")
    return [t for t in ops.split() if t not in ("(", ")", "{", "}", "[", "]", "!")]


def reg(t):
    m = re.fullmatch(r"r(\d+)", t)
    return int(m.group(1)) if m else None


def step(state, mnem, ops):
    """Apply one instruction to the register state dict."""
    m = mnem
    if m in NO_WRITE:
        return
    if m == "pop":
        for t in toks(ops):
            rr = reg(t)
            if rr is not None:
                state[rr] = Sym(unknown=True)
        return
    if m == "call":
        for r in list(state):
            state[r] = Sym(unknown=True)
        return
    if m.startswith("b") or m in ("ja", "jr", "jrc", "ret"):
        return
    if m not in WRITE_MNEMS:
        return

    t = toks(ops)
    if not t:
        return
    d = reg(t[0])
    if d is None:
        return
    rest = t[1:]

    if m in ("ldw", "lwu", "ld", "ldd"):
        rs = [x for x in (reg(y) for y in rest) if x is not None]
        off = 0
        for y in rest:
            v = norm_imm(y)
            if v is not None:
                off = v
        state[d] = load_from(state, rs[0], off) if len(rs) == 1 else Sym(unknown=True)
        return
    if m == "sdb":
        state[d] = Sym(unknown=True)
        return

    if m in ("mov", "movz", "mova"):
        if len(rest) == 1:
            v = norm_imm(rest[0])
            if v is not None:
                state[d] = Sym(val=v)
                return
            rs = reg(rest[0])
            if rs is not None:
                state[d] = state.get(rs, Sym())
                return
        state[d] = Sym(unknown=True)
        return
    if m == "movn":
        v = norm_imm(rest[0]) if rest else None
        state[d] = Sym(val=-v) if v is not None else Sym(unknown=True)
        return

    regs = [x for x in (reg(y) for y in rest) if x is not None]
    imv = None
    for y in rest:
        v = norm_imm(y)
        if v is not None:
            imv = v
            break

    if m in ("add", "addi", "sub", "subi"):
        neg = m in ("sub", "subi")
        r = None
        if imv is not None and len(regs) == 1:
            r = add_sym(state.get(regs[0], Sym()).val, -imv if neg else imv)
        elif len(regs) == 2 and imv is None:
            a, b = state.get(regs[0], Sym()), state.get(regs[1], Sym())
            if not (a.unknown or b.unknown):
                r = add_sym(a.val, -b.val) if (neg and isinstance(b.val, int)) \
                    else (None if neg else add_sym(a.val, b.val))
        state[d] = Sym(val=r) if r is not None else Sym(unknown=True)
        return

    if m in ("andi", "ori", "xori", "and", "or", "xor", "nor"):
        if imv is None:
            state[d] = Sym(unknown=True)
            return
        if len(regs) == 1:
            cur = state.get(regs[0], Sym())
        elif len(regs) == 2:
            a, b = state.get(regs[0], Sym()), state.get(regs[1], Sym())
            if a.unknown or b.unknown:
                state[d] = Sym(unknown=True)
                return
            r = add_sym(a.val, b.val)
            cur = Sym(val=r) if r is not None else Sym(unknown=True)
        else:
            state[d] = Sym(unknown=True)
            return
        cv = cur.const() if not cur.unknown else None
        if cv is None:
            state[d] = Sym(unknown=True)
            return
        if m in ("andi", "and"):
            state[d] = Sym(val=cv & imv)
        elif m in ("ori", "or"):
            state[d] = Sym(val=cv | imv)
        elif m == "xori":
            state[d] = Sym(val=cv ^ imv)
        else:
            state[d] = Sym(unknown=True)
        return

    state[d] = Sym(unknown=True)


def func_of(row):
    if len(row) < 7:
        return "-"
    return row[6].strip().split("@")[0] or "-"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", default=REC)
    ap.add_argument("--exh", default=EXH)
    ap.add_argument("--target", default="02004b02,02004870,02004a7a")
    ap.add_argument("--only", help="restrict to one call site (hex address)")
    ap.add_argument("--context", type=int, default=0,
                    help="print the containing function for --only")
    args = ap.parse_args()

    rows = load(args.rec)
    if args.exh and args.exh != "none":
        for a, r in load(args.exh).items():
            rows.setdefault(a, r)
    addrs = sorted(rows)

    func_entry = {}
    cur = None
    for a in addrs:
        mnem, _ = parse_row(rows[a])
        if mnem == "push":
            cur = a
        func_entry[a] = cur

    targets = {t.strip().lower(): STORAGE_WRAP.get(t.strip().lower(), "?")
               for t in args.target.split(",")}

    hits = []
    for a in addrs:
        mnem, text = parse_row(rows[a])
        if mnem != "call":
            continue
        tm = re.search(r"(0x[0-9a-fA-F]{8})", text)
        if not tm:
            continue
        t = tm.group(1)[2:].lower()
        if t not in targets:
            continue
        if args.only and f"{a:08x}" != args.only.strip().lower().removeprefix("0x").rjust(8, "0"):
            continue
        start = func_entry[a]
        state = {}
        if start is not None:
            for b in addrs:
                if b >= a:          # the call clobbers r0-r2; stop before it
                    break
                if b < start:
                    continue
                bm, bo = parse_row(rows[b])
                step(state, bm, bo)
        syms = [state.get(i, Sym()) for i in (0, 1, 2)]
        known = [not s.unknown for s in syms]
        if all(known) and all(s.const() is not None for s in syms):
            kind = "FIXED"
        elif all(known):
            kind = "DERIVED"
        else:
            kind = "UNKNOWN"
        hits.append((a, func_of(rows[a]), t, syms[0], syms[1], syms[2], kind, start))

    print(f"# {len(hits)} call sites   targets={sorted(targets.items())}")
    print(f"{'site':<10} {'func':<16} {'tgt':<8} {'r0 (src/dst)':<16} "
          f"{'r1 (storage)':<16} {'r2 (len)':<10} kind")
    for a, f, t, s0, s1, s2, kind, start in hits:
        print(f"{a:08x}  {f[:16]:<16} {t:<8} {str(s0):<16} {str(s1):<16} "
              f"{str(s2):<10} {kind}")

    if args.context and args.only:
        for a, f, t, s0, s1, s2, kind, start in hits:
            print(f"\n== {a:08x} in {f} (entry {start and hex(start)}) ==")
            for b in addrs:
                if start is not None and b < start:
                    continue
                if b > a:
                    break
                bm, bo = parse_row(rows[b])
                print(f"  {b:08x}  {rows[b][1]:<12} {bm:<7} {bo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
