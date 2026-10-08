#!/usr/bin/env python3
"""Enumerate every access to the global object at 0x01c33260 (v15 "g").

Why this exists
---------------
handoff 2026-10-03 §3.4 (persistence-s3) reduces to one question:

    is *(g+0x0000)  the same storage base as  *(g+0x160) ?

`FUN_02005fac` (the 151,320 B bulk save/load) uses `*(g+0x0000)`.
The record path (§3.2/§3.3 of the handoff) uses `*(g+0x160)` and
`*(g+0x164)`.  If they are the same base, storage extends to +0x279e3 and
the handoff's "+0x9209 closes the layout" conclusion collapses.  If they are
different, that conclusion survives but on different grounds.

Method
------
The listing never names `g` as an absolute address except in `mov r,#0x1c33260`.
Every other access reaches it as `reg + offset`, where `reg` was loaded from
`g` some number of instructions earlier.  So:

  1. forward-scan, tracking which registers currently hold `g + K`
  2. on any access `[rX + off]` where rX holds `g + K`, record
     `g + K + off`
  3. on `mov rX, rY` propagate, on `add rX, rY, #imm` propagate

This is a linear under-approximation (no unrolling).  A field that appears
only under a loop we failed to unroll may be missed -- so the report labels
coverage, not completeness.

ABI note: a `call` invalidates only the volatile registers (r0-r3, r12-r15).
r4-r11 survive a call by the Jieli calling convention, so their g-relative
value is preserved.  Getting this wrong silently drops most accesses that
follow a call inside a function -- which is the common case, not the edge case.

Usage
-----
  tools/smk37_g_fields.py                 # summary of g+0..g+0x40
  tools/smk37_g_fields.py --range 0:0x40  # per-field access detail
  tools/smk37_g_fields.py --field 0x160   # every access to one field
"""
import argparse
import gzip
import re
import sys

REC = ("baselines/v15/analysis/quarkslab/results/"
       "quarkslab-recursive-listing.tsv.gz")
EXH = ("baselines/v15/analysis/quarkslab/results/"
       "quarkslab-exhaustive-listing.tsv.gz")

G = 0x01c33260


def open_text(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") \
        else open(p, "r", errors="replace")


def load(paths):
    out = {}
    for p in paths:
        if not p or p == "none":
            continue
        with open_text(p) as f:
            for line in f:
                fl = line.rstrip("\n").split("\t")
                if len(fl) < 4:
                    continue
                try:
                    a = int(fl[0], 16)
                except ValueError:
                    continue
                out.setdefault(a, fl)
    return out


def parse(fl):
    m = fl[3].strip().lower()
    t = fl[4].strip() if len(fl) > 4 else ""
    parts = t.split(None, 1)
    if parts and parts[0].lower() == m:
        t = parts[1] if len(parts) > 1 else ""
    return m, t


def toks(ops):
    return [x for x in ops.replace(",", " ").split()
            if x not in ("(", ")", "{", "}", "[", "]", "!")]


def reg(t):
    m = re.fullmatch(r"r(\d+)", t)
    return int(m.group(1)) if m else None


def norm_imm(s):
    """Parse an immediate token. Returns None if it is not a clean literal.

    quarkslab sometimes glues the closing bracket onto the literal
    (`sw r0,[r1 + 0x4]`) after the bracket-strip pass, so tolerate that.
    """
    s = s.strip().lstrip("#").rstrip("]")
    m = re.fullmatch(r"(-?)0x([0-9a-fA-F]+)", s)
    if m:
        v = int(m.group(2), 16)
        return -v if m.group(1) else v
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return None


# access kinds
LD = {"ldw", "lw", "lwu", "ld", "lhz", "lhb", "lh", "lb", "lhu", "lbu"}
ST = {"sw", "sb", "sh", "sdw", "_sw", "_sb", "_sh", "sdb"}


class Val:
    """A register's tracked value.

    Kinds:
      'c'   constant int          -> `movz r0,#0x33bc`
      'g'   g-relative offset K   -> the register holds g+K
      'm'   memory ref (reg,off)  -> `ldw r1,r0,#0x160` with r0 = g
      'u'   unknown / not tracked
    """

    __slots__ = ("kind", "val")

    def __init__(self, kind, val=None):
        self.kind = kind
        self.val = val

    @staticmethod
    def unknown():
        return Val("u")

    @staticmethod
    def const(v):
        return Val("c", v)

    @staticmethod
    def g(k):
        return Val("g", k)

    @staticmethod
    def mem(r, off):
        return Val("m", (r, off))

    def as_const(self):
        """The integer value if this is a constant, else None."""
        return self.val if self.kind == "c" else None

    def __repr__(self):
        return {  "c": lambda: f"{self.val:#x}",
                 "g": lambda: f"g+{self.val:#x}",
                 "m": lambda: f"[r{self.val[0]}{self.val[1]:+#x}]",
                 "u": lambda: "?"}[self.kind]()


def mem_of(state, base, off):
    """Symbolic value of mem[base + off]."""
    b = state.get(base, Val.unknown())
    if b.kind == "c":
        return Val.const(b.val + off)
    if b.kind == "g":
        return Val.g(b.val + off)
    if b.kind == "m":
        return Val.mem(b.val[0], b.val[1] + off)
    return Val.unknown()


def add_vals(a, b):
    """Symbolic add; None when not representable."""
    if a.kind == "c" and b.kind == "c":
        return Val.const(a.val + b.val)
    if a.kind == "g" and b.kind == "c":
        return Val.g(a.val + b.val)
    if a.kind == "c" and b.kind == "g":
        return Val.g(b.val + a.val)
    if a.kind == "m" and b.kind == "c":
        return Val.mem(a.val[0], a.val[1] + b.val)
    if a.kind == "c" and b.kind == "m":
        return Val.mem(b.val[0], b.val[1] + a.val)
    if a.kind == "m" and b.kind == "m" and a.val[0] == b.val[0]:
        return Val.mem(a.val[0], a.val[1] + b.val[1])
    return None


WRITE_MNEMS = {
    "mov", "movz", "movn", "mova", "ldw", "lwu", "ld", "ldd",
    "add", "addi", "sub", "subi", "andi", "ori", "xori", "and", "or",
    "xor", "nor", "neg", "not", "clz", "ctz", "abs", "min", "max",
    "minu", "maxu", "sext", "zext", "sext16", "zext16", "ext", "orbs",
}
# mnemonics that write a register but are not modelled -> value becomes unknown
UNMODELLED_WRITE = {
    "sll", "srl", "sra", "asr", "mul", "mac", "div", "mod", "rotl", "rotr",
    "sel", "bf", "sdb",
}
CALLER_SAVED = set(range(0, 4)) | set(range(12, 16))


BRACKETED = re.compile(r"\[\s*(r\d+)\s*(?:\+\s*(#?0x[0-9a-fA-F]+|#?-?\d+))?\s*\]")


def mem_base_off(m, tk):
    """Return (base_reg, offset) for a load/store.

    The base register is the one INSIDE the brackets.  For `sw r0,[r6+0x160]`
    the data register r0 comes first and must NOT be mistaken for the base --
    that mistake made every store look like it targeted the destination
    register's value, producing both phantom g+0x0 writers and a missing
    g+0x160 writer.  Fall back to first-register only when there are no
    brackets at all (quarkslab prints some forms bracket-free).
    """
    joined = " ".join(tk)
    mb = BRACKETED.search(joined)
    if mb:
        base_reg = reg(mb.group(1))
        off = norm_imm(mb.group(2)) if mb.group(2) else 0
        if base_reg is not None:
            return base_reg, (off or 0)
    # bracket-free fallback: skip the leading data register for stores
    regs = [reg(x) for x in tk]
    regs = [x for x in regs if x is not None]
    off = 0
    for x in tk:
        v = norm_imm(x)
        if v is not None:
            off = v
    if not regs:
        return None, off
    base_reg = regs[-1] if m in LD else (regs[1] if len(regs) > 1 else regs[0])
    return base_reg, off


def step(state, m, tk):
    """Apply one instruction to `state` (dict reg -> Val)."""
    if m == "call":
        for r in CALLER_SAVED:
            state[r] = Val.unknown()
        return
    if m in ("push", "nop", "break", "sync", "rts", "rti"):
        return
    if m == "pop":
        for x in tk:
            rr = reg(x)
            if rr is not None:
                state[rr] = Val.unknown()
        return
    if m in LD:
        d = reg(tk[0])
        if d is None:
            return
        rs = [reg(x) for x in tk[1:]]
        rs = [x for x in rs if x is not None]
        off = 0
        for x in tk[1:]:
            v = norm_imm(x)
            if v is not None:
                off = v
        if len(rs) == 1:
            state[d] = mem_of(state, rs[0], off)
        else:
            state[d] = Val.unknown()
        return
    if m in ST:
        return

    d = reg(tk[0]) if tk else None
    if d is None:
        return
    if m not in WRITE_MNEMS:
        state[d] = Val.unknown()
        return

    rest = tk[1:]
    imv = None
    for x in rest:
        v = norm_imm(x)
        if v is not None:
            imv = v
            break
    regs = [x for x in (reg(y) for y in rest) if x is not None]

    if m in ("mov", "movz", "mova"):
        if len(rest) == 1:
            if imv is not None:
                state[d] = Val.const(imv) if imv != G else Val.g(0)
                return
            if regs:
                state[d] = state.get(regs[0], Val.unknown())
                return
        state[d] = Val.unknown()
        return
    if m == "movn":
        state[d] = Val.const(-imv) if imv is not None else Val.unknown()
        return

    if m in ("add", "addi", "sub", "subi"):
        neg = m in ("sub", "subi")
        r = None
        if imv is not None and len(regs) == 1:
            base = state.get(regs[0], Val.unknown())
            r = add_vals(base, Val.const(-imv if neg else imv))
        elif imv is None and len(regs) == 2:
            a = state.get(regs[0], Val.unknown())
            b = state.get(regs[1], Val.unknown())
            if a.kind != "u" and b.kind != "u":
                r = add_vals(a, b)
                if neg and r is not None and b.kind == "c":
                    r = Val.const(a.val - b.val) if a.kind == "c" \
                        else Val.g(a.val - b.val) if a.kind == "g" else None
        state[d] = r if r is not None else Val.unknown()
        return

    # logic ops: only fold when both sides are constants
    if m in ("andi", "ori", "xori", "and", "or", "xor"):
        if imv is None:
            state[d] = Val.unknown()
            return
        if len(regs) == 1:
            cur = state.get(regs[0], Val.unknown())
        elif len(regs) == 2:
            a = state.get(regs[0], Val.unknown())
            b = state.get(regs[1], Val.unknown())
            if a.kind != "u" and b.kind != "u":
                cur = add_vals(a, b)
                if cur is None:
                    cur = Val.unknown()
            else:
                cur = Val.unknown()
        else:
            cur = Val.unknown()
        if cur.kind != "c":
            state[d] = Val.unknown()
            return
        cv = cur.val
        if m in ("andi", "and"):
            state[d] = Val.const(cv & imv)
        elif m in ("ori", "or"):
            state[d] = Val.const(cv | imv)
        else:
            state[d] = Val.const(cv ^ imv)
        return

    state[d] = Val.unknown()


# Known answers, each read by hand from the v15 listing.  A tool that cannot
# reproduce these is broken -- this file already shipped one bug (store base
# register confusion) that a single fixture would have caught immediately.
KNOWN = [
    # (g-relative field, kind, site, why)
    (0x160, "ST", 0x02005eee,
     "boot producer: sw r0,[r6+0x160] -- base is r6 (=g), data is r0"),
    (0x164, "ST", 0x02005ef2,
     "boot producer: sw r5,[r6+0x164] -- read/mapping pointer"),
    (0x160, "LD", 0x0200551a,
     "FUN_02005512: ldw r1,r0,#0x160 with r0 = g"),
    (0x160, "LD", 0x02005f12,
     "boot selection read: ldw r1,r6,#0x160 with r6 = g"),
    (0x1d0, "ST", 0x02004f16,
     "boot: sw r0,[r6+0x1d0] with r6 = g"),
]

# Fields that must NOT appear.  Each was a real mistake at some point:
#   g+0x9200  -- `add r1,r1,0x9200` adds to a *memory* value (ldw result),
#                so it is a storage offset, not a g field.
#   g+0x3a0   -- `add r0,r0,#0x3a0` is address arithmetic, not an access.
FORBIDDEN = [
    (0x9200, "selection+0x9200 is a STORAGE offset from *(g+0x160), not a g field"),
    (0x3a0, "g+0x3a0 is reached by `add`, which produces an address, "
            "not a load/store the tool should record"),
]


def self_test(args):
    rows = load([args.rec, args.exh])
    addrs = sorted(rows)
    state = {}
    access = {}
    for a in addrs:
        m, t = parse(rows[a])
        tk = toks(t)
        if not tk:
            continue
        if m in LD or m in ST:
            base_reg, off = mem_base_off(m, tk)
            if base_reg is not None:
                b = state.get(base_reg, Val.unknown())
                k = None
                if b.kind == "g":
                    k = b.val + off
                elif b.kind == "c" and G <= b.val < G + 0x40000:
                    k = b.val - G
                if k is not None:
                    width = 4 if m in ("ldw", "lw", "lwu", "ld", "sw",
                                       "sdw", "_sw", "sdb") \
                        else 2 if m in ("sh", "lhz", "_sh") else 1
                    access.setdefault(k, []).append(
                        (a, "ST" if m in ST else "LD", width, m))
        step(state, m, tk)

    print(f"# self-test: {len(KNOWN)} known answers "
          f"({len(access)} g-relative fields discovered)")
    failures = []
    for field, kind, site, why in KNOWN:
        got = [(a, k) for a, k, _w, _m in access.get(field, [])]
        hit = any(a == site and k == kind for a, k in got)
        status = "ok  " if hit else "FAIL"
        print(f"  [{status}] g+{field:#06x} {kind} @ {site:#010x}  -- {why}")
        if not hit:
            have = ", ".join(f"{k}@{a:#x}" for a, k in got[:6]) or "(none)"
            failures.append(f"g+{field:#x} {kind}@{site:#x} missing; "
                            f"actual: {have}")
    for field, why in FORBIDDEN:
        got = access.get(field, [])
        status = "ok  " if not got else "FAIL"
        print(f"  [{status}] g+{field:#06x} must be ABSENT -- {why}")
        if got:
            failures.append(f"g+{field:#x} should be absent, got "
                            f"{len(got)} access(es), e.g. "
                            f"{got[0][0]:#x}")
    total = len(KNOWN) + len(FORBIDDEN)
    if failures:
        print(f"\nSELF-TEST FAIL: {len(failures)}/{total}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nSELF-TEST PASS: {total}/{total} "
          f"({len(KNOWN)} known + {len(FORBIDDEN)} negative)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", default=REC)
    ap.add_argument("--exh", default=EXH)
    ap.add_argument("--range", default="0:0x40",
                    help="g-relative field range to summarise")
    ap.add_argument("--field", help="show every access to one g+offset")
    ap.add_argument("--self-test", action="store_true",
                    help="run known-answer regressions and exit")
    args = ap.parse_args()

    if args.self_test:
        return self_test(args)

    rows = load([args.rec, args.exh])
    addrs = sorted(rows)
    state = {}
    access = {}

    for a in addrs:
        m, t = parse(rows[a])
        tk = toks(t)
        if not tk:
            continue

        # Record the g-relative target BEFORE stepping (a store defines no
        # register, so state is unaffected, but keep order for clarity).
        if m in LD or m in ST:
            base_reg, off = mem_base_off(m, tk)
            if base_reg is not None:
                b = state.get(base_reg, Val.unknown())
                k = None
                if b.kind == "g":
                    k = b.val + off
                elif b.kind == "c":
                    # an absolute RAM address equal to g+off is still g-relative
                    if b.val - G == off:
                        k = off
                    elif G <= b.val < G + 0x40000:
                        k = b.val - G
                if k is not None:
                    width = 4 if m in ("ldw", "lw", "lwu", "ld", "sw",
                                       "sdw", "_sw", "sdb") \
                        else 2 if m in ("sh", "lhz", "_sh") else 1
                    access.setdefault(k, []).append(
                        (a, "ST" if m in ST else "LD", width, m))

        step(state, m, tk)

    if args.field is not None:
        want = int(args.field, 16)
        print(f"# every access to g+{want:#x}")
        for off in sorted(access):
            if off != want:
                continue
            for a, kind, w, m in access[off]:
                print(f"  {a:#010x}  {kind} w={w}  {m}")
        return 0

    lo, hi = (int(x, 16) for x in args.range.split(":"))
    print(f"# g = {G:#x}   listing rows {len(rows)}")
    print(f"# summary for g+{lo:#x}..g+{hi:#x}")
    print(f"{'field':<12} {'VA':<12} {'LD':>5} {'ST':>5} {'w':>4}  first/last site")
    for off in sorted(access):
        if not (lo <= off <= hi):
            continue
        ld = [x for x in access[off] if x[1] == "LD"]
        st = [x for x in access[off] if x[1] == "ST"]
        ws = ",".join(sorted({str(x[2]) for x in access[off]}))
        sites = f"{min(x[0] for x in access[off]):#x}..{max(x[0] for x in access[off]):#x}"
        print(f"g+{off:#08x}  {G+off:#010x}  {len(ld):>5} {len(st):>5} {ws:>4}  {sites}")

    touched = sorted(o for o in access if lo <= o <= hi)
    print(f"\n# distinct fields in range touched: {len(touched)}")
    print(f"# NEVER-TOUCHED fields in range (under-approximation caveat applies):")
    holes = []
    stride = 4
    cur = lo
    while cur <= hi:
        if cur not in access:
            holes.append(cur)
        cur += stride
    if holes:
        # merge consecutive
        runs = []
        s = holes[0]
        p = holes[0]
        for x in holes[1:]:
            if x == p + stride:
                p = x
                continue
            runs.append((s, p))
            s = p = x
        runs.append((s, p))
        for s, e in runs:
            print(f"   g+{s:#08x} .. g+{e:#08x}   ({(e-s)//stride+1} words)")
    else:
        print("   (none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
