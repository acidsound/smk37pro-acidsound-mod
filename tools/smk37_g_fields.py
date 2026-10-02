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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", default=REC)
    ap.add_argument("--exh", default=EXH)
    ap.add_argument("--range", default="0:0x40",
                    help="g-relative field range to summarise")
    ap.add_argument("--field", help="show every access to one g+offset")
    args = ap.parse_args()

    rows = load([args.rec, args.exh])
    addrs = sorted(rows)

    # gp[r] = K such that the register holds g+K, or None
    gp = {}
    # access[off] = [(addr, kind, width)]
    access = {}

    for a in addrs:
        m, t = parse(rows[a])
        tk = toks(t)
        if not tk:
            continue

        # `mov rD,#0x1c33260`  seeds the tracking
        if m in ("mov", "movz", "mova") and len(tk) == 2:
            d, s = reg(tk[0]), tk[1]
            if d is None:
                continue
            v = norm_imm(s)
            if v == G:
                gp[d] = 0
                continue
            if s in gp or (v is not None and v not in (None,)):
                if v is None and reg(s) is not None:
                    gp[d] = gp.get(reg(s))
                else:
                    gp[d] = None
                continue

        # `mov rD,rS` / `add rD,rS,#imm` propagation
        if m in ("mov", "movz", "mova", "add", "addi", "sub", "subi") and len(tk) >= 2:
            d, s = reg(tk[0]), reg(tk[1])
            if d is not None and s is not None:
                base = gp.get(s)
                imv = None
                for x in tk[1:]:
                    imv = norm_imm(x)
                    if imv is not None:
                        break
                if base is None:
                    gp[d] = None
                elif imv is not None and m in ("add", "addi"):
                    gp[d] = base + imv
                elif imv is not None and m in ("sub", "subi"):
                    gp[d] = base - imv
                else:
                    gp[d] = base
                continue

        # any instruction that writes a register kills its g-ness
        d = reg(tk[0])
        if d is not None and m not in LD and m not in ST and m != "call":
            gp[d] = None

        if m == "call":
            # Jieli ABI: r4-r11 are callee-saved, r0-r3/r12-r15 are volatile.
            # Killing everything here loses every access that follows a call
            # inside the same function -- which is most of them.  Only the
            # volatile set is invalidated.
            for r in list(gp):
                if r < 4 or r >= 12:
                    gp[r] = None

        # memory access [rX + off]
        if m in LD or m in ST:
            base_reg = None
            off = 0
            for x in tk:
                rr = reg(x)
                if rr is not None:
                    base_reg = rr
                else:
                    v = norm_imm(x)
                    if v is not None:
                        off = v
            if base_reg is None:
                continue
            k = gp.get(base_reg)
            if k is None:
                continue
            width = 4 if m in ("ldw", "lw", "lwu", "ld", "sw", "sdw", "_sw", "sdb") \
                else 2 if m in ("sh", "lhz", "_sh") else 1
            access.setdefault(k + off, []).append(
                (a, "ST" if m in ST else "LD", width, m))

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
    step = 4
    cur = lo
    while cur <= hi:
        if cur not in access:
            holes.append(cur)
        cur += step
    if holes:
        # merge consecutive
        runs = []
        s = holes[0]
        p = holes[0]
        for x in holes[1:]:
            if x == p + step:
                p = x
                continue
            runs.append((s, p))
            s = p = x
        runs.append((s, p))
        for s, e in runs:
            print(f"   g+{s:#08x} .. g+{e:#08x}   ({(e-s)//step+1} words)")
    else:
        print("   (none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
