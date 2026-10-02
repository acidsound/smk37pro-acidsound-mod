#!/usr/bin/env python3
"""Resolve every storage-ABI call site into (RAM range, storage offset, length),
then intersect that with the access map of the global object g = 0x01c33260.

This is the persistence map.  It answers, for every byte the firmware writes to
(or reads from) non-volatile storage: "where does it come from / go to, and is
that RAM covered by a named field?"

It reuses the value lattice from smk37_g_fields.py (const / g-relative / memory
reference) so that `ldw r1,r0,#0x160` followed by `add r1,r1,0x9200` folds to
`storage base + 0x9200` -- the case the older smk37_callargs.py reported as
UNKNOWN.

Output
------
--table     one row per resolved call site
--gfield    g fields, each annotated: STORED / RESTORED / RAM-ONLY
--selftest  known-answer regressions
--json      machine-readable dump for the map generator

Deliberate limits (carry these into any conclusion):
  * linear forward replay, no unrolling -> UNRESOLVED means "not proven", and
    is an under-approximation.
  * a `call` invalidates only the volatile set (Jieli r4-r11 are callee-saved).
  * pre/post-index addressing (`sb r6,[++r0=r4]`) has no resolvable base.
"""
import argparse
import gzip
import json
import re
import sys

REC = ("baselines/v15/analysis/quarkslab/results/"
       "quarkslab-recursive-listing.tsv.gz")
EXH = ("baselines/v15/analysis/quarkslab/results/"
       "quarkslab-exhaustive-listing.tsv.gz")

G = 0x01C33260

# storage ABI (v15).  read(dst, storage, len) / write(src, storage, len)
ABI = {
    0x02004b02: ("write", 3),
    0x02004870: ("read", 3),
    0x02004a7a: ("inner", 3),
}

# quarkslab prefixes some forms with '_' (`_lw`, `_lb.z`, `_sw`). `_lw` is a
# plain load and MUST be in here: `FUN_02005FAC` reloads the storage base with
# `_lw r1,[r4+0x0]` immediately before its 8 bulk writes, and missing it left
# 16 of the 69 sites unresolved -- the single largest cause.
LD = {"ldw", "lw", "lwu", "ld", "ldd", "lb.z", "lh.z", "lbz", "lhz", "lbu",
      "lhu", "lb", "lh", "_lw", "_lb.z", "_lb", "_lh", "_lh.z", "_ldw"}
ST = {"sw", "sb", "sh", "sdw", "_sw", "_sb", "_sh", "sdb"}
BRACKETED = re.compile(
    r"\[\s*(r\d+)\s*(?:([+-])\s*(#?(?:0x[0-9a-fA-F]+|\d+)))?\s*\]")
CALLTO = re.compile(r"(0x[0-9a-fA-F]{8})")

WRITE_MNEMS = {
    "mov", "movz", "movn", "mova", "ldw", "lwu", "ld", "ldd",
    "add", "addi", "sub", "subi", "andi", "ori", "xori", "and", "or",
    "xor", "neg", "not", "clz", "ctz", "abs", "min", "max", "minu", "maxu",
    "sext", "zext", "sext16", "zext16", "ext", "orbs",
    "uxtb", "mul", "mac", "lsl", "sll", "lsr", "srl", "asr", "sra",
}
VOLATILE = set(range(0, 4)) | set(range(12, 16))


# ---------------------------------------------------------------- plumbing
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
    if s is None:
        return None
    s = s.strip().lstrip("#").rstrip("]")
    m = re.fullmatch(r"(-?)0x([0-9a-fA-F]+)", s)
    if m:
        v = int(m.group(2), 16)
        return -v if m.group(1) else v
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return None


# Register-indexed addressing: `[r0+r1<<2]`, `[rX + rY<<N]`.  The base is the
# FIRST register; the second is a scaled index.  Returning the wrong one here
# makes the tool invent a pointer (it reported `ptr(mem[0xc55])` for a settings
# table access), which is how a tool bug becomes a published "finding".
# Any bracket expression containing TWO registers is dynamically addressed,
# whether or not it is scaled: `[r0+r1<<2]` (scaled) and `[r0+r5]` (plain).
# Both make the effective offset runtime-dependent.  Guessing produced a fake
# storage pointer (`ptr(mem[0x1])`) on exactly the second form.
BRACKET_ANY = re.compile(r"\[([^\]]*)\]")
REG_TOK = re.compile(r"r\d+")


def mem_base_off(m, tk):
    """(base_reg, off) for a load/store.

    Returns (None, off) when the addressing is not statically resolvable, so
    the caller records UNRESOLVED rather than inventing a pointer.  Two rules:
      * the base register is the FIRST register inside the brackets;
      * if the brackets contain a second register, the offset is dynamic and
        must not be folded into an address.
    """
    joined = " ".join(tk)

    mb = BRACKET_ANY.search(joined)
    if mb:
        inner = mb.group(1)
        regs_in = REG_TOK.findall(inner)
        if not regs_in:
            return None, 0
        base_reg = reg(regs_in[0])
        if len(regs_in) > 1:
            return base_reg, 0      # dynamic offset -- do not invent one
        off = norm_imm(inner.replace(regs_in[0], "").strip())
        if off is None:
            off = 0
        return base_reg, off

    regs = [reg(x) for x in tk]
    regs = [x for x in regs if x is not None]
    off = 0
    for x in tk:
        v = norm_imm(x)
        if v is not None:
            off = v
    if not regs:
        return None, off
    return (regs[-1] if m in LD else
            (regs[1] if len(regs) > 1 else regs[0])), off


# ------------------------------------------------------------- value lattice
class Val:
    __slots__ = ("kind", "val")

    def __init__(self, kind, val=None):
        self.kind = kind          # 'c' const | 'g' g-relative | 'm' memref | 'u'
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
        """A memory reference: mem[r + off].  Used for the *result* of a load.

        This is deliberately NOT the same as Val.g(): loading the word at
        g+0x160 yields a RUNTIME pointer (a storage base), not an address
        inside g.  Collapsing the two made r1 fold to `g+0x9360` and mislabel
        every storage offset as g-relative.
        """
        return Val("m", (r, off))

    @staticmethod
    def ptr(desc):
        """A runtime pointer value with unknown numeric value.

        desc is a provenance string, e.g. 'mem[g+0x160]', kept so the map can
        still say *which* field a storage base came from.
        """
        return Val("p", desc)

    def as_int(self):
        return self.val if self.kind == "c" else None

    def gk(self):
        return self.val if self.kind == "g" else None

    def is_unknown(self):
        return self.kind == "u"

    def __repr__(self):
        return {"c": lambda: f"{self.val:#x}",
                "g": lambda: f"g+{self.val:#x}",
                "m": lambda: f"[r{self.val[0]}{self.val[1]:+#x}]",
                "p": lambda: f"ptr({self.val})",
                "u": lambda: "?"}[self.kind]()


def load_from(state, base, off):
    """Result of `ldw Rd,[base+off]`.

    This is a *value read out of memory*, i.e. a pointer whose numeric content
    is unknown to us.  It is NOT an address we can compute, and it is NOT
    g-relative.  Provenance is preserved so the map can name the source field.
    """
    b = state.get(base, Val.unknown())
    if b.kind == "g":
        return Val.ptr(f"mem[g+{b.val + off:#x}]")
    if b.kind == "c":
        return Val.ptr(f"mem[{b.val + off:#x}]")
    if b.kind == "m":
        return Val.ptr(f"mem[r{b.val[0]}{b.val[1] + off:+#x}]")
    if b.kind == "p":
        return Val.ptr(f"mem[{b.val}]")
    return Val.unknown()


def add_vals(a, b):
    if a.kind == "c" and b.kind == "c":
        return Val.const(a.val + b.val)
    if a.kind == "p" and b.kind == "c":
        return Val.ptr(f"{a.val}+{b.val:+#x}")
    if a.kind == "c" and b.kind == "p":
        return Val.ptr(f"{b.val}+{a.val:+#x}")
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


def step(state, m, tk):
    if m == "call":
        for r in VOLATILE:
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
        base, off = mem_base_off(m, tk)
        state[d] = load_from(state, base, off) if base is not None \
            else Val.unknown()
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
                state[d] = Val.g(0) if imv == G else Val.const(imv)
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
        # Jieli uses TWO-operand arithmetic: `add rd,rs` means rd += rs, and
        # `add rd,#imm` (single operand) means rd += imm.  Treating the two
        # operand form as rd = rs destroyed every computed pointer -- e.g. at
        # 0x02026d90 `add r1,r2` (really r1 += r2) wiped the r1 that
        # 0x02026d8c had just loaded with *(g+0x160).
        if imv is None and len(regs) == 1:
            r = add_vals(state.get(d, Val.unknown()),
                         state.get(regs[0], Val.unknown()))
            state[d] = r if r is not None else Val.unknown()
            return
        r = None
        if imv is not None and len(regs) == 1:
            r = add_vals(state.get(regs[0], Val.unknown()),
                         Val.const(-imv if neg else imv))
        elif imv is None and len(regs) == 2:
            a = state.get(regs[0], Val.unknown())
            b = state.get(regs[1], Val.unknown())
            if a.kind != "u" and b.kind != "u":
                r = add_vals(a, b)
                if r is not None and neg and b.kind == "c":
                    if a.kind == "c":
                        r = Val.const(a.val - b.val)
                    elif a.kind == "g":
                        r = Val.g(a.val - b.val)
                    elif a.kind == "p":
                        r = Val.ptr(f"{a.val}-{b.val:#x}")
                    elif a.kind == "m":
                        r = Val.mem(a.val[0], a.val[1] - b.val)
        state[d] = r if r is not None else Val.unknown()
        return

    # `uxtb rd,rs` / `sext rd,rs` -- a narrowing cast of a pointer offset.
    # Keep provenance: the value is still "derived from" rs.
    if m in ("uxtb", "sext", "zext", "sext16", "zext16", "uxtb16"):
        if len(regs) == 1:
            state[d] = state.get(regs[0], Val.unknown())
            return
        state[d] = Val.unknown()
        return

    # `lsl/lsr rd,rs,#sh` -- shifts.  Keep provenance for pointer-ish values
    # (index<<5 == bank*32 in the record formula).
    if m in ("lsl", "sll", "lsr", "srl", "asr", "sra") and imv is not None \
            and len(regs) == 1:
        src = state.get(regs[0], Val.unknown())
        if src.kind == "c":
            v = src.val
            if m in ("lsl", "sll"):
                state[d] = Val.const(v << imv)
            elif m in ("lsr", "srl"):
                state[d] = Val.const(v >> imv)
            else:
                state[d] = Val.const(v)
        elif src.kind in ("p", "g"):
            op = "<<" if m in ("lsl", "sll") else ">>"
            state[d] = Val.ptr(f"{src.val}{op}{imv}")
        else:
            state[d] = Val.unknown()
        return

    # `mul rd,rs,#imm` -- if rs is a pointer-ish value keep provenance so the
    # storage offset (e.g. index*0xa3) stays attributable to its base field.
    if m in ("mul", "mac") and imv is not None and len(regs) == 1:
        src = state.get(regs[0], Val.unknown())
        if src.kind in ("p", "g"):
            state[d] = Val.ptr(f"{src.val}*{imv:#x}")
        elif src.kind == "c":
            state[d] = Val.const(src.val * imv)
        else:
            state[d] = Val.unknown()
        return

    if m in ("andi", "ori", "xori", "and", "or", "xor") and imv is not None:
        if len(regs) == 1:
            cur = state.get(regs[0], Val.unknown())
        elif len(regs) == 2:
            a = state.get(regs[0], Val.unknown())
            b = state.get(regs[1], Val.unknown())
            cur = add_vals(a, b) if a.kind != "u" and b.kind != "u" \
                else Val.unknown()
        else:
            cur = Val.unknown()
        cv = cur.as_int() if cur.kind == "c" else None
        if cv is None:
            state[d] = Val.unknown()
        elif m in ("andi", "and"):
            state[d] = Val.const(cv & imv)
        elif m in ("ori", "or"):
            state[d] = Val.const(cv | imv)
        else:
            state[d] = Val.const(cv ^ imv)
        return

    state[d] = Val.unknown()


# ------------------------------------------------------------------- replay
def replay(rows, want_calls=True):
    """Single forward pass.  Returns (sites, g_access).

    sites:     list of resolved ABI call sites
    g_access:  dict g-relative offset -> {"LD": n, "ST": n, "sites": [...]}
    """
    addrs = sorted(rows)
    state = {}
    sites = []
    g_access = {}

    for a in addrs:
        m, t = parse(rows[a])
        tk = toks(t)
        if not tk:
            continue

        # --- record g-relative memory accesses (before stepping) ---
        if m in LD or m in ST:
            base, off = mem_base_off(m, tk)
            if base is not None:
                b = state.get(base, Val.unknown())
                k = None
                if b.kind == "g":
                    k = b.val + off
                elif b.kind == "c" and G <= b.val < G + 0x40000:
                    k = b.val - G
                if k is not None:
                    e = g_access.setdefault(k, {"LD": 0, "ST": 0,
                                                "w": set(), "sites": []})
                    e["LD" if m in LD else "ST"] += 1
                    e["w"].add(4 if m in ("ldw", "lw", "lwu", "ld", "sw",
                                          "sdw", "_sw", "sdb", "ldd")
                               else 2 if m in ("sh", "_sh") else 1)
                    e["sites"].append(a)

        # --- ABI call sites: read args, then let the call clobber ---
        if want_calls and m == "call":
            tm = CALLTO.search(t)
            if tm:
                tgt = int(tm.group(1), 16)
                if tgt in ABI:
                    kind, _ = ABI[tgt]
                    r0 = state.get(0, Val.unknown())
                    r1 = state.get(1, Val.unknown())
                    r2 = state.get(2, Val.unknown())
                    sites.append({
                        "addr": a, "target": tgt, "kind": kind,
                        "r0": repr(r0), "r1": repr(r1),
                        "len": repr(r2),
                        "r0_kind": r0.kind, "r1_kind": r1.kind,
                        "r2_kind": r2.kind,
                        "r0_val": r0.val, "r1_val": r1.val,
                        "r2_val": r2.val,
                        "func": (rows[a][6].strip().split("@")[0]
                                 if len(rows[a]) > 6 else "-"),
                    })
        step(state, m, tk)

    return sites, g_access


def describe_ram(v):
    """Human/JSON form of an r0 (RAM side) value."""
    if v["r0_kind"] == "c":
        a = v["r0_val"]
        return {"kind": "abs", "addr": a,
                "g_offset": (a - G) if G <= a < G + 0x40000 else None}
    if v["r0_kind"] == "g":
        return {"kind": "g", "g_offset": v["r0_val"],
                "addr": G + v["r0_val"]}
    if v["r0_kind"] == "m":
        return {"kind": "memref", "reg": v["r0_val"][0],
                "off": v["r0_val"][1]}
    return {"kind": "unknown"}


def describe_storage(v):
    """r1 = storage base pointer + offset."""
    if v["r1_kind"] == "p":
        return {"kind": "runtime_ptr", "provenance": v["r1_val"]}
    if v["r1_kind"] == "m":
        base_reg, boff = v["r1_val"]
        return {"kind": "memref", "base_reg": base_reg, "base_off": boff}
    if v["r1_kind"] == "c":
        return {"kind": "abs", "addr": v["r1_val"]}
    if v["r1_kind"] == "g":
        return {"kind": "g_direct", "g_offset": v["r1_val"]}
    return {"kind": "unknown"}


# ------------------------------------------------------------------- output
def cmd_table(rows, out):
    sites, _ = replay(rows)
    print(f"# {len(sites)} storage-ABI call sites")
    hdr = (f"{'site':<11} {'kind':<6} {'func':<15} {'RAM (r0)':<22} "
           f"{'storage (r1)':<20} {'len':<12} resolved")
    print(hdr)
    for v in sites:
        ram = describe_ram(v)
        sto = describe_storage(v)
        ln = f"{v['r2_val']:#x}" if v["r2_kind"] == "c" else "?"
        ok = (v["r0_kind"] in ("c", "g")
              and v["r1_kind"] in ("m", "p") and v["r2_kind"] == "c")
        ram_s = (f"{ram['addr']:#x}" if "addr" in ram
                 else f"g+{ram['g_offset']:#x}" if ram["kind"] == "g"
                 else ram["kind"])
        if sto["kind"] == "runtime_ptr":
            sto_s = sto["provenance"]
        elif sto["kind"] == "memref":
            sto_s = f"[r{sto['base_reg']}{sto['base_off']:+#x}]"
        else:
            sto_s = sto["kind"]
        print(f"{v['addr']:#011x} {v['kind']:<6} {v['func'][:15]:<15} "
              f"{ram_s:<22} {sto_s:<20} {ln:<12} {'YES' if ok else 'no'}")
    return 0


def cmd_gfield(rows, out):
    sites, g_access = replay(rows)
    persisted_st, persisted_ld = {}, {}
    for v in sites:
        ram = describe_ram(v)
        if ram.get("g_offset") is None:
            continue
        tgt = persisted_st if v["kind"] == "write" else persisted_ld
        e = tgt.setdefault(ram["g_offset"],
                           {"len": v["r2_val"], "sites": [],
                            "storage": describe_storage(v)})
        e["sites"].append(v["addr"])

    print(f"# g = {G:#x}; {len(g_access)} fields accessed, "
          f"{len(persisted_st)} written to storage, "
          f"{len(persisted_ld)} restored from storage\n")
    print(f"{'g+off':<11} {'VA':<12} {'LD':>4} {'ST':>4} {'w':<5} "
          f"{'STORED len/sites':<26} RESTORED")
    for off in sorted(g_access):
        e = g_access[off]
        ws = ",".join(str(x) for x in sorted(e["w"]))
        st = ""
        if off in persisted_st:
            p = persisted_st[off]
            n = p["len"] if isinstance(p["len"], int) else "?"
            st = f"w:{n}@{len(p['sites'])}site"
        ld = ""
        if off in persisted_ld:
            p = persisted_ld[off]
            n = p["len"] if isinstance(p["len"], int) else "?"
            ld = f"r:{n}@{len(p['sites'])}site"
        print(f"g+{off:#08x}  {G+off:#010x} {e['LD']:>4} {e['ST']:>4} "
              f"{ws:<5} {st:<26} {ld}")
    return 0


KNOWN = [
    # (site, kind, r0 expectation, r2)  -- read by hand from the listing
    (0x02005528, "write", "g", 0x9),      # FUN_02005512 selection save
    (0x02005f0e, "read", "g", 0x80),      # boot flag table read
    (0x02005f20, "read", "g", 0x9),       # boot selection read
    (0x02026da6, "write", "g", 0xa3),     # official SAVE raw record
    (0x02026dd0, "write", "g", 0x80),     # official SAVE flag table
]
FORBIDDEN = [
    # store base is inside the brackets -- r0 must never be read as the base
    ("0x02005eee is a store, not an ABI call", None, None, None),
]


def cmd_selftest(rows):
    sites, _ = replay(rows)
    by = {v["addr"]: v for v in sites}
    print(f"# self-test: {len(sites)} call sites discovered")
    failures = []
    for site, kind, r0kind, length in KNOWN:
        v = by.get(site)
        if v is None:
            failures.append(f"{site:#x} missing from site list")
            print(f"  [FAIL] {site:#x} {kind:<5} not discovered")
            continue
        ok = v["kind"] == kind and v["r0_kind"] == r0kind and \
            v["r2_val"] == length
        print(f"  [{'ok  ' if ok else 'FAIL'}] {site:#x} {kind:<5} "
              f"r0={v['r0']} r1={v['r1']} len={v['len']}")
        if not ok:
            failures.append(f"{site:#x}: got kind={v['kind']} "
                            f"r0={v['r0_kind']} len={v['r2_val']}, "
                            f"want {kind}/{r0kind}/{length:#x}")
    # negative: an ABI call site must never be attributed the store's base reg
    bad = [v for v in sites if v["r0_kind"] == "u" and v["r2_kind"] == "c"
           and v["kind"] == "write"]
    print(f"  [ok  ] unresolved-but-typed writes present: {len(bad)} "
          f"(expected, not a failure)")
    if failures:
        print(f"\nSELF-TEST FAIL: {len(failures)}/{len(KNOWN)}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"\nSELF-TEST PASS: {len(KNOWN)}/{len(KNOWN)}")
    return 0


def cmd_json(rows, out):
    sites, g_access = replay(rows)
    doc = {
        "g": G,
        "sites": [
            {"addr": f"0x{v['addr']:08x}", "kind": v["kind"],
             "func": v["func"],
             "ram": describe_ram(v), "storage": describe_storage(v),
             "len": (v["r2_val"] if v["r2_kind"] == "c" else None),
             "r0_kind": v["r0_kind"], "r1_kind": v["r1_kind"],
             "r2_kind": v["r2_kind"]}
            for v in sites
        ],
        "g_fields": [
            {"off": f"{off}", "off_hex": f"{off & 0xFFFFFFFF:#010x}",
             "va": f"0x{G+off:08x}",
             "LD": e["LD"], "ST": e["ST"], "w": sorted(e["w"]),
             "sites": [f"0x{s:08x}" for s in e["sites"]],
             "negative": off < 0}
            for off, e in sorted(g_access.items())
        ],
    }
    with open(out, "w") as f:
        json.dump(doc, f, indent=1)
    print(f"wrote {out}: {len(doc['sites'])} sites, "
          f"{len(doc['g_fields'])} g fields")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", default=REC)
    ap.add_argument("--exh", default=EXH)
    ap.add_argument("--table", action="store_true")
    ap.add_argument("--gfield", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", metavar="PATH")
    args = ap.parse_args()

    rows = load([args.rec, args.exh])
    if args.selftest:
        return cmd_selftest(rows)
    if args.json:
        return cmd_json(rows, args.json)
    if args.gfield:
        return cmd_gfield(rows, None)
    return cmd_table(rows, None)


if __name__ == "__main__":
    sys.exit(main())
