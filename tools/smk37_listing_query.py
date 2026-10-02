#!/usr/bin/env python3
"""Extract instruction ranges / function bodies from a Ghidra listing TSV(.gz).

Listing TSV format: address \\t bytes \\t length \\t mnemonic \\t text \\t flow_type \\t function
Addresses are lowercase hex without 0x. max-address space.

Usage:
  # address range
  tools/smk37_listing_query.py --rec <listing.tsv.gz> --range 02005500:02005600
  # all rows belonging to a function (matched on the `function` column)
  tools/smk37_listing_query.py --rec <listing.tsv.gz> --func 02005512
  # xrefs: which rows reference a given target address (call/branch text match)
  tools/smk37_listing_query.py --rec <listing.tsv.gz> --xref 02004b02
  # raw bytes for a range (reads the binary, not the listing)
  tools/smk37_listing_query.py --bin app.bin --bytes 0201da00:0201dc00
"""
import argparse
import gzip
import re
import sys

DEFAULT_REC = ("baselines/v15/analysis/quarkslab/results/"
               "quarkslab-recursive-listing.tsv.gz")
DEFAULT_EXH = ("baselines/v15/analysis/quarkslab/results/"
               "quarkslab-exhaustive-listing.tsv.gz")


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def norm(s):
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def parse_range(spec):
    if ":" in spec:
        a, b = spec.split(":", 1)
    elif "-" in spec[1:]:
        a, b = spec.split("-", 1)
    else:
        a = b = spec
    return int(norm(a), 16), int(norm(b), 16)


def row_addr(fields):
    try:
        return int(fields[0], 16)
    except ValueError:
        return None


def is_row(fields):
    return len(fields) >= 4 and row_addr(fields) is not None


def addr(fields):
    """int address of a listing row (0 for headers/blank lines)."""
    a = row_addr(fields)
    return 0 if a is None else a


def fmt(fields):
    addr, byts, length, mnem, text = fields[0], fields[1], fields[2], fields[3], fields[4]
    flow = fields[5] if len(fields) > 5 else ""
    func = fields[6] if len(fields) > 6 else ""
    out = f"{addr}  {byts:<12} {mnem:<8}"
    if text:
        out += f" {text}"
    if flow:
        out += f"   [{flow}]"
    if func:
        out += f"   ; {func}"
    return out


def cmd_range(args, paths):
    lo, hi = parse_range(args.range)
    hits = 0
    seen = set()
    for p in paths:
        with open_text(p) as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if not is_row(fields):
                    continue
                a = addr(fields)
                if lo <= a <= hi and a not in seen:
                    seen.add(a)
                    print(fmt(fields))
                    hits += 1
    if not hits:
        print(f"(no rows in {args.range})", file=sys.stderr)


def cmd_func(args, paths):
    target = norm(args.func)
    # two passes: collect the function label, then print its rows
    want = None
    for p in paths:
        with open_text(p) as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if len(fields) < 7 or not is_row(fields):
                    continue
                func = fields[6].strip().lower().split("@")[0]
                # NB: the function column is lower-cased, so the FUN_ prefix
                # must be lower-case too or every lookup misses.
                if func in (target, "fun_" + target):
                    want = func
                    break
        if want:
            break
    if not want:
        print(f"(function {target} not found in listings)", file=sys.stderr)
        return
    lo = hi = None
    for p in paths:
        with open_text(p) as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if len(fields) < 7 or not is_row(fields):
                    continue
                if fields[6].strip().lower().split("@")[0] != want:
                    continue
                a = addr(fields)
                if lo is None or a < lo:
                    lo = a
                if hi is None or a > hi:
                    hi = a
    if lo is None or hi is None:
        print(f"(no rows for {want})", file=sys.stderr)
        return
    print(f"== {want}  rows {lo:08x}..{hi:08x}  span={hi-lo} ==")
    # print the body directly; --range is not set when invoked via --func
    seen = set()
    for p in paths:
        with open_text(p) as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if len(fields) < 4 or not is_row(fields):
                    continue
                a = addr(fields)
                # both listings usually cover the same rows; print each once
                if lo <= a <= hi and a not in seen:
                    seen.add(a)
                    print(fmt(fields))


def cmd_xref(args, paths):
    target = norm(args.xref)
    pat = re.compile(r"\b" + re.escape(target) + r"\b", re.IGNORECASE)
    n = 0
    seen = set()
    for p in paths:
        with open_text(p) as f:
            for line in f:
                fields = line.rstrip("\n").split("\t")
                if len(fields) < 5 or not is_row(fields):
                    continue
                a = addr(fields)
                if pat.search(fields[4]) and a not in seen:
                    seen.add(a)
                    print(fmt(fields))
                    n += 1
    if not n:
        print(f"(no references to {target})", file=sys.stderr)


def cmd_bytes(args):
    lo, hi = parse_range(args.bytes)
    base = int(norm(args.base), 16) if args.base else 0x02000000
    with open(args.bin, "rb") as f:
        f.seek(lo - base)
        data = f.read(hi - lo + 1)
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{lo + i:08x}  {hexs:<47}  {txt}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rec", default=DEFAULT_REC)
    ap.add_argument("--exh", default=DEFAULT_EXH)
    ap.add_argument("--range", help="lo:hi address range")
    ap.add_argument("--func", help="function start address (0x optional)")
    ap.add_argument("--xref", help="target address to search for in the text column")
    ap.add_argument("--bin", help="binary for --bytes")
    ap.add_argument("--base", help="load address of --bin (default 0x02000000)")
    ap.add_argument("--bytes", help="lo:hi raw byte dump")
    args = ap.parse_args()

    if args.bytes:
        if not args.bin:
            ap.error("--bytes requires --bin")
        return cmd_bytes(args)

    paths = [args.rec]
    if args.exh and args.exh != "none" and args.exh != args.rec:
        paths.append(args.exh)
    paths = [p for p in paths if p and p != "none"]

    if args.func:
        cmd_func(args, paths)
    elif args.xref:
        cmd_xref(args, paths)
    elif args.range:
        cmd_range(args, paths)
    else:
        ap.error("need one of --range / --func / --xref / --bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
