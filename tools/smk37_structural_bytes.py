#!/usr/bin/env python3
"""Byte-level re-check of the "structural" function pairs.

The instruction-level classifier can call a pair structural for two reasons that
are not code changes: the decompiler attributed the same bytes to a different
function (boundary), or a relocated constant changed the instruction bytes
(relocation).  This tool ignores function boundaries entirely and reports the
byte-alignment blocks that fall inside the address span of the pair, with both
sides decoded from the listings.  A pair with no block inside its span is
byte-identical.
"""

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from smk37_app_diff_align import (  # noqa: E402
    AddressMap,
    build_blocks,
    collect_anchors,
    longest_increasing_subsequence,
)
from smk37_listing_diff import BASE, load_function, open_text  # noqa: E402


def load_instructions(listing: Path):
    """Return (sorted addresses, {address: (length, mnemonic, text)})."""
    table = {}
    with open_text(listing) as handle:
        handle.readline()
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7:
                continue
            table[int(parts[0], 16)] = (int(parts[2]), parts[3], parts[4])
    return sorted(table), table


def render_range(addresses, table, start: int, end: int, limit: int = 6):
    selected = [a for a in addresses if start <= a < end]
    out = []
    for address in selected[:limit]:
        _length, _mnemonic, text = table[address]
        out.append("%#x %s" % (address, text))
    if len(selected) > limit:
        out.append("... (+%d)" % (len(selected) - limit))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--base-listing", type=Path, required=True)
    parser.add_argument("--target-listing", type=Path, required=True)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--target-image", type=Path, required=True)
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--max-blocks", type=int, default=8)
    args = parser.parse_args(argv)

    base_image = args.base_image.read_bytes()
    target_image = args.target_image.read_bytes()
    chain = longest_increasing_subsequence(
        collect_anchors(base_image, target_image, args.k))
    forward = AddressMap(chain, args.k, BASE)
    blocks = [b for b in build_blocks(base_image, target_image, chain, args.k)
              if b["kind"] != "equal"]

    base_addresses, base_table = load_instructions(args.base_listing)
    target_addresses, target_table = load_instructions(args.target_listing)

    rows = list(csv.DictReader(open(args.pairs), delimiter="\t"))
    structural = [row for row in rows if row["verdict"] == "structural"]

    print("# %d non-equal byte blocks in the whole image" % len(blocks))
    print()
    for row in structural:
        base_entry = int(row["base_entry"], 16)
        target_entry = int(row["target_entry"], 16)
        base_rows = load_function(args.base_listing, base_entry)
        base_size = sum(base_table[item[0]][0] for item in base_rows
                        if item[0] in base_table)
        span_lo = base_entry
        span_hi = base_entry + base_size
        target_span_lo = forward(span_lo)
        target_span_hi = forward(span_hi - 1) + 1

        hits = []
        changed_base = 0
        for block in blocks:
            lo = BASE + block["src_start"]
            hi = BASE + block["src_end"]
            if hi <= span_lo or lo >= span_hi:
                continue
            hits.append(block)
            changed_base += min(hi, span_hi) - max(lo, span_lo)

        total = span_hi - span_lo
        print("=== v15 %#010x (%d B) -> v16 %#010x" % (base_entry, total, target_entry))
        print("    v16 span %#010x..%#010x | blocks inside: %d | changed base bytes: %d (%.2f%%)"
              % (target_span_lo, target_span_hi, len(hits), changed_base,
                 100.0 * changed_base / total if total else 0.0))
        for block in hits[:args.max_blocks]:
            src_lo = BASE + block["src_start"]
            src_hi = BASE + block["src_end"]
            dst_lo = BASE + block["dst_start"]
            dst_hi = BASE + block["dst_end"]
            print("    [%s] v15 %#x..%#x (%d B) | v16 %#x..%#x (%d B)"
                  % (block["kind"], src_lo, src_hi, block["src_len"],
                     dst_lo, dst_hi, block["dst_len"]))
            for line in render_range(base_addresses, base_table, src_lo, src_hi):
                print("        - %s" % line)
            for line in render_range(target_addresses, target_table, dst_lo, dst_hi):
                print("        + %s" % line)
        if len(hits) > args.max_blocks:
            print("    ... (+%d more blocks)" % (len(hits) - args.max_blocks))
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
