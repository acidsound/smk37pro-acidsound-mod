#!/usr/bin/env python3
"""Decide whether a "structural" function pair is a real code change or only a
function-boundary / relocation artefact.

Method: align the two instruction streams (tools/smk37_listing_diff.py), then take
every block that exists on one side only.  Each instruction of such a block is
looked up in the *other* image at the address produced by the byte alignment map,
and the two instruction texts are compared after both are rewritten into the v16
address space and normalised for formatting differences.

A block whose instructions are all found is not new code - the decompiler merely
attributed it to a different function.  Only blocks with genuinely missing or
different instructions count as a real change.
"""

import argparse
import csv
import difflib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from smk37_app_diff_align import (  # noqa: E402
    AddressMap,
    collect_anchors,
    longest_increasing_subsequence,
)
from smk37_listing_diff import (  # noqa: E402
    BASE,
    canonical,
    estimate_ram_shift,
    make_normaliser,
    open_text,
)


def tidy(text: str) -> str:
    """Remove the decompiler block annotations and spacing differences."""
    text = text.strip()
    while text.startswith("}"):
        text = text[1:].strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r",\s+", ",", text)
    return text


def load_index(listing: Path):
    """Return {address: (mnemonic, text, bytes)}."""
    index = {}
    with open_text(listing) as handle:
        handle.readline()
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7:
                continue
            index[int(parts[0], 16)] = (parts[3], parts[4], bytes.fromhex(parts[1]))
    return index


def load_function(listing: Path, entry: int):
    rows = []
    with open_text(listing) as handle:
        handle.readline()
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7 or parts[6] == "-":
                continue
            if int(parts[6].split("@")[-1], 16) != entry:
                continue
            rows.append((int(parts[0], 16), parts[3], parts[4]))
    rows.sort(key=lambda item: item[0])
    return rows


def lookup(index, address, key, other_key):
    """Find an instruction whose normalised text equals key near address."""
    for candidate in (address, address - 2, address + 2, address - 4, address + 4):
        item = index.get(candidate)
        if item is not None and other_key(item[1]) == key:
            return candidate, item, True
    return address, index.get(address), False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument("--base-listing", type=Path, required=True)
    parser.add_argument("--target-listing", type=Path, required=True)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--target-image", type=Path, required=True)
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--threshold", type=float, default=0.80)
    args = parser.parse_args(argv)

    base_image = args.base_image.read_bytes()
    target_image = args.target_image.read_bytes()
    chain = longest_increasing_subsequence(
        collect_anchors(base_image, target_image, args.k))
    forward = AddressMap(chain, args.k, BASE)
    backward = AddressMap([(d, s) for s, d in chain], args.k, BASE)
    base_len = len(base_image)

    print("# loading listings ...")
    base_index = load_index(args.base_listing)
    target_index = load_index(args.target_listing)

    rows = list(csv.DictReader(open(args.pairs), delimiter="\t"))
    structural = [row for row in rows if row["verdict"] == "structural"]

    print()
    print("%-12s %-12s %6s %6s  %-14s %s"
          % ("v15", "v16", "base_n", "tgt_n", "verdict", "one-sided blocks"))
    real_changes = []
    for row in structural:
        base_entry = int(row["base_entry"], 16)
        target_entry = int(row["target_entry"], 16)
        base_rows = load_function(args.base_listing, base_entry)
        target_rows = load_function(args.target_listing, target_entry)
        ram_shift = estimate_ram_shift(
            [(a, m, t) for a, m, t in base_rows],
            [(a, m, t) for a, m, t in target_rows])
        normalise15 = make_normaliser(forward, base_len, ram_shift)

        def key15(text):
            return tidy(canonical(normalise15(text)))

        def key16(text):
            return tidy(canonical(text))

        base_keys = [key15(item[2]) for item in base_rows]
        target_keys = [key16(item[2]) for item in target_rows]
        opcodes = difflib.SequenceMatcher(None, base_keys, target_keys,
                                          autojunk=False).get_opcodes()

        blocks = []
        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "equal":
                continue
            if tag in ("delete", "replace") and i2 > i1:
                blocks.append(("v15-only", base_rows[i1:i2], base_keys[i1:i2],
                               forward, target_index, key16))
            if tag in ("insert", "replace") and j2 > j1:
                blocks.append(("v16-only", target_rows[j1:j2], target_keys[j1:j2],
                               backward, base_index, key15))

        changed_blocks = 0
        block_notes = []
        pair_changes = []
        for label, items, keys, mapper, index, other_key in blocks:
            found = 0
            missing = []
            for (address, _mnemonic, _text), key in zip(items, keys):
                mapped = mapper(address)
                if mapped is None:
                    missing.append((address, None, "no mapping"))
                    continue
                _hit, item, ok = lookup(index, mapped, key, other_key)
                if ok:
                    found += 1
                else:
                    missing.append((address, mapped, item[1] if item else "not decoded"))
            ratio = found / float(len(items)) if items else 0.0
            block_notes.append((label, items[0][0], items[-1][0], len(items), ratio))
            if ratio < args.threshold:
                changed_blocks += 1
                pair_changes.append((label, items[0][0], items[-1][0], len(items),
                                     ratio, missing, items))

        verdict = "REAL CHANGE" if changed_blocks else "boundary only"
        rendered = ", ".join("%s %#x..%#x n=%d match=%.2f" % note for note in block_notes)
        print("%#010x   %#010x   %6d %6d  %-14s %s"
              % (base_entry, target_entry, len(base_rows), len(target_rows),
                 verdict, rendered[:64]))
        if pair_changes:
            real_changes.append((base_entry, target_entry, pair_changes))

    print()
    print("== blocks that are genuinely different ==")
    for base_entry, target_entry, pair_changes in real_changes:
        print()
        print("--- v15 %#010x -> v16 %#010x" % (base_entry, target_entry))
        for label, lo, hi, count, ratio, missing, items in pair_changes:
            print("  %s %#010x..%#010x  %d instructions, %d unmatched (match %.2f)"
                  % (label, lo, hi, count, len(missing), ratio))
            for address, mapped, other in missing:
                source = next((t for a, _m, t in items if a == address), "?")
                print("    %#010x  %-38s -> %s : %s"
                      % (address, tidy(canonical(normalise15(source))),
                         hex(mapped) if mapped else "-", tidy(canonical(other))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
