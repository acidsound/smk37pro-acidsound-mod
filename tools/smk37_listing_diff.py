#!/usr/bin/env python3
"""Aligned diff of two decoded functions from Ghidra TSV listings.

Unlike tools/smk37_app_function_diff.py (which compares instruction positions
one-to-one and only classifies the pair), this tool produces a real alignment:
inserted and deleted instructions are shown as such, and absolute constants are
normalised through the byte alignment map before comparison.

Two normalisation variants are tried and the better alignment wins:
  A) map absolute addresses inside the application image through the alignment
  B) as A, plus shift absolute RAM addresses by the measured RAM delta of the pair

Example:
  python3 tools/smk37_listing_diff.py \
    --base-listing  <v15 recursive listing> \
    --target-listing <v16 recursive listing> \
    --base-function 0x0200FC34 --target-function 0x0200FC4C
"""

import argparse
import bisect
import difflib
import gzip
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from smk37_app_diff_align import (  # noqa: E402
    AddressMap,
    collect_anchors,
    longest_increasing_subsequence,
)

BASE = 0x02000000
RAM_LOW = 0x01000000
RAM_HIGH = 0x02000000
HEX_ANY = re.compile(r"0x[0-9a-fA-F]+")
PLACE = "\x00"


def open_text(path: Path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def load_function(path: Path, entry: int):
    """Return [(address, mnemonic, text)] for one function entry address."""
    rows = []
    with open_text(path) as handle:
        header = handle.readline()
        if not header.startswith("address\t"):
            raise SystemExit("unexpected listing header in %s" % path)
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7 or parts[6] == "-":
                continue
            try:
                function_entry = int(parts[6].split("@")[-1], 16)
            except ValueError:
                continue
            if function_entry == entry:
                rows.append((int(parts[0], 16), parts[3], parts[4]))
    rows.sort(key=lambda item: item[0])
    return rows


def constants(text: str):
    return [int(value, 16) for value in HEX_ANY.findall(text)]


def shape(text: str):
    return HEX_ANY.sub(PLACE, text)


def estimate_ram_shift(base_rows, target_rows):
    """Pick the RAM delta that explains the most absolute RAM address pairs."""
    base_ram = [v for _a, _m, text in base_rows for v in constants(text)
                if RAM_LOW <= v < RAM_HIGH]
    target_ram = sorted(set(v for _a, _m, text in target_rows for v in constants(text)
                             if RAM_LOW <= v < RAM_HIGH))
    if not base_ram or not target_ram:
        return 0
    votes = Counter()
    for value in base_ram:
        index = bisect.bisect_left(target_ram, value)
        for candidate in target_ram[max(0, index - 4):index + 4]:
            delta = candidate - value
            if abs(delta) <= 0x400:
                votes[delta] += 1
    if not votes:
        return 0
    return votes.most_common(1)[0][0]


def canonical(text: str) -> str:
    """Rewrite every hex literal without leading zeros (0x0202f092 -> 0x202f092).

    Both sides must be canonicalised, otherwise a relocated constant that keeps the
    same value still compares unequal ("0x0202f092" vs "0x202f092").
    """
    return HEX_ANY.sub(lambda match: "0x%x" % int(match.group(0), 16), text)


def make_normaliser(address_map, base_len: int, ram_shift: int):
    """Return a function rewriting base instruction text into target space.

    Small immediates are never rewritten: they are usually struct offsets or loop
    counters, and shifting them destroys the alignment.
    """
    def normalise(text: str) -> str:
        if PLACE in shape(text):
            def replace(match):
                value = int(match.group(0), 16)
                if BASE <= value < BASE + base_len:
                    mapped = address_map(value)
                    if mapped is not None:
                        value = mapped
                elif ram_shift and RAM_LOW <= value < RAM_HIGH:
                    value = value + ram_shift
                return "0x%x" % value
            text = HEX_ANY.sub(replace, text)
        return text
    return normalise


def score(opcodes):
    """Lower is better: instructions that could not be matched one-to-one."""
    return sum(max(i2 - i1, j2 - j1)
               for tag, i1, i2, j1, j2 in opcodes if tag != "equal")


def align(base_rows, target_rows, address_map, base_len, ram_shift):
    normalise = make_normaliser(address_map, base_len, ram_shift)
    base_keys = [normalise(text) for _a, _m, text in base_rows]
    target_keys = [canonical(text) for _a, _m, text in target_rows]
    matcher = difflib.SequenceMatcher(None, base_keys, target_keys, autojunk=False)
    return matcher.get_opcodes()


def render(base_rows, target_rows, opcodes, context, base_label, target_label,
           ram_shift):
    out = []
    out.append("--- %s (%d instructions)" % (base_label, len(base_rows)))
    out.append("+++ %s (%d instructions)" % (target_label, len(target_rows)))
    for tag, i1, i2, j1, j2 in opcodes:
        if tag == "equal":
            length = i2 - i1
            windows = [(0, length, False)]
            if context >= 0 and length > 2 * context + 1:
                windows = [(0, context, False), (length - context, length, True)]
            for start, end, _tail in windows:
                for k in range(start, end):
                    b_addr, _bm, b_text = base_rows[i1 + k]
                    t_addr, _tm, t_text = target_rows[j1 + k]
                    if b_text == t_text:
                        out.append("  %#010x  %s" % (b_addr, b_text))
                    else:
                        out.append("  %#010x  %-42s | %#010x  %s"
                                   % (b_addr, b_text, t_addr, t_text))
            if len(windows) == 2:
                out.append("  ... %d unchanged instructions ..." % (length - 2 * context))
            continue
        for k in range(i1, i2):
            b_addr, _bm, b_text = base_rows[k]
            out.append("- %#010x  %s" % (b_addr, b_text))
        for k in range(j1, j2):
            t_addr, _tm, t_text = target_rows[k]
            out.append("+ %#010x  %s" % (t_addr, t_text))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-listing", type=Path, required=True)
    parser.add_argument("--target-listing", type=Path, required=True)
    parser.add_argument("--base-function", required=True)
    parser.add_argument("--target-function", required=True)
    parser.add_argument("--base-image", type=Path)
    parser.add_argument("--target-image", type=Path)
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--context", type=int, default=4)
    parser.add_argument("--no-ram-shift", action="store_true")
    args = parser.parse_args(argv)

    base_entry = int(args.base_function, 16)
    target_entry = int(args.target_function, 16)
    base_rows = load_function(args.base_listing, base_entry)
    target_rows = load_function(args.target_listing, target_entry)
    if not base_rows:
        raise SystemExit("no instructions for %#x in %s" % (base_entry, args.base_listing))
    if not target_rows:
        raise SystemExit("no instructions for %#x in %s" % (target_entry, args.target_listing))

    if args.base_image and args.target_image:
        base_image = args.base_image.read_bytes()
        target_image = args.target_image.read_bytes()
        chain = longest_increasing_subsequence(
            collect_anchors(base_image, target_image, args.k))
        address_map = AddressMap(chain, args.k, BASE)
        base_len = len(base_image)
    else:
        address_map = lambda value: None
        base_len = 0

    shift = 0 if args.no_ram_shift else estimate_ram_shift(base_rows, target_rows)
    plain = align(base_rows, target_rows, address_map, base_len, 0)
    shifted = align(base_rows, target_rows, address_map, base_len, shift) if shift else plain
    if score(shifted) < score(plain):
        opcodes, applied = shifted, shift
    else:
        opcodes, applied = plain, 0

    inserted = sum(j2 - j1 for tag, _i1, _i2, j1, j2 in opcodes if tag in ("insert", "replace"))
    deleted = sum(i2 - i1 for tag, i1, i2, _j1, _j2 in opcodes if tag in ("delete", "replace"))
    print("# unmatched: inserted=%d deleted=%d (of %d -> %d); RAM delta applied: %+#x"
          % (inserted, deleted, len(base_rows), len(target_rows), applied))
    for line in render(base_rows, target_rows, opcodes, args.context,
                       "v15 %#010x" % base_entry, "v16 %#010x" % target_entry,
                       applied):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
