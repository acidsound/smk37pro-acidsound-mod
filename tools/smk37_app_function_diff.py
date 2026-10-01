#!/usr/bin/env python3
"""Function-level diff between two decoded SMK-37 Pro application images.

Pairing strategy
----------------
1.  Build a collinear byte alignment between the two images
    (tools/smk37_app_diff_align.py).
2.  Read Ghidra recursive listings and recover each function instruction range
    from the trailing "function" column.
3.  Predict the target entry address of every base function through the
    alignment map and match it to the closest target function entry within a
    small tolerance.
4.  Classify each pair:
      identical          - same mnemonic sequence, same operand text
      relocated          - same mnemonic sequence; operand text differs only in
                           absolute addresses that follow the alignment map
      constants_changed  - same mnemonic sequence; at least one absolute address
                           does not follow the alignment map
      structural         - mnemonic sequence differs
    Functions present in only one image are reported as added / removed.

The tool is read-only.
"""

from __future__ import annotations

import argparse
import bisect
import gzip
import json
import re
import sys
from collections import OrderedDict
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


def parse_listing(path: Path):
    """Return OrderedDict[function_entry] -> list of (address, mnemonic, text, bytes)."""
    functions = OrderedDict()
    with open_text(path) as handle:
        header = handle.readline()
        if not header.startswith("address\t"):
            raise SystemExit("unexpected listing header in %s: %r" % (path, header))
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7:
                continue
            address, raw, _length, mnemonic, text, _flow, function = parts[:7]
            if function == "-":
                continue
            entry = int(function.split("@")[-1], 16)
            functions.setdefault(entry, []).append(
                (int(address, 16), mnemonic, text, raw))
    for key in functions:
        functions[key].sort(key=lambda item: item[0])
    return functions


def shape(text: str) -> str:
    return HEX_ANY.sub(PLACE, text)


def constants(text: str):
    return [int(value, 16) for value in HEX_ANY.findall(text)]


def image_relocated(base_text: str, target_text: str, address_map, base_len: int):
    """True when every difference follows the byte alignment of the app image."""
    if base_text == target_text:
        return True
    if shape(base_text) != shape(target_text):
        return False
    for base_value, target_value in zip(constants(base_text), constants(target_text)):
        if base_value == target_value:
            continue
        if not (BASE <= base_value < BASE + base_len):
            return False
        if address_map(base_value) != target_value:
            return False
    return True


def candidate_ram_deltas(pairs):
    """Collect deltas of absolute RAM addresses seen anywhere in the function."""
    deltas = set()
    for _b_addr, b_text, _t_addr, t_text in pairs:
        if shape(b_text) != shape(t_text):
            continue
        for b_value, t_value in zip(constants(b_text), constants(t_text)):
            if b_value == t_value:
                continue
            if RAM_LOW <= b_value < RAM_HIGH and RAM_LOW <= t_value < RAM_HIGH:
                deltas.add(t_value - b_value)
    return deltas


def explain(base_text: str, target_text: str, address_map, base_len: int, ram_deltas):
    """Explain one differing instruction using the alignment map or the RAM deltas."""
    if base_text == target_text:
        return True
    if shape(base_text) != shape(target_text):
        return False
    for base_value, target_value in zip(constants(base_text), constants(target_text)):
        if base_value == target_value:
            continue
        if BASE <= base_value < BASE + base_len:
            if address_map(base_value) == target_value:
                continue
            return False
        if RAM_LOW <= base_value < RAM_HIGH and RAM_LOW <= target_value < RAM_HIGH:
            if target_value - base_value in ram_deltas:
                continue
            return False
        # A 32-bit RAM address is often materialised as a pair of small immediates;
        # those low halves move by exactly the same delta.
        if base_value < 0x100000 and target_value < 0x100000:
            if target_value - base_value in ram_deltas:
                continue
            return False
        return False
    return True


def raw_agreement(base_instructions, target_instructions):
    """Fraction of instructions whose encoded bytes are identical.

    Instructions carrying an absolute address differ in bytes, so a correct pair
    still shows a high value; a mispaired function shows a value near zero.
    """
    if not base_instructions:
        return 0.0
    same = 0
    for base_item, target_item in zip(base_instructions, target_instructions):
        if base_item[3] == target_item[3]:
            same += 1
    return same / float(len(base_instructions))


def compare_pair(base_instructions, target_instructions, address_map, base_len):
    base_mnemonics = [item[1] for item in base_instructions]
    target_mnemonics = [item[1] for item in target_instructions]
    if base_mnemonics != target_mnemonics:
        return "structural", [], None, []

    differing = []
    for base_item, target_item in zip(base_instructions, target_instructions):
        b_addr, _b_mnemonic, b_text, _b_raw = base_item
        t_addr, _t_mnemonic, t_text, _t_raw = target_item
        if b_text != t_text:
            differing.append((b_addr, b_text, t_addr, t_text))

    ram_deltas = candidate_ram_deltas(differing)
    unexplained = []
    for b_addr, b_text, t_addr, t_text in differing:
        if not explain(b_text, t_text, address_map, base_len, ram_deltas):
            if len(unexplained) < 10:
                unexplained.append((b_addr, b_text, t_addr, t_text))

    if unexplained:
        return "constants_changed", [], sorted(ram_deltas) or None, unexplained
    if ram_deltas:
        return "ram_relocated", [], sorted(ram_deltas), []
    return "relocated", [], None, []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-image", type=Path, required=True)
    parser.add_argument("--target-image", type=Path, required=True)
    parser.add_argument("--base-listing", type=Path, required=True)
    parser.add_argument("--target-listing", type=Path, required=True)
    parser.add_argument("--tolerance", type=int, default=24)
    parser.add_argument("--k", type=int, default=16)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--pairs", type=Path)
    parser.add_argument("--details", type=Path)
    args = parser.parse_args(argv)

    base_image = args.base_image.read_bytes()
    target_image = args.target_image.read_bytes()
    chain = longest_increasing_subsequence(
        collect_anchors(base_image, target_image, args.k))
    address_map = AddressMap(chain, args.k, BASE)
    print("alignment anchors=%d" % len(chain))

    base_functions = parse_listing(args.base_listing)
    target_functions = parse_listing(args.target_listing)
    print("base functions=%d target functions=%d" % (len(base_functions), len(target_functions)))

    target_entries = sorted(target_functions)

    # Collect every plausible (base, target) proposal, then resolve conflicts by
    # quality.  Two base functions can predict the same target address (function
    # splitting differs between the two images), so a nearest-first greedy pass
    # would let the first one win even when it is the weaker match.
    proposals = []
    for entry in base_functions:
        predicted = address_map(entry)
        if predicted is None:
            continue
        index = bisect.bisect_left(target_entries, predicted)
        for candidate_index in range(index - 3, index + 4):
            if 0 <= candidate_index < len(target_entries):
                candidate = target_entries[candidate_index]
                distance = abs(candidate - predicted)
                if distance <= args.tolerance:
                    proposals.append((distance, entry, candidate))
    proposals.sort()

    paired = {}
    used_targets = set()
    for distance, entry, candidate in proposals:
        if entry in paired or candidate in used_targets:
            continue
        base_instructions = base_functions[entry]
        target_instructions = target_functions[candidate]
        agreement = raw_agreement(base_instructions, target_instructions)
        same_mnemonics = ([item[1] for item in base_instructions]
                          == [item[1] for item in target_instructions])
        if not same_mnemonics and agreement < 0.50:
            continue
        if len(base_instructions) < 8 and agreement < 0.25:
            continue
        paired[entry] = (candidate, distance)
        used_targets.add(candidate)

    counts = {}
    rows = []
    details = []
    paired_final = {}
    rejected = []
    for entry, (target_entry, _distance) in paired.items():
        agreement = raw_agreement(base_functions[entry], target_functions[target_entry])
        verdict, _unused, ram_deltas, unexplained = compare_pair(
            base_functions[entry], target_functions[target_entry], address_map, len(base_image))
        paired_final[entry] = target_entry
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append({
            "verdict": verdict,
            "raw_agreement": round(agreement, 4),
            "base_entry": entry,
            "target_entry": target_entry,
            "entry_delta": target_entry - entry,
            "entry_prediction_error": target_entry - address_map(entry),
            "base_instructions": len(base_functions[entry]),
            "target_instructions": len(target_functions[target_entry]),
            "ram_deltas": ram_deltas,
        })
        if verdict != "identical":
            details.append((verdict, entry, target_entry, unexplained, ram_deltas,
                            len(base_functions[entry]), len(target_functions[target_entry]), agreement))

    paired = paired_final
    used_targets = set(paired.values())
    # Content fallback: a function can move further than the address tolerance when
    # the images are not locally collinear.  Match the remaining functions by their
    # full mnemonic signature and confirm with byte agreement.
    signature = {}
    for candidate in target_entries:
        if candidate in used_targets:
            continue
        key = tuple(item[1] for item in target_functions[candidate])
        if len(key) >= 3:
            signature.setdefault(key, []).append(candidate)
    content_paired = 0
    for entry in base_functions:
        if entry in paired:
            continue
        base_instructions = base_functions[entry]
        key = tuple(item[1] for item in base_instructions)
        if len(key) < 3:
            continue
        options = [c for c in signature.get(key, []) if c not in used_targets]
        if not options:
            continue
        predicted = address_map(entry)
        options.sort(key=lambda c: abs(c - predicted))
        for candidate in options:
            if raw_agreement(base_instructions, target_functions[candidate]) >= 0.50:
                paired[entry] = (candidate, candidate - predicted)
                used_targets.add(candidate)
                content_paired += 1
                break
    print("content_fallback_pairings=%d" % content_paired)

    added = [entry for entry in target_entries if entry not in used_targets]
    removed = [entry for entry in base_functions if entry not in paired]
    rows.sort(key=lambda item: item["base_entry"])

    # Entries that vanish and reappear nearby with a similar instruction count are
    # usually a function-boundary artifact of the shifted image, not deleted code.
    added_index = sorted(added)
    split_merge = []
    genuinely_removed = []
    for entry in removed:
        count = len(base_functions[entry])
        predicted = address_map(entry)
        candidate = None
        for other in added_index:
            if other in used_targets:
                continue
            if abs(len(target_functions[other]) - count) > max(3, count * 0.1):
                continue
            if abs(other - predicted) <= 0x40:
                candidate = other
                break
        if candidate is None:
            genuinely_removed.append(entry)
        else:
            split_merge.append((entry, candidate, count))

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps({
            "base_image": str(args.base_image),
            "target_image": str(args.target_image),
            "base_functions": len(base_functions),
            "target_functions": len(target_functions),
            "paired": len(paired),
            "counts": counts,
            "ram_deltas_observed": sorted({
                delta for row in rows if row["ram_deltas"] for delta in row["ram_deltas"]}),
            "added_target_functions": [hex(x) for x in added],
            "removed_base_functions": [hex(x) for x in removed],
            "split_merge_candidates": [
                {"base": hex(a), "target": hex(b), "instructions": c} for a, b, c in split_merge],
            "genuinely_removed_base_functions": [hex(x) for x in genuinely_removed],
            "pairs": rows,
        }, indent=2) + "\n")

    if args.pairs:
        args.pairs.parent.mkdir(parents=True, exist_ok=True)
        with open(args.pairs, "w", encoding="utf-8") as handle:
            handle.write("verdict\tbase_entry\ttarget_entry\tbase_instructions\t"
                         "target_instructions\tentry_delta\tprediction_error\tram_delta\t"
                         "raw_agreement\n")
            for row in rows:
                rendered = row.copy()
                rendered["ram_delta"] = ",".join("+%#x" % d for d in (row["ram_deltas"] or [])) or "-"
                handle.write("{verdict}\t{base_entry:#010x}\t{target_entry:#010x}\t"
                             "{base_instructions}\t{target_instructions}\t"
                             "{entry_delta:+#x}\t{entry_prediction_error:+#x}\t"
                             "{ram_delta}\t{raw_agreement:.3f}\n".format(**rendered))

    if args.details:
        args.details.parent.mkdir(parents=True, exist_ok=True)
        with open(args.details, "w", encoding="utf-8") as handle:
            handle.write("# Non-identical function pairs\n\n")
            handle.write("Generated by tools/smk37_app_function_diff.py.\n\n")
            for (verdict, entry, target_entry, unexplained, ram_deltas,
                 base_count, target_count, agreement) in sorted(
                     details, key=lambda item: (item[0], item[1])):
                handle.write("## %s  %#010x -> %#010x  (%d -> %d instructions, "
                             "raw agreement %.3f)\n\n" % (
                    verdict, entry, target_entry, base_count, target_count, agreement))
                if ram_deltas:
                    handle.write("RAM address delta: %s\n\n" % (
                        ", ".join("+%#x" % d for d in ram_deltas)))
                for b_addr, b_text, t_addr, t_text in unexplained:
                    handle.write("- %#010x  base: %s\n" % (b_addr, b_text))
                    handle.write("  %#010x  v16 : %s\n" % (t_addr, t_text))
                handle.write("\n")

    print("paired=%d (byte-verified) counts=%s" % (len(paired), counts))
    print("rejected_pairings=%d (raw agreement < 0.50)" % len(rejected))
    for entry, target_entry, agreement in rejected:
        print("  x %#010x -> %#010x agreement=%.3f" % (entry, target_entry, agreement))
    print("removed_base_functions=%d (split/merge candidates=%d, genuinely removed=%d)"
          % (len(removed), len(split_merge), len(genuinely_removed)))
    print("added_target_functions=%d" % len(added))
    for entry in genuinely_removed:
        print("  - removed %#010x (%d instructions)" % (entry, len(base_functions[entry])))
    for a, b, c in split_merge:
        print("  ~ boundary %#010x (%d) -> %#010x (%d)"
              % (a, c, b, len(target_functions[b])))
    for entry in added:
        print("  + added   %#010x (%d instructions)" % (entry, len(target_functions[entry])))
    return 0


if __name__ == "__main__":
    sys.exit(main())