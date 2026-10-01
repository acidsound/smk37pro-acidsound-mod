#!/usr/bin/env python3
"""Anchor-based monotonic alignment of two decoded SMK-37 Pro application images.

The v15 -> v16 diff previously used a 24-byte anchor probe per function, which can
lock onto coincidental matches.  This tool builds a proper collinear alignment:

  1. index unique k-mers of the target image
  2. collect (source, target) anchors whose k-mer is unique in both images
  3. keep the longest increasing subsequence, so anchors are strictly collinear
  4. walk consecutive anchors and emit an edit script of equal / insert / delete /
     replace blocks, including the case where a replaced block has the same length
     on both sides

Outputs a machine-readable alignment JSON plus a human-readable summary.  Runtime
base is the caller's business: everything here is image-relative, and absolute
runtime addresses are reported by adding --base.

This tool reads files only; it never writes to a device.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import sys
from pathlib import Path

DEFAULT_K = 16


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def index_unique_kmers(data: bytes, k: int):
    """Map k-mer -> unique offset, dropping any k-mer that occurs more than once."""
    seen = {}
    dup = set()
    limit = len(data) - k
    for i in range(limit + 1):
        mer = data[i:i + k]
        if mer in seen:
            dup.add(mer)
        else:
            seen[mer] = i
    for mer in dup:
        del seen[mer]
    return seen


def collect_anchors(source: bytes, target: bytes, k: int):
    target_index = index_unique_kmers(target, k)
    anchors = []
    limit = len(source) - k
    for i in range(limit + 1):
        mer = source[i:i + k]
        j = target_index.get(mer)
        if j is not None:
            anchors.append((i, j))
    return anchors


def longest_increasing_subsequence(anchors):
    """Patience-sorting LIS over the target coordinate, preserving source order."""
    if not anchors:
        return []
    tails = []          # tails[m] = index into anchors of the smallest tail of a run of length m+1
    prev = [-1] * len(anchors)
    for idx, (_, j) in enumerate(anchors):
        lo, hi = 0, len(tails)
        while lo < hi:
            mid = (lo + hi) // 2
            if anchors[tails[mid]][1] < j:
                lo = mid + 1
            else:
                hi = mid
        if lo > 0:
            prev[idx] = tails[lo - 1]
        if lo == len(tails):
            tails.append(idx)
        else:
            tails[lo] = idx
    chain = []
    cursor = tails[-1]
    while cursor != -1:
        chain.append(anchors[cursor])
        cursor = prev[cursor]
    chain.reverse()
    return chain


def classify_gap(source, target, s_prev_end, d_prev_end, s_next, d_next):
    """Classify the region strictly between two consecutive anchors."""
    src_gap = s_next - s_prev_end
    dst_gap = d_next - d_prev_end
    if src_gap == 0 and dst_gap == 0:
        return None
    if src_gap == 0:
        return "insert_target", src_gap, dst_gap
    if dst_gap == 0:
        return "delete_target", src_gap, dst_gap
    if src_gap == dst_gap:
        left = source[s_prev_end:s_next]
        right = target[d_prev_end:d_next]
        if left == right:
            return "equal", src_gap, dst_gap
        return "replace", src_gap, dst_gap
    return "complex", src_gap, dst_gap


def build_blocks(source, target, chain, k):
    blocks = []
    for order in range(len(chain) - 1):
        s_i, d_i = chain[order]
        s_j, d_j = chain[order + 1]
        s_prev_end = s_i + k
        d_prev_end = d_i + k
        verdict = classify_gap(source, target, s_prev_end, d_prev_end, s_j, d_j)
        if verdict is None:
            continue
        kind, src_gap, dst_gap = verdict
        blocks.append({
            "kind": kind,
            "src_start": s_prev_end,
            "src_end": s_j,
            "dst_start": d_prev_end,
            "dst_end": d_j,
            "src_len": src_gap,
            "dst_len": dst_gap,
            "delta": dst_gap - src_gap,
        })
    return blocks


def group_runs(chain, k):
    """Collapse runs of byte-consecutive anchors sharing one constant (dst - src)."""
    runs = []
    previous_src = None
    for s_i, d_i in chain:
        shift = d_i - s_i
        if (runs is not None and previous_src is not None
                and runs[-1]["shift"] == shift and s_i == previous_src + 1):
            runs[-1]["src_end"] = s_i + k
            runs[-1]["dst_end"] = d_i + k
            runs[-1]["anchors"] += 1
        else:
            runs.append({
                "shift": shift,
                "src_start": s_i,
                "src_end": s_i + k,
                "dst_start": d_i,
                "dst_end": d_i + k,
                "anchors": 1,
            })
        previous_src = s_i
    return runs


class AddressMap:
    """Maps a source address to a target address using the anchor chain.

    The anchor chain is stored as image-relative offsets; pass the runtime base
    (0x02000000 for this platform) so callers can work in absolute addresses.
    """

    def __init__(self, chain, k, base=0):
        self.k = k
        self.base = base
        self.starts = [s for s, _ in chain]
        self.chain = chain
        self.src_len = chain[-1][0] + k if chain else 0

    def __call__(self, address: int):
        if not self.chain:
            return None
        offset = address - self.base
        idx = bisect.bisect_right(self.starts, offset) - 1
        if idx < 0:
            idx = 0
        s_i, d_i = self.chain[idx]
        return offset - s_i + d_i + self.base


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("source", type=Path, help="base image (v15 decoded app)")
    parser.add_argument("target", type=Path, help="target image (v16 decoded app)")
    parser.add_argument("--k", type=int, default=DEFAULT_K, help="anchor k-mer size (default 16)")
    parser.add_argument("--base", default="0x02000000", help="runtime base address for reporting")
    parser.add_argument("--json", type=Path, help="write the alignment as JSON")
    parser.add_argument("--max-blocks", type=int, default=200,
                        help="cap on blocks written to JSON (largest first)")
    args = parser.parse_args(argv)

    base = int(args.base, 0)
    source = args.source.read_bytes()
    target = args.target.read_bytes()
    if len(source) == 0 or len(target) == 0:
        raise SystemExit("empty input image")

    anchors = collect_anchors(source, target, args.k)
    chain = longest_increasing_subsequence(anchors)
    if not chain:
        raise SystemExit("no collinear anchors found; images may be unrelated")
    blocks = build_blocks(source, target, chain, args.k)
    runs = group_runs(chain, args.k)

    inserted = sum(b["dst_len"] for b in blocks if b["kind"] == "insert_target")
    deleted = sum(b["src_len"] for b in blocks if b["kind"] == "delete_target")
    replaced = sum(b["src_len"] for b in blocks if b["kind"] == "replace")
    complex_bytes = sum(b["src_len"] + b["dst_len"] for b in blocks if b["kind"] == "complex")

    longest_src = max((b["src_len"] for b in blocks), default=0)
    longest_dst = max((b["dst_len"] for b in blocks), default=0)
    anchor_coverage_src = sum(
        min(r["src_end"], len(source)) - r["src_start"] for r in runs
    )
    anchor_coverage_dst = sum(
        min(r["dst_end"], len(target)) - r["dst_start"] for r in runs
    )

    result = {
        "source": str(args.source),
        "source_size": len(source),
        "source_sha256": sha256(source),
        "target": str(args.target),
        "target_size": len(target),
        "target_sha256": sha256(target),
        "k": args.k,
        "base": hex(base),
        "anchor_count": len(anchors),
        "collinear_anchor_count": len(chain),
        "shift_run_count": len(runs),
        "block_count": len(blocks),
        "inserted_target_bytes": inserted,
        "deleted_target_bytes": deleted,
        "replaced_bytes": replaced,
        "complex_bytes": complex_bytes,
        "size_delta": len(target) - len(source),
        "longest_insert": longest_dst,
        "longest_delete": longest_src,
        "anchor_coverage_source_bytes": anchor_coverage_src,
        "anchor_coverage_target_bytes": anchor_coverage_dst,
        "runs": [
            {
                "shift": r["shift"],
                "src_start": hex(base + r["src_start"]),
                "src_end": hex(base + r["src_end"]),
                "dst_start": hex(base + r["dst_start"]),
                "dst_end": hex(base + r["dst_end"]),
                "anchors": r["anchors"],
            }
            for r in runs
        ],
        "blocks": [
            {
                "kind": b["kind"],
                "src_start": hex(base + b["src_start"]),
                "src_end": hex(base + b["src_end"]),
                "dst_start": hex(base + b["dst_start"]),
                "dst_end": hex(base + b["dst_end"]),
                "src_len": b["src_len"],
                "dst_len": b["dst_len"],
                "delta": b["delta"],
                "src_bytes": source[b["src_start"]:b["src_end"]][:32].hex(),
                "dst_bytes": target[b["dst_start"]:b["dst_end"]][:32].hex(),
            }
            for b in sorted(blocks, key=lambda item: -(item["src_len"] + item["dst_len"]))[:args.max_blocks]
        ],
    }

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n")

    print("source_size={} target_size={} size_delta={:+d}".format(
        len(source), len(target), len(target) - len(source)))
    print("anchors={} collinear={} shift_runs={} blocks={}".format(
        len(anchors), len(chain), len(runs), len(blocks)))
    print("inserted={} deleted={} replaced={} complex={}".format(
        inserted, deleted, replaced, complex_bytes))
    print("anchor_coverage source={} target={}".format(anchor_coverage_src, anchor_coverage_dst))
    print("longest_insert={} longest_delete={}".format(longest_dst, longest_src))
    ranked = sorted(runs, key=lambda item: -(item["src_end"] - item["src_start"]))
    print("shift_runs={} (showing largest {} by source span)".format(len(runs), min(30, len(runs))))
    for run in ranked[:30]:
        print("  shift {:+#7x}  src {:#010x}..{:#010x}  dst {:#010x}..{:#010x}  span={} anchors={}".format(
            run["shift"], base + run["src_start"], base + run["src_end"],
            base + run["dst_start"], base + run["dst_end"],
            run["src_end"] - run["src_start"], run["anchors"]))
    print("edge_shifts: first={:+#x} last={:+#x}".format(runs[0]["shift"], runs[-1]["shift"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
