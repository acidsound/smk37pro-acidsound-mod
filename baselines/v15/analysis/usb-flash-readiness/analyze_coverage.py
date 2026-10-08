#!/usr/bin/env python3
"""Derive runtime address-space coverage from the pinned Ghidra listings.

Inputs (hash-guarded):
  baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz
  baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz
  build/v15-official-app.bin

Output: coverage.json  (per-4KiB-page decoded-byte accounting over the official
v15 application runtime window 0x02000000..0x02000000+len(app.bin))

Offline only: reads files, writes one JSON file. No device, USB, flash or OTA.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
QDIR = ROOT / "baselines/v15/analysis/quarkslab/results"
APP = ROOT / "build/v15-official-app.bin"
OUT = pathlib.Path(__file__).resolve().parent / "coverage.json"

APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
RUNTIME_BASE = 0x02000000
PAGE = 0x1000


def load_listing(path: pathlib.Path):
    """Return (set_of_start_addresses, dict addr->length, set_of_function_entries)."""
    starts = set()
    lengths = {}
    funcs = set()
    with gzip.open(path, "rt") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        assert header[:2] == ["address", "bytes"], header
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if not parts or not parts[0]:
                continue
            addr = int(parts[0], 16)
            length = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else len(parts[1]) // 2
            starts.add(addr)
            lengths[addr] = length
            if len(parts) > 6 and parts[6] not in ("-", ""):
                funcs.add(parts[6])
    return starts, lengths, funcs


def main() -> int:
    app = APP.read_bytes()
    got = hashlib.sha256(app).hexdigest()
    if got != APP_SHA256:
        print(f"hash guard failed: {got} != {APP_SHA256}", file=sys.stderr)
        return 1

    rec = load_listing(QDIR / "quarkslab-recursive-listing.tsv.gz")
    exh = load_listing(QDIR / "quarkslab-exhaustive-listing.tsv.gz")

    app_end = RUNTIME_BASE + len(app)
    npages = (len(app) + PAGE - 1) // PAGE
    pages = []
    for i in range(npages):
        base = RUNTIME_BASE + i * PAGE
        end = base + PAGE
        rec_bytes = sum(l for a, l in rec[1].items() if base <= a < end)
        exh_bytes = sum(l for a, l in exh[1].items() if base <= a < end)
        rec_ins = sum(1 for a in rec[0] if base <= a < end)
        exh_ins = sum(1 for a in exh[0] if base <= a < end)
        # call instructions in the recursive decode inside the page
        pages.append({
            "page_start": f"0x{base:08x}",
            "recursive_instruction_bytes": rec_bytes,
            "recursive_instruction_count": rec_ins,
            "exhaustive_instruction_bytes": exh_bytes,
            "exhaustive_instruction_count": exh_ins,
            "page_size": PAGE,
        })

    decoded_pages = sum(1 for p in pages if p["recursive_instruction_bytes"] > 0)
    empty_pages = [p["page_start"] for p in pages if p["recursive_instruction_bytes"] == 0]
    big_holes = [p["page_start"] for p in pages
                 if p["recursive_instruction_bytes"] == 0 and p["exhaustive_instruction_bytes"] < PAGE // 8]

    total_rec = sum(p["recursive_instruction_bytes"] for p in pages)
    total_exh = sum(p["exhaustive_instruction_bytes"] for p in pages)

    out = {
        "format": "smk37-v15-runtime-coverage-v1",
        "scope": "official v15 application image only; offline static decode accounting",
        "inputs": {
            "app_image": "build/v15-official-app.bin",
            "app_image_sha256": got,
            "app_image_size": len(app),
            "runtime_base": f"0x{RUNTIME_BASE:08x}",
            "runtime_end_exclusive": f"0x{app_end:08x}",
            "recursive_listing": "baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz",
            "exhaustive_listing": "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz",
            "decoder": "quarkslab/ghidra-jieli e1bd0707874b77b759401555d24839ad43af1267 (Ghidra 12.1.2)",
        },
        "summary": {
            "page_size": PAGE,
            "pages": npages,
            "pages_with_recursive_decode": decoded_pages,
            "pages_without_recursive_decode": len(empty_pages),
            "recursive_decoded_bytes": total_rec,
            "exhaustive_decoded_bytes": total_exh,
            "coverage_denominator_bytes": len(app),
            "recursive_coverage_ratio": round(total_rec / len(app), 6),
            "exhaustive_coverage_ratio": round(total_exh / len(app), 6),
            "pages_without_recursive_decode_list": empty_pages,
            "pages_without_recursive_and_mostly_undecoded_in_exhaustive": big_holes,
            "recursive_function_count": len(rec[2]),
            "exhaustive_function_count": len(exh[2]),
        },
        "pages": pages,
        "interpretation_limits": [
            "recursive_instruction_bytes counts decoded code only; a zero page is NOT proven data.",
            "exhaustive decode may decode data as instructions; it is not proof of executability.",
            "absence of decoded instructions is never evidence of free space.",
        ],
    }
    OUT.write_text(json.dumps(out, indent=2, sort_keys=False) + "\n")
    print(f"pages={npages} recursive_decoded_pages={decoded_pages} "
          f"recursive_coverage={out['summary']['recursive_coverage_ratio']} "
          f"exhaustive_coverage={out['summary']['exhaustive_coverage_ratio']}")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
