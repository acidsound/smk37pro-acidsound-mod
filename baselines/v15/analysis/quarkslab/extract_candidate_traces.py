#!/usr/bin/env python3
"""Extract the exact code/data evidence used to classify v15 MIDI candidates."""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
from pathlib import Path

EXPECTED_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
BASE = 0x02000000


def listing_rows(path: Path) -> list[tuple[int, str]]:
    result = []
    for line in path.read_text(errors="replace").splitlines()[1:]:
        try:
            address = int(line.split("\t", 1)[0], 16)
        except (ValueError, IndexError):
            continue
        result.append((address, line))
    return result


def range_lines(rows: list[tuple[int, str]], start: int, end: int) -> list[str]:
    return [line for address, line in rows if start <= address < end]


def matching_lines(rows: list[tuple[int, str]], text: str) -> list[str]:
    return [line for _, line in rows if text in line]


def raw_pointer_offsets(data: bytes, value: int) -> list[int]:
    needle = struct.pack("<I", value)
    result = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return result
        result.append(offset)
        cursor = offset + 1


def code_block(lines: list[str]) -> str:
    return "```text\n" + "\n".join(lines) + "\n```"


def first_nul(data: bytes, address: int, limit: int = 128) -> tuple[int | None, bytes]:
    offset = address - BASE
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        return None, data[offset : offset + min(limit, 32)]
    return end - offset, data[offset:end]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--recursive-listing", type=Path, required=True)
    parser.add_argument("--exhaustive-listing", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    data = args.image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"unexpected image SHA-256 {digest}")

    recursive = listing_rows(args.recursive_listing)
    exhaustive = listing_rows(args.exhaustive_listing)
    log_lines = args.log.read_text(errors="replace").splitlines()
    target_xrefs = []
    for line in log_lines:
        if "V15DecoderAnalysis.java> TARGET_XREF phase=" in line:
            target_xrefs.append(
                line.split("V15DecoderAnalysis.java> ", 1)[1].rsplit(
                    " (GhidraScript)", 1
                )[0]
            )

    descriptor_values = [
        0x02057276,
        0x020572D2,
        0x02057483,
        0x02057900,
        0x020579AA,
        0x020579B7,
        0x02057A3C,
        0x02057A4A,
    ]

    lines = [
        "# Candidate trace extraction",
        "",
        f"Exact input SHA-256: `{digest}`.",
        "",
        "This file preserves candidate evidence. It does not promote an xref or an",
        "exhaustive-sweep decode to a function identity.",
        "",
        "## Named-target xrefs",
        "",
        code_block(target_xrefs),
        "",
        "## Descriptor-header candidate at `FUN_02024d4c`",
        "",
        "Direct calls recovered to the candidate:",
        "",
        code_block(matching_lines(exhaustive, "call 0x02024d4c")),
        "",
        "Candidate body:",
        "",
        code_block(range_lines(recursive, 0x02024D4C, 0x02024DEA)),
        "",
        "The repeated callee and zero-terminated byte helpers:",
        "",
        code_block(range_lines(recursive, 0x0201A67C, 0x0201A6EC)),
        "",
        code_block(range_lines(recursive, 0x02048E5C, 0x02048ED6)),
        "",
        "C-string plausibility of decoded `r1` values:",
        "",
        "| Address | Bytes before first NUL | Prefix |",
        "|---:|---:|---|",
    ]
    for address in descriptor_values:
        length, prefix = first_nul(data, address)
        rendered_length = "none<=128" if length is None else str(length)
        lines.append(
            f"| `0x{address:08x}` | {rendered_length} | `{prefix!r}` |"
        )

    cin_entry = 0x02000F8E
    cin_refs = raw_pointer_offsets(data, cin_entry)
    lines.extend(
        [
            "",
            "## CIN-table interior candidate at `0x02000f8e`",
            "",
            f"Direct decoded calls: {len(matching_lines(exhaustive, 'call 0x02000f8e'))}.",
            f"Raw little-endian pointers to entry: {len(cin_refs)}.",
            "",
            code_block(range_lines(exhaustive, 0x02000F8E, 0x02001050)),
            "",
            "The disputed reference is to `0x02057abe`, CIN index 14, not to the",
            "table start at `0x02057ab0`. No caller or raw function pointer was recovered.",
            "",
            "## `midi_route` exhaustive-only overlap",
            "",
            code_block(range_lines(exhaustive, 0x02004F44, 0x0200506A)),
            "",
            "The loop reads a contiguous rodata range that overlaps the string. It does",
            "not load the `midi_route` start as a semantic string pointer.",
            "",
        ]
    )
    args.output.write_text("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
