#!/usr/bin/env python3
"""Prove the official-v15 heap symbols and evaluate two R03 RAM reservations."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
APP = ROOT / "build/v15-official-app.bin"
OBJECT = OUT / "mem_heap.pi32.o"
MATCHER_DIR = ROOT / "baselines/v15/analysis/sdk-signatures"
sys.path.insert(0, str(MATCHER_DIR))
from match_relocated_objects import parse_elf  # noqa: E402

APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
OBJECT_SHA = "82fb6c5a2546861c6114442f556b573da739717c5f53cfbc31853337e36e5fb6"
SDK_COMMIT = "e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d"
SDK_SOURCE_SHA = "411cb79e74853a5b7ce9135514f59d8eafb5b098ced2f8acde08201fdfcf380c"
TOOLCHAIN_ARCHIVE_SHA = "f686586bcfb45e0f0bb27fd2b39c7a7f313cb4f0e88a66a14da621ffa8225958"
CLANG_SHA = "42b94f9e11140b0fcab8f807b2872ad245b8eeca03a2d792f8706c5a3a35d34c"

APP_BASE = 0x02000000
SBRK_VA = 0x0205E9DA
SBRK_OBJECT_OFFSET = 0x1F4
SBRK_SIZE = 0x62
BSS_START = 0x01C099D4
BSS_END = 0x01C4651C
OLD_BSS_SIZE = 0x3CB48
POINTER_SLOT = 0x01C4651C
HEAP_BEGIN = 0x01C46520
HEAP_END = 0x01C7FD30
FIXED_END = 0x01C465E0
VOICE_SIZE = 0x9C
METADATA_SIZE = 8


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hx(value: int) -> str:
    return f"0x{value:08x}"


def raw_hits(data: bytes, value: int) -> list[int]:
    needle = value.to_bytes(4, "little")
    hits: list[int] = []
    cursor = 0
    while True:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            return hits
        hits.append(cursor)
        cursor += 1


def mov_payload_hits(data: bytes, start: int, end: int) -> list[dict[str, str]]:
    hits = []
    for offset in range(len(data) - 6):
        value = int.from_bytes(data[offset + 2:offset + 6], "little")
        if start <= value < end:
            hits.append({"instruction": hx(APP_BASE + offset), "value": hx(value), "bytes": data[offset:offset + 6].hex()})
    return hits


def main() -> None:
    app = APP.read_bytes()
    if sha(APP) != APP_SHA:
        raise SystemExit("refusing non-official-v15 app")
    if sha(OBJECT) != OBJECT_SHA:
        raise SystemExit("unexpected mem_heap object")

    raw, sections, symbols, relocations = parse_elf(OBJECT)
    section_index = next(i for i, section in enumerate(sections) if section.name == ".mem_heap_code")
    section = sections[section_index]
    symbol = next(item for item in symbols if item[0] == "sbrk" and item[1] == SBRK_OBJECT_OFFSET)
    _, value, size, _, _ = symbol
    assert size == SBRK_SIZE
    object_body = raw[section.offset + value:section.offset + value + size]
    app_offset = SBRK_VA - APP_BASE
    v15_body = app[app_offset:app_offset + size]
    function_relocs = [r for r in relocations[section_index] if value <= r["offset"] < value + size]
    relocation_rows = []
    masked = set()
    recovered = {}
    for relocation in function_relocs:
        relative = relocation["offset"] - value
        name = symbols[relocation["symbol"]][0]
        for index in range(relative, relative + 6):
            masked.add(index)
        encoded = int.from_bytes(v15_body[relative + 2:relative + 6], "little")
        recovered[name] = encoded
        relocation_rows.append({"relative_offset": hx(relative), "symbol": name, "v15_value": hx(encoded)})

    fixed = [i for i in range(size) if i not in masked]
    fixed_equal = sum(object_body[i] == v15_body[i] for i in fixed)
    differing = [i for i, pair in enumerate(zip(object_body, v15_body)) if pair[0] != pair[1]]
    expected_differences = sorted(relative + delta for relative in (0x0E, 0x1E, 0x26) for delta in range(2, 6))

    pointer_hits = []
    for address in range(POINTER_SLOT, HEAP_BEGIN):
        pointer_hits.extend({"value": hx(address), "app_offset": hx(hit)} for hit in raw_hits(app, address))
    fixed_hits = mov_payload_hits(app, HEAP_BEGIN, FIXED_END)

    checks = [
        ("official-v15-app", sha(APP) == APP_SHA, sha(APP)),
        ("pinned-mem-heap-object", sha(OBJECT) == OBJECT_SHA, sha(OBJECT)),
        ("sbrk-symbol-size", size == SBRK_SIZE, hx(size)),
        ("sbrk-all-fixed-bytes-exact", fixed_equal == len(fixed) == 80, f"{fixed_equal}/{len(fixed)}"),
        ("sbrk-only-relocation-payload-differs", differing == expected_differences, differing),
        ("sbrk-init-address", recovered.get("sbrk.__init_addr") == 0x01C32D94, hx(recovered.get("sbrk.__init_addr", 0))),
        ("heap-begin", recovered.get("HEAP_BEGIN") == HEAP_BEGIN, hx(recovered.get("HEAP_BEGIN", 0))),
        ("heap-end", recovered.get("HEAP_END") == HEAP_END, hx(recovered.get("HEAP_END", 0))),
        ("pointer-slot-is-linker-padding", BSS_END == POINTER_SLOT and HEAP_BEGIN - POINTER_SLOT == 4, f"{hx(POINTER_SLOT)}..{hx(HEAP_BEGIN)}"),
        ("pointer-slot-no-absolute-reference", not pointer_hits, pointer_hits),
        ("fixed-prefix-capacity", FIXED_END - HEAP_BEGIN >= VOICE_SIZE + METADATA_SIZE, hx(FIXED_END - HEAP_BEGIN)),
        ("fixed-prefix-no-reference-except-heap-begin", fixed_hits == [{"instruction": "0x0205e9f8", "value": "0x01c46520", "bytes": "c5ff2065c401"}], fixed_hits),
        ("pointer-zero-extension-stops-at-heap", BSS_START + (OLD_BSS_SIZE + 4) == HEAP_BEGIN, hx(BSS_START + OLD_BSS_SIZE + 4)),
        ("fixed-zero-extension-stops-at-new-heap", BSS_START + (FIXED_END - BSS_START) == FIXED_END, hx(FIXED_END)),
    ]
    if not all(ok for _, ok, _ in checks):
        raise SystemExit("heap-prefix evidence validation failed")

    evidence = {
        "format": "smk37-v15-r03-heap-prefix-reservation-v1",
        "inputs": {
            "app": str(APP.relative_to(ROOT)), "app_sha256": sha(APP),
            "object": str(OBJECT.relative_to(ROOT)), "object_sha256": sha(OBJECT),
            "sdk_commit": SDK_COMMIT, "sdk_mem_heap_source_sha256": SDK_SOURCE_SHA,
            "toolchain_archive_sha256": TOOLCHAIN_ARCHIVE_SHA, "clang_sha256": CLANG_SHA,
        },
        "sbrk_match": {
            "v15_address": hx(SBRK_VA), "size": hx(size), "fixed_bytes_exact": fixed_equal,
            "fixed_bytes_total": len(fixed), "differing_offsets": differing,
            "relocations": relocation_rows, "recovered_symbols": {key: hx(value) for key, value in recovered.items()},
        },
        "option_a_pointer_anchor": {
            "pointer_slot": f"{hx(POINTER_SLOT)}..{hx(HEAP_BEGIN)}", "boot_zero_size_patch": f"{hx(OLD_BSS_SIZE)} -> {hx(OLD_BSS_SIZE + 4)}",
            "ownership": "PASS for the four-byte zeroed pointer slot",
            "allocation": "BLOCK until a thread-safe v15 allocator entry and producer code placement are independently proven",
        },
        "option_b_fixed_prefix": {
            "range": f"{hx(HEAP_BEGIN)}..{hx(FIXED_END)}", "size": hx(FIXED_END - HEAP_BEGIN),
            "layout": {"voice": f"{hx(HEAP_BEGIN)}..{hx(HEAP_BEGIN + VOICE_SIZE)}", "valid": hx(HEAP_BEGIN + 0x9C), "active_count": hx(HEAP_BEGIN + 0x9D), "generation": hx(HEAP_BEGIN + 0xA0), "guard_start": hx(HEAP_BEGIN + 0xA4)},
            "boot_zero_size_patch": f"{hx(OLD_BSS_SIZE)} -> {hx(FIXED_END - BSS_START)}",
            "heap_begin_patch": f"{hx(HEAP_BEGIN)} -> {hx(FIXED_END)}",
            "ownership": "PASS if both exact patches are applied; allocator cannot address below its patched HEAP_BEGIN",
            "requirement_status": "EXCEPTION REQUIRED because heap capacity is reduced by 0xc0 despite unchanged allocator ABI",
        },
        "decision": "Gate A has a concrete fixed-prefix ownership construction, but R03 remains BLOCKED by the no-allocator-change rule and unproven producer/consumer code placement.",
        "validation": [{"check": name, "status": "PASS", "detail": str(detail)} for name, _, detail in checks],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    report = f"""# R03 official-v15 heap-prefix reservation audit

## Result

The official SDK `sbrk()` is now identified at `{hx(SBRK_VA)}` with all 80
non-relocated bytes exact. Its three relocations recover:

- `sbrk.__init_addr = 0x01c32d94`
- `HEAP_BEGIN = {hx(HEAP_BEGIN)}`
- `HEAP_END = {hx(HEAP_END)}`

This closes the previous unknown-heap-boundary blocker.

## Option A: zeroed pointer anchor

`{hx(POINTER_SLOT)}..{hx(HEAP_BEGIN)}` is the exact four-byte linker alignment
padding between the BSS end and 32-byte-aligned heap start. Increasing the boot
BSS-zero length from `{hx(OLD_BSS_SIZE)}` to `{hx(OLD_BSS_SIZE + 4)}` initializes
the slot to null and stops exactly at `HEAP_BEGIN`.

The slot itself is **PASS**. The complete option is **BLOCK** until a thread-safe
v15 allocation entry and producer code placement are proven.

## Option B: fixed zeroed heap prefix

Increasing BSS zeroing through `{hx(FIXED_END)}` and changing the single matched
`HEAP_BEGIN` immediate to `{hx(FIXED_END)}` reserves
`{hx(HEAP_BEGIN)}..{hx(FIXED_END)}` (`0xc0` bytes). The proposed layout is:

- voice: `0x01c46520..0x01c465bc` (`0x9c`)
- valid: `0x01c465bc`
- active count: `0x01c465bd`
- generation: `0x01c465c0..0x01c465c4`
- guard: `0x01c465c4..0x01c465e0`

Static ownership is **PASS if and only if both exact patches are applied**.
The public linker establishes that the allocator begins at `HEAP_BEGIN`, and the
matched v15 `sbrk()` confirms that boundary at runtime. The reserved interval has
no absolute reference other than the old `HEAP_BEGIN` relocation.

This is not yet an R03 PASS. It reduces heap capacity by `0xc0`, conflicting
with the current “do not change allocator” requirement even though allocator ABI
and implementation are unchanged. A controlled-checkpoint exception plus heap
stress validation would be required. Producer/consumer code placement also
remains blocked.

## Provenance

- SDK commit: `{SDK_COMMIT}`
- SDK `mem_heap.c` SHA-256: `{SDK_SOURCE_SHA}`
- official toolchain archive SHA-256: `{TOOLCHAIN_ARCHIVE_SHA}`
- `pi32v2/bin/clang` SHA-256: `{CLANG_SHA}`
- rebuilt object SHA-256: `{OBJECT_SHA}`

## Reproduce

```sh
./reproduce_mem_heap.sh SDK_ROOT PI32_CLANG mem_heap.pi32.o
python3 analyze_heap_prefix.py
shasum -a 256 -c SHA256SUMS
```
"""
    (OUT / "report.md").write_text(report)
    (OUT / "validation.txt").write_text("\n".join(f"PASS\t{name}\t{detail}" for name, _, detail in checks) + "\n")
    files = ["reproduce_mem_heap.sh", "analyze_heap_prefix.py", "mem_heap.pi32.o", "evidence.json", "report.md", "validation.txt"]
    (OUT / "SHA256SUMS").write_text("\n".join(f"{sha(OUT / name)}  {name}" for name in files) + "\n")


if __name__ == "__main__":
    main()
