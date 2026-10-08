#!/usr/bin/env python3
"""Independent official-v15 checks for the R03 RAM ownership options."""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
APP = ROOT / "build/v15-official-app.bin"
OBJECT = ROOT / "baselines/v15/analysis/r03-owned-ram/heap-prefix-reservation/mem_heap.pi32.o"
REQUIREMENTS = ROOT / "baselines/v15/analysis/r03-owned-ram/requirements.md"

APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
OBJECT_SHA256 = "82fb6c5a2546861c6114442f556b573da739717c5f53cfbc31853337e36e5fb6"
SDK_SOURCE_SHA256 = "411cb79e74853a5b7ce9135514f59d8eafb5b098ced2f8acde08201fdfcf380c"
APP_BASE = 0x02000000
SBRK_VA = 0x0205E9DA
SBRK_SIZE = 0x62
BSS_START = 0x01C099D4
BSS_END = 0x01C4651C
OLD_BSS_SIZE = 0x3CB48
POINTER_SLOT = BSS_END
HEAP_BEGIN = 0x01C46520
FIXED_END = 0x01C465E0
HEAP_END = 0x01C7FD30
VOICE_SIZE = 0x9C
METADATA_SIZE = 8
SHT_SYMTAB, SHT_RELA, SHT_REL, STT_FUNC = 2, 4, 9, 2


@dataclass
class Section:
    name: str
    stype: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    entsize: int


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hx(value: int) -> str:
    return f"0x{value:08x}"


def cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    return data[offset:end if end >= 0 else len(data)].decode("utf-8", "replace")


def parse_elf(path: Path):
    raw = path.read_bytes()
    if raw[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", raw, 18)[0] != 0xF1:
        raise ValueError(f"expected little-endian pi32v2 ELF32: {path}")
    shoff = struct.unpack_from("<I", raw, 32)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", raw, 46)
    headers = [struct.unpack_from("<IIIIIIIIII", raw, shoff + i * shentsize) for i in range(shnum)]
    shstr = headers[shstrndx]
    names = raw[shstr[4]:shstr[4] + shstr[5]]
    sections = [Section(cstr(names, h[0]), h[1], h[3], h[4], h[5], h[6], h[7], h[9]) for h in headers]
    symbols = []
    for section in sections:
        if section.stype != SHT_SYMTAB:
            continue
        string_section = sections[section.link]
        strings = raw[string_section.offset:string_section.offset + string_section.size]
        for off in range(section.offset, section.offset + section.size, section.entsize):
            nameoff, value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", raw, off)
            symbols.append((cstr(strings, nameoff), value, size, info, shndx))
    relocations: dict[int, list[dict[str, int]]] = {}
    for section in sections:
        if section.stype not in (SHT_RELA, SHT_REL):
            continue
        entries = relocations.setdefault(section.info, [])
        for off in range(section.offset, section.offset + section.size, section.entsize):
            roff, rinfo = struct.unpack_from("<II", raw, off)
            entries.append({"offset": roff, "type": rinfo & 0xFF, "symbol": rinfo >> 8})
    return raw, sections, symbols, relocations


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
    for offset in range(len(data) - 5):
        value = int.from_bytes(data[offset + 2:offset + 6], "little")
        if start <= value < end:
            hits.append({
                "instruction": hx(APP_BASE + offset),
                "value": hx(value),
                "bytes": data[offset:offset + 6].hex(),
            })
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sdk-mem-heap", type=Path, help="optional pinned SDK mem_heap.c for source hash verification")
    args = ap.parse_args()

    app = APP.read_bytes()
    raw, sections, symbols, relocations = parse_elf(OBJECT)
    section_index = next(i for i, section in enumerate(sections) if section.name == ".mem_heap_code")
    section = sections[section_index]
    symbol = next(item for item in symbols if item[0] == "sbrk" and item[3] & 0x0F == STT_FUNC)
    _, value, size, _, shndx = symbol
    if shndx != section_index:
        raise SystemExit("sbrk is not in .mem_heap_code")

    object_body = raw[section.offset + value:section.offset + value + size]
    app_offset = SBRK_VA - APP_BASE
    v15_body = app[app_offset:app_offset + size]
    function_relocs = sorted(
        (r for r in relocations[section_index] if value <= r["offset"] < value + size),
        key=lambda item: item["offset"],
    )

    masked: set[int] = set()
    recovered: dict[str, int] = {}
    relocation_rows = []
    for relocation in function_relocs:
        relative = relocation["offset"] - value
        name = symbols[relocation["symbol"]][0]
        masked.update(range(relative, relative + 6))
        encoded = int.from_bytes(v15_body[relative + 2:relative + 6], "little")
        recovered[name] = encoded
        relocation_rows.append({"relative_offset": hx(relative), "symbol": name, "v15_value": hx(encoded)})

    fixed = [i for i in range(size) if i not in masked]
    fixed_equal = sum(object_body[i] == v15_body[i] for i in fixed)
    differing = [i for i, pair in enumerate(zip(object_body, v15_body)) if pair[0] != pair[1]]
    expected_differences = sorted(relative + delta for relative in (0x0E, 0x1E, 0x26) for delta in range(2, 6))
    pointer_hits = [
        {"value": hx(address), "app_offset": hx(hit)}
        for address in range(POINTER_SLOT, HEAP_BEGIN)
        for hit in raw_hits(app, address)
    ]
    prefix_mov_hits = mov_payload_hits(app, HEAP_BEGIN, FIXED_END)
    requirements = REQUIREMENTS.read_text(encoding="utf-8")

    old_span = HEAP_END - HEAP_BEGIN
    new_span = HEAP_END - FIXED_END
    heap_loss = old_span - new_span
    option_a_zero_size = OLD_BSS_SIZE + 4
    option_b_zero_size = FIXED_END - BSS_START

    checks: list[tuple[str, bool, object]] = [
        ("official-v15-app-sha256", sha256(APP) == APP_SHA256, sha256(APP)),
        ("pinned-mem-heap-object-sha256", sha256(OBJECT) == OBJECT_SHA256, sha256(OBJECT)),
        ("sbrk-address-and-size", size == SBRK_SIZE and len(v15_body) == SBRK_SIZE, f"{hx(SBRK_VA)} size={hx(size)}"),
        ("sbrk-three-relocated-instructions", [r["relative_offset"] for r in relocation_rows] == [hx(0x0E), hx(0x1E), hx(0x26)], relocation_rows),
        ("sbrk-all-80-non-relocated-bytes-exact", len(fixed) == fixed_equal == 80, f"{fixed_equal}/{len(fixed)}"),
        ("sbrk-only-relocation-payload-differs", differing == expected_differences, differing),
        ("sbrk-init-address", recovered.get("sbrk.__init_addr") == 0x01C32D94, hx(recovered.get("sbrk.__init_addr", 0))),
        ("heap-begin", recovered.get("HEAP_BEGIN") == HEAP_BEGIN, hx(recovered.get("HEAP_BEGIN", 0))),
        ("heap-end", recovered.get("HEAP_END") == HEAP_END, hx(recovered.get("HEAP_END", 0))),
        ("boot-bss-start-instruction", app[0x16:0x1C].hex() == "c3ffd499c001", app[0x16:0x1C].hex()),
        ("boot-bss-size-instruction", app[0x1E:0x24].hex() == "c2ff48cb0300", app[0x1E:0x24].hex()),
        ("boot-zero-loop-is-word-granular", app[0x24:0x2C].hex() == "a2a20203b105f25d", app[0x24:0x2C].hex()),
        ("bss-end-arithmetic", BSS_START + OLD_BSS_SIZE == BSS_END, hx(BSS_START + OLD_BSS_SIZE)),
        ("pointer-slot-is-four-byte-padding", POINTER_SLOT == BSS_END and HEAP_BEGIN - POINTER_SLOT == 4, f"{hx(POINTER_SLOT)}..{hx(HEAP_BEGIN)}"),
        ("pointer-slot-has-no-raw-absolute-reference", not pointer_hits, pointer_hits),
        ("option-a-zero-stops-at-old-heap", BSS_START + option_a_zero_size == HEAP_BEGIN, hx(BSS_START + option_a_zero_size)),
        ("option-b-zero-stops-at-new-heap", BSS_START + option_b_zero_size == FIXED_END, hx(BSS_START + option_b_zero_size)),
        ("option-b-zero-size-word-aligned", option_b_zero_size % 4 == 0, hx(option_b_zero_size)),
        ("option-b-prefix-size", FIXED_END - HEAP_BEGIN == 0xC0, hx(FIXED_END - HEAP_BEGIN)),
        ("option-b-voice-plus-metadata-fit", VOICE_SIZE + METADATA_SIZE <= FIXED_END - HEAP_BEGIN, f"needed={hx(VOICE_SIZE + METADATA_SIZE)} available={hx(FIXED_END - HEAP_BEGIN)}"),
        ("old-and-new-heap-bounds-aligned-32", HEAP_BEGIN % 0x20 == FIXED_END % 0x20 == 0, f"old={hx(HEAP_BEGIN)} new={hx(FIXED_END)}"),
        ("only-old-heap-begin-mov-in-prefix", prefix_mov_hits == [{"instruction": "0x0205e9f8", "value": "0x01c46520", "bytes": "c5ff2065c401"}], prefix_mov_hits),
        ("heap-loss-exactly-0xc0", heap_loss == 0xC0, f"old={hx(old_span)} new={hx(new_span)} loss={hx(heap_loss)}"),
        ("current-requirement-forbids-allocator-change", "R03 must not change the allocator or claimed polyphony." in requirements, "requirements.md Gate C"),
        ("current-requirement-forbids-absence-only-claim", "a hard BLOCK if the only evidence is absence of decoded xrefs" in requirements, "requirements.md Gate A.8"),
    ]

    if args.sdk_mem_heap:
        source_digest = sha256(args.sdk_mem_heap)
        if source_digest != SDK_SOURCE_SHA256:
            raise SystemExit(f"unexpected SDK mem_heap.c: {source_digest}")
        print(f"PASS\tpinned-sdk-mem-heap-source-sha256\t{source_digest}")

    failed = [name for name, ok, _ in checks if not ok]
    if failed:
        raise SystemExit("independent RAM checks failed: " + ", ".join(failed))

    evidence = {
        "format": "smk37-v15-r03-independent-ram-review-v1",
        "inputs": {
            "app": str(APP.relative_to(ROOT)),
            "app_sha256": sha256(APP),
            "mem_heap_object": str(OBJECT.relative_to(ROOT)),
            "mem_heap_object_sha256": sha256(OBJECT),
            "requirements": str(REQUIREMENTS.relative_to(ROOT)),
            "requirements_sha256": sha256(REQUIREMENTS),
            "sdk_mem_heap_source_sha256_expected": SDK_SOURCE_SHA256,
        },
        "sbrk": {
            "address": hx(SBRK_VA),
            "size": hx(size),
            "fixed_bytes_exact": fixed_equal,
            "fixed_bytes_total": len(fixed),
            "differing_offsets": differing,
            "relocations": relocation_rows,
            "recovered_symbols": {name: hx(address) for name, address in recovered.items()},
        },
        "boot_and_ranges": {
            "bss": f"{hx(BSS_START)}..{hx(BSS_END)}",
            "old_bss_zero_size": hx(OLD_BSS_SIZE),
            "option_a_bss_zero_size": hx(option_a_zero_size),
            "option_b_bss_zero_size": hx(option_b_zero_size),
            "option_b_bss_extension": hx(FIXED_END - BSS_END),
            "pointer_padding": f"{hx(POINTER_SLOT)}..{hx(HEAP_BEGIN)}",
            "reserved_prefix": f"{hx(HEAP_BEGIN)}..{hx(FIXED_END)}",
            "old_heap_span": hx(old_span),
            "new_heap_span": hx(new_span),
            "heap_loss": hx(heap_loss),
            "heap_loss_percent": heap_loss * 100.0 / old_span,
        },
        "decisions": {
            "option_a_anchor": "PASS",
            "option_a_complete_candidate": "BLOCK",
            "option_a_exception": "NOT JUSTIFIED",
            "option_b_gate_a_static_ownership": "PASS IF BOTH EXACT PATCHES ARE APPLIED",
            "option_b_current_requirements": "BLOCK",
            "option_b_checkpoint_exception": "JUSTIFIABLE FOR OFFLINE CHECKPOINT WORK ONLY; NOT A FLASH PASS",
            "r03_overall": "BLOCK",
        },
        "validation": [{"check": name, "status": "PASS", "detail": str(detail)} for name, _, detail in checks],
    }
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUT / "validation.txt").write_text(
        "\n".join(f"PASS\t{name}\t{detail}" for name, _, detail in checks) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
