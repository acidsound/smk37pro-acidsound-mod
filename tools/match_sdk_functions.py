#!/usr/bin/env python3
"""Find exact public AC79 SDK ELF function bodies inside SMK app.bin.

This intentionally uses only the Python standard library. Exact matches are
high-confidence anchors; absence of a match is not evidence that a function is
absent because linked addresses and compiler options can change its bytes.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path


APP_BASE = 0x02000120
ELF_MAGIC = b"\x7fELF"
SHT_SYMTAB = 2
STT_FUNC = 2


class ElfError(RuntimeError):
    pass


@dataclass
class Section:
    name_offset: int
    section_type: int
    address: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass
class FunctionBytes:
    name: str
    address: int
    data: bytes


def c_string(table: bytes, offset: int) -> str:
    if offset >= len(table):
        raise ElfError("string-table offset is out of range")
    end = table.find(b"\0", offset)
    if end < 0:
        raise ElfError("unterminated ELF string")
    return table[offset:end].decode("utf-8", "replace")


def parse_elf_functions(raw: bytes, minimum: int, maximum: int) -> list[FunctionBytes]:
    if raw[:4] != ELF_MAGIC or raw[4] != 1 or raw[5] != 1:
        raise ElfError("expected a little-endian ELF32 file")
    if struct.unpack_from("<H", raw, 18)[0] != 0xF1:
        raise ElfError("expected Pi32v2 ELF machine 0xF1")

    section_offset = struct.unpack_from("<I", raw, 32)[0]
    section_entry_size, section_count = struct.unpack_from("<HH", raw, 46)
    if section_entry_size != 40:
        raise ElfError("unexpected ELF32 section-header size")

    sections: list[Section] = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        values = struct.unpack_from("<IIIIIIIIII", raw, offset)
        sections.append(
            Section(
                name_offset=values[0],
                section_type=values[1],
                address=values[3],
                offset=values[4],
                size=values[5],
                link=values[6],
                entry_size=values[9],
            )
        )

    functions: list[FunctionBytes] = []
    for section in sections:
        if section.section_type != SHT_SYMTAB:
            continue
        if section.link >= len(sections) or section.entry_size != 16:
            raise ElfError("invalid ELF symbol-table link or entry size")
        string_section = sections[section.link]
        strings = raw[string_section.offset : string_section.offset + string_section.size]
        count = section.size // section.entry_size
        for index in range(count):
            offset = section.offset + index * section.entry_size
            name_offset, value, size, info, _, section_index = struct.unpack_from(
                "<IIIBBH", raw, offset
            )
            if info & 0xF != STT_FUNC or not (minimum <= size <= maximum):
                continue
            if section_index == 0 or section_index >= len(sections):
                continue
            owner = sections[section_index]
            relative = value - owner.address
            if relative < 0 or relative + size > owner.size:
                continue
            body_offset = owner.offset + relative
            body = raw[body_offset : body_offset + size]
            name = c_string(strings, name_offset)
            if name and any(body):
                functions.append(FunctionBytes(name, value, body))
    return functions


def all_offsets(haystack: bytes, needle: bytes, limit: int = 2) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while len(offsets) < limit:
        found = haystack.find(needle, cursor)
        if found < 0:
            break
        offsets.append(found)
        cursor = found + 1
    return offsets


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sdk_elf", type=Path)
    parser.add_argument("app_bin", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ghidra-seeds", type=Path,
                        help="write address/name seeds for Smk37ApplyFunctionMatches.java")
    parser.add_argument("--minimum-size", type=int, default=12)
    parser.add_argument("--maximum-size", type=int, default=256)
    args = parser.parse_args()

    sdk = args.sdk_elf.read_bytes()
    app = args.app_bin.read_bytes()
    functions = parse_elf_functions(sdk, args.minimum_size, args.maximum_size)
    matches = []
    for function in functions:
        offsets = all_offsets(app, function.data)
        if len(offsets) == 1:
            matches.append(
                {
                    "name": function.name,
                    "sdk_address": function.address,
                    "size": len(function.data),
                    "app_offset": offsets[0],
                    "app_address": APP_BASE + offsets[0],
                }
            )
    matches.sort(key=lambda item: item["app_offset"])
    report = {
        "format": "smk37-sdk-exact-function-matches-v1",
        "sdk_functions_considered": len(functions),
        "unique_exact_matches": len(matches),
        "matches": matches,
        "caveat": "Exact matches are anchors only; relocated or optimized functions will not match.",
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    if args.ghidra_seeds:
        lines = [f"0x{item['app_address']:08x}\t{item['name']}" for item in matches]
        args.ghidra_seeds.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
