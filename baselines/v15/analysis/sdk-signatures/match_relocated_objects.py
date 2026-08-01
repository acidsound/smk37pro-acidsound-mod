#!/usr/bin/env python3
"""Relocation-aware pi32v2 object matcher for the exact official v15 app.

Relocated six-byte code instructions (or four-byte data words) are masked. A
candidate is defensible only when every fixed island matches, or at least two
unique 16-byte windows align at one function start and cover 24 fixed bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path

EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
APP_BASE = 0x02000000
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


def cstr(data: bytes, offset: int) -> str:
    if offset >= len(data):
        return ""
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
    relocations: dict[int, list[dict]] = {}
    for section in sections:
        if section.stype not in (SHT_RELA, SHT_REL):
            continue
        entries = relocations.setdefault(section.info, [])
        for off in range(section.offset, section.offset + section.size, section.entsize):
            roff, rinfo = struct.unpack_from("<II", raw, off)
            entries.append({"offset": roff, "type": rinfo & 0xff, "symbol": rinfo >> 8})
    return raw, sections, symbols, relocations


def offsets(data: bytes, needle: bytes) -> list[int]:
    out, pos = [], 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


def fixed_islands(size: int, masked: list[tuple[int, int]], minimum: int = 8) -> list[tuple[int, int]]:
    out, cursor = [], 0
    for start, end in masked:
        if start - cursor >= minimum:
            out.append((cursor, start))
        cursor = max(cursor, end)
    if size - cursor >= minimum:
        out.append((cursor, size))
    return out


def analyze(path: Path, app: bytes, window: int = 16) -> dict:
    raw, sections, symbols, relocations = parse_elf(path)
    reports = []
    code_fingerprints = []
    for name, value, size, info, shndx in symbols:
        if info & 0x0f != STT_FUNC or size < 8 or not name or not 0 < shndx < len(sections):
            continue
        section = sections[shndx]
        rel = value - section.address
        if rel < 0 or rel + size > section.size:
            continue
        body = raw[section.offset + rel:section.offset + rel + size]
        function_relocs = [r for r in relocations.get(shndx, []) if value <= r["offset"] < value + size]
        code_fingerprints.append({
            "name": name,
            "size": size,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "relocations": sorted(
                (r["offset"] - value, r["type"], r["symbol"]) for r in function_relocs
            ),
        })
        width = 6 if ".text" in section.name else 4
        masked = merge([(r["offset"] - value, min(size, r["offset"] - value + width)) for r in function_relocs])
        islands = fixed_islands(size, masked)
        strict = []
        if islands:
            anchor = max(islands, key=lambda x: x[1] - x[0])
            for hit in offsets(app, body[anchor[0]:anchor[1]]):
                start = hit - anchor[0]
                if 0 <= start <= len(app) - size and all(app[start+a:start+b] == body[a:b] for a, b in islands):
                    strict.append(start)
        clusters: dict[int, list[tuple[int, int]]] = {}
        for a, b in islands:
            for source in range(a, b - window + 1, max(2, window // 2)):
                hits = offsets(app, body[source:source + window])
                if len(hits) == 1:
                    start = hits[0] - source
                    if 0 <= start <= len(app) - size:
                        clusters.setdefault(start, []).append((source, source + window))
        ranked = []
        for start, spans in clusters.items():
            covered = set()
            for a, b in spans:
                covered.update(range(a, b))
            ranked.append({"app_offset": start, "app_address": APP_BASE + start,
                           "unique_windows": len(spans), "covered_fixed_bytes": len(covered)})
        ranked.sort(key=lambda x: (-x["covered_fixed_bytes"], -x["unique_windows"], x["app_offset"]))
        if strict or ranked:
            best = ranked[0] if ranked else None
            accepted = bool(strict) or bool(best and best["unique_windows"] >= 2 and best["covered_fixed_bytes"] >= 24)
            reports.append({
                "name": name, "size": size, "body_sha256": hashlib.sha256(body).hexdigest(),
                "relocation_count": len(function_relocs), "masked_ranges": masked,
                "fixed_bytes": sum(b-a for a, b in islands),
                "strict_masked_matches": strict, "best_window_cluster": best,
                "accepted_by_threshold": accepted,
            })
    canonical = json.dumps(
        sorted(code_fingerprints, key=lambda item: (item["name"], item["size"], item["body_sha256"])),
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return {
        "path": path.name,
        "function_count": len(code_fingerprints),
        "code_signature_sha256": hashlib.sha256(canonical).hexdigest(),
        "functions_with_hits": reports,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("app", type=Path)
    ap.add_argument("objects", type=Path, nargs="+")
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()
    app = args.app.read_bytes()
    digest = hashlib.sha256(app).hexdigest()
    if digest != EXPECTED_APP_SHA256:
        raise SystemExit(f"refusing non-official-v15 app: {digest}")
    objects = [analyze(path, app) for path in args.objects]
    accepted = [{"object": obj["path"], **fn} for obj in objects for fn in obj["functions_with_hits"] if fn["accepted_by_threshold"]]
    report = {
        "format": "smk37-v15-relocation-aware-object-matches-v1",
        "app": {"size": len(app), "sha256": digest, "runtime_base": APP_BASE},
        "criterion": "all fixed islands, or >=2 aligned unique 16-byte windows covering >=24 fixed bytes",
        "accepted": accepted,
        "objects": objects,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
