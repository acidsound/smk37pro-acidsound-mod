#!/usr/bin/env python3
"""Conservative, standard-library scan of the pinned AC79 SDK against exact SMK37 v15.

This tool verifies the artifact and SDK revision, inventories the relevant GNU
archives, performs unique exact function matching from the SDK's pi32v2 ELF,
and records product-side byte/string/constant/pointer fingerprints. It does not
modify firmware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

APP_BASE = 0x02000000
EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
EXPECTED_SDK_COMMIT = "e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d"
EXPECTED = {
    "cpu/wl82/liba/lib_midi_dec.a": "3f4a38dbec69eb2f85c56838eaa461252c8ee0e419211d06aebf46ce9bc62f03",
    "cpu/wl82/tools/loader_tools/sdk.elf": "250b0534fee9f57208b42e38c97c36982875fac901db1d9979e781f0d26e0cf3",
}
SELECTED_MEMBERS = {
    "cpu/wl82/liba/lib_midi_dec.a": {
        "midi_fread_tone.o", "midi_synth.o", "midi_tabs.o"
    },
    "cpu/wl82/liba/audio_server.a": {
        "midi_ctrl_decoder.c.o", "midi_dec.c.o", "midi_event.c.o", "midi_play.c.o"
    },
}
USB_ANCHORS = {
    "usb_set_pull_up", "usb_set_pull_down", "usb_set_direction",
    "usb_output", "usb_set_die"
}
MIDI_NAMES = ("midi", "note_on", "note_off", "pitchbend", "glissando")
SHT_SYMTAB = 2
STT_FUNC = 2


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def all_offsets(data: bytes, needle: bytes, limit: int | None = None) -> list[int]:
    out: list[int] = []
    pos = 0
    while limit is None or len(out) < limit:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        out.append(pos)
        pos += 1
    return out


def ar_members(path: Path) -> list[dict]:
    raw = path.read_bytes()
    if raw[:8] != b"!<arch>\n":
        raise ValueError(f"not a GNU archive: {path}")
    names = b""
    out = []
    pos = 8
    while pos + 60 <= len(raw):
        header = raw[pos:pos + 60]
        pos += 60
        if header[58:60] != b"`\n":
            raise ValueError(f"bad archive member header at {pos - 60}")
        raw_name = header[:16].decode("ascii", "replace").rstrip()
        size = int(header[48:58].decode("ascii").strip())
        body = raw[pos:pos + size]
        pos += size + (size & 1)
        if raw_name == "//":
            names = body
            continue
        if raw_name in ("/", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        name = raw_name.rstrip("/")
        if raw_name.startswith("/") and raw_name[1:].isdigit() and names:
            start = int(raw_name[1:])
            end = names.find(b"/\n", start)
            name = names[start:end].decode("utf-8", "replace")
        magic = "llvm-bitcode" if body[:4] == b"BC\xc0\xde" else "elf" if body[:4] == b"\x7fELF" else "other"
        out.append({"name": name, "size": len(body), "sha256": sha256(body), "format": magic})
    return out


@dataclass
class Section:
    stype: int
    address: int
    offset: int
    size: int
    link: int
    entsize: int


def cstr(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset)
    if offset >= len(data) or end < 0:
        return ""
    return data[offset:end].decode("utf-8", "replace")


def elf_functions(raw: bytes, minimum: int = 12, maximum: int = 256) -> list[dict]:
    if raw[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", raw, 18)[0] != 0xF1:
        raise ValueError("expected little-endian pi32v2 ELF32 machine 0xf1")
    shoff = struct.unpack_from("<I", raw, 32)[0]
    shentsize, shnum = struct.unpack_from("<HH", raw, 46)
    sections = []
    for i in range(shnum):
        h = struct.unpack_from("<IIIIIIIIII", raw, shoff + i * shentsize)
        sections.append(Section(h[1], h[3], h[4], h[5], h[6], h[9]))
    out = []
    for section in sections:
        if section.stype != SHT_SYMTAB or section.entsize != 16:
            continue
        string_section = sections[section.link]
        strings = raw[string_section.offset:string_section.offset + string_section.size]
        for off in range(section.offset, section.offset + section.size, section.entsize):
            nameoff, value, size, info, _other, shndx = struct.unpack_from("<IIIBBH", raw, off)
            if info & 0x0f != STT_FUNC or not minimum <= size <= maximum:
                continue
            if shndx == 0 or shndx >= len(sections):
                continue
            owner = sections[shndx]
            rel = value - owner.address
            if rel < 0 or rel + size > owner.size:
                continue
            body = raw[owner.offset + rel:owner.offset + rel + size]
            name = cstr(strings, nameoff)
            if name and any(body):
                out.append({"name": name, "sdk_address": value, "size": size, "body": body})
    return out


def unique_exact_matches(functions: list[dict], app: bytes) -> list[dict]:
    out = []
    for fn in functions:
        hits = all_offsets(app, fn["body"], 2)
        if len(hits) == 1:
            offset = hits[0]
            out.append({
                "name": fn["name"], "sdk_address": fn["sdk_address"],
                "size": fn["size"], "body_sha256": sha256(fn["body"]),
                "app_offset": offset, "app_address": APP_BASE + offset,
            })
    return sorted(out, key=lambda item: item["app_offset"])


def internal_pointer_runs(app: bytes, count: int = 11, code_end: int = 0x57000) -> list[dict]:
    out = []
    for offset in range(0, len(app) - 4 * count + 1, 4):
        values = struct.unpack_from(f"<{count}I", app, offset)
        if all(APP_BASE <= value < APP_BASE + code_end and value % 2 == 0 for value in values):
            before_ok = offset < 4 or not (APP_BASE <= struct.unpack_from("<I", app, offset - 4)[0] < APP_BASE + code_end)
            after = offset + 4 * count
            after_ok = after + 4 > len(app) or not (APP_BASE <= struct.unpack_from("<I", app, after)[0] < APP_BASE + code_end)
            if before_ok and after_ok:
                out.append({"offset": offset, "addresses": list(values)})
    return out


def git_head(sdk: Path) -> str:
    return subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"], text=True).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sdk_root", type=Path)
    ap.add_argument("app_bin", type=Path)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args()

    sdk = args.sdk_root.resolve()
    app = args.app_bin.read_bytes()
    app_hash = sha256(app)
    if app_hash != EXPECTED_APP_SHA256:
        raise SystemExit(f"refusing non-official-v15 app: {app_hash}")
    head = git_head(sdk)
    if head != EXPECTED_SDK_COMMIT:
        raise SystemExit(f"refusing unpinned SDK revision: {head}")

    archive_reports = {}
    file_hashes = {}
    for rel, selected in SELECTED_MEMBERS.items():
        path = sdk / rel
        digest = sha256(path.read_bytes())
        file_hashes[rel] = {"size": path.stat().st_size, "sha256": digest}
        if rel in EXPECTED and digest != EXPECTED[rel]:
            raise SystemExit(f"hash mismatch for {rel}: {digest}")
        members = ar_members(path)
        archive_reports[rel] = [m for m in members if m["name"] in selected]

    elf_rel = "cpu/wl82/tools/loader_tools/sdk.elf"
    elf_raw = (sdk / elf_rel).read_bytes()
    elf_hash = sha256(elf_raw)
    if elf_hash != EXPECTED[elf_rel]:
        raise SystemExit(f"hash mismatch for {elf_rel}: {elf_hash}")
    file_hashes[elf_rel] = {"size": len(elf_raw), "sha256": elf_hash}
    functions = elf_functions(elf_raw)
    matches = unique_exact_matches(functions, app)

    strings = {}
    for text in [b"midi_route", b"Keys Channel-", b"Pad Bank-"]:
        strings[text.decode()] = all_offsets(app, text)

    rates = struct.pack("<9I", 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000)
    regions = []
    for name, start, end in [
        ("raw_midi_stream_parser", 0x1050, 0x1388),
        ("product_midi_message_handler", 0x1E64A, 0x1E722),
        ("product_midi_handler_callsite", 0x2D1B4, 0x2D1F4),
    ]:
        body = app[start:end]
        regions.append({"name": name, "offset": start, "address": APP_BASE + start,
                        "size": len(body), "sha256": sha256(body), "bytes": body.hex()})

    report = {
        "format": "smk37-v15-pinned-ac79-sdk-signatures-v1",
        "inputs": {
            "app": {"size": len(app), "sha256": app_hash, "runtime_base": APP_BASE},
            "sdk_commit": head,
            "files": file_hashes,
        },
        "archives": archive_reports,
        "sdk_elf_exact": {
            "functions_considered": len(functions),
            "unique_exact_matches": len(matches),
            "usb_anchors": [m for m in matches if m["name"] in USB_ANCHORS],
            "midi_named_matches": [m for m in matches if any(x in m["name"].lower() for x in MIDI_NAMES)],
            "all_matches": matches,
        },
        "v15_fingerprints": {
            "raw_regions": regions,
            "strings": strings,
            "sample_rate_sequence": {
                "values_hz": [48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000],
                "offsets": all_offsets(app, rates),
                "classification": "rejected: immediately followed by USB Audio Class interface descriptors",
            },
            "eleven_pointer_runs": internal_pointer_runs(app),
        },
        "policy": "Exact and relocation-aware matches are anchors. A v15 synth/API identity requires two independent specific matches.",
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
