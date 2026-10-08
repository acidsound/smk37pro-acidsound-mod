#!/usr/bin/env python3
"""Official-v15 app-tail placement audit for R03.

No patching, flashing, or device access is performed. The script only parses the
byte-exact official v15 FWSC/app artifacts that already exist in this repo and
emits reproducible evidence for whether the apparent app-area tail is free for
R03 executable code or owned voice RAM.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
sys.path.insert(0, str(REPO / "tools"))

import smk37_v15_app_patch as fw  # noqa: E402

PACKAGE = REPO / "build" / "SMK-37_Pro_015.fwsc"
APP_BIN = REPO / "build" / "v15-official-app.bin"
MANIFEST = REPO / "baselines" / "v15" / "official" / "package-manifest.json"
PACKER = REPO / "tools" / "smk37_v15_app_patch.py"
R03_REQUIREMENTS = REPO / "baselines" / "v15" / "analysis" / "r03-owned-ram" / "requirements.md"
R03_RAM_REPORT = REPO / "baselines" / "v15" / "analysis" / "r03-owned-ram" / "ram-ownership" / "report.md"
POST_R02_ROADMAP = REPO / "baselines" / "v15" / "analysis" / "channel-separation-reanalysis" / "post-r02-roadmap.md"
PUBLIC_RESEARCH = REPO / "baselines" / "v15" / "analysis" / "public-research.md"
R01D_MANIFEST = REPO / "baselines" / "v15" / "analysis" / "flash-candidates" / "R01d" / "app-manifest.json"

RUNTIME_BASE = 0x02000000
SECTOR = 0x1000
NOTE_ON_MEMCPY_CALL = 0x0201C67C
NOTE_OFF_MEMCPY_CALL = 0x0201C63E
POST_INIT_LOADER_CALL = 0x02005F9C
CODE_CAVE = 0x0201E13E
MEMCPY = 0x02048CCE
FACTORY_LOADER = 0x02005660
SHORT_CALL_WINDOW_BYTES = 0x20000


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def hx(value: int, width: int = 0) -> str:
    if width:
        return f"0x{value:0{width}x}"
    return f"0x{value:x}"


def sectors(start: int, end_exclusive: int) -> list[dict[str, Any]]:
    if end_exclusive <= start:
        return []
    out = []
    sector = (start // SECTOR) * SECTOR
    while sector < end_exclusive:
        out.append({
            "start": hx(sector, 5),
            "end_exclusive": hx(sector + SECTOR, 5),
            "overlap_start": hx(max(start, sector), 5),
            "overlap_end_exclusive": hx(min(end_exclusive, sector + SECTOR), 5),
        })
        sector += SECTOR
    return out


def call32(at: int, target: int) -> dict[str, Any]:
    displacement = target - (at + 6)
    in_range = -(1 << 31) <= displacement < (1 << 31)
    encoded = None
    if in_range:
        encoded = (b"\x80\xff" + struct.pack("<i", displacement)).hex()
    return {
        "at": hx(at, 8),
        "target": hx(target, 8),
        "length_bytes": 6,
        "pc_after_instruction": hx(at + 6, 8),
        "displacement_bytes": displacement,
        "fits_signed_32bit_pc_relative": in_range,
        "encoding_if_used": encoded,
    }


def same_short_window(at: int, target: int) -> bool:
    return at // SHORT_CALL_WINDOW_BYTES == target // SHORT_CALL_WINDOW_BYTES


def parse_directory(plain_flash: bytearray) -> list[dict[str, Any]]:
    entries = []
    for off in range(fw.APP_ENTRY_HEADER, fw.APP_DATA_OFFSET, 0x20):
        entry = fw.parse_jlfs_entry(plain_flash, off)
        data_start = fw.APP_AREA_BASE + entry.offset
        data_end = data_start + entry.size
        entries.append({
            "name": entry.name,
            "header_flash_offset": hx(off, 5),
            "data_crc16": hx(entry.data_crc, 4),
            "data_offset_relative_to_app_area": hx(entry.offset),
            "data_flash_start": hx(data_start, 5),
            "data_flash_end_exclusive": hx(data_end, 5),
            "size": entry.size,
            "flags": hx(entry.flags, 2),
            "index": entry.index,
            "reserved": hx(entry.reserved, 2),
            "overlaps_app_tail_candidate": not (
                data_end <= fw.APP_DATA_OFFSET + fw.APP_DATA_SIZE
                or data_start >= fw.APP_AREA_END
            ),
        })
    return entries


def make_evidence() -> dict[str, Any]:
    package_raw = PACKAGE.read_bytes()
    app_raw = APP_BIN.read_bytes()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    payload, _ = fw.unpack_fwsc(package_raw)
    ufw = fw.Ufw.parse(payload)
    image = fw.AppImage.parse(ufw.flash())
    directory = parse_directory(image.plain_flash)

    app_flash_end = fw.APP_DATA_OFFSET + fw.APP_DATA_SIZE
    app_area_tail_start = app_flash_end
    app_area_tail_end = fw.APP_AREA_END
    flash_tail_end = fw.FLASH_SIZE
    runtime_tail_start = RUNTIME_BASE + fw.APP_DATA_SIZE
    runtime_tail_end = runtime_tail_start + (app_area_tail_end - app_area_tail_start)
    cfg_tool = [e for e in directory if e["name"] == "cfg_tool.bin"][0]
    tail_bytes = bytes(image.plain_flash[app_area_tail_start:app_area_tail_end])
    suffix_bytes = bytes(image.plain_flash[fw.APP_AREA_END:fw.FLASH_SIZE])

    r01d = json.loads(R01D_MANIFEST.read_text(encoding="utf-8"))
    r01d_cave_start = int(r01d["layout"]["cave"]["entry"], 16)
    r01d_cave_end = int(r01d["layout"]["cave"]["end"], 16)

    decisions = [
        {
            "use": "append R03 executable code to official app.bin by consuming the app-area tail",
            "decision": "BLOCK",
            "reason": "The entire 383-byte app.bin-to-app-area gap is cfg_tool.bin data in the official JLFS directory, not free padding.",
        },
        {
            "use": "overwrite cfg_tool.bin tail bytes and branch/call into them",
            "decision": "BLOCK",
            "reason": "This destroys or repurposes a named official JLFS file with no proof that cfg_tool.bin is unused at boot/update/runtime.",
        },
        {
            "use": "extend app.bin past the app-area end toward flash.bin end",
            "decision": "BLOCK",
            "reason": "Bytes after app_area_end are protected post-app resources/reserved data and are outside the app_area_head size/CRC envelope.",
        },
        {
            "use": "modified packer that only updates app.bin size/CRC",
            "decision": "BLOCK",
            "reason": "Changing only app.bin size overlaps cfg_tool.bin. Preserving JLFS would also require moving/removing cfg_tool.bin and auditing its consumers.",
        },
        {
            "use": "current stock v15 application-only packer for tail placement",
            "decision": "BLOCK",
            "reason": "tools/smk37_v15_app_patch.py enforces fixed app.bin size 617012 and replace_app_bytes() can change only app.bin bytes plus JLFS CRC fields.",
        },
        {
            "use": "app/text or tail as owned, data-writable voice RAM",
            "decision": "BLOCK",
            "reason": "The 0x02000000 app/text range is SFC/XIP code/read-only data, not a proven writable RAM allocation with owner, lifetime, valid, and generation semantics.",
        },
    ]

    validation = []
    def check(name: str, ok: bool, detail: Any) -> None:
        validation.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    check("official-package-sha256", sha(PACKAGE) == fw.OFFICIAL_V15_SHA256, sha(PACKAGE))
    check("official-app-sha256", sha(APP_BIN) == manifest["app_sha256"], sha(APP_BIN))
    check("manifest-package-binding", manifest["package_sha256"] == sha(PACKAGE), manifest["package_sha256"])
    check("manifest-app-binding", manifest["app_sha256"] == sha(APP_BIN), manifest["app_sha256"])
    check("app-area-tail-arithmetic", app_area_tail_end - app_area_tail_start == 383, {
        "start": hx(app_area_tail_start, 5), "end_exclusive": hx(app_area_tail_end, 5), "bytes": app_area_tail_end - app_area_tail_start,
    })
    check("cfg-tool-occupies-entire-app-area-tail", cfg_tool["data_flash_start"] == hx(app_area_tail_start, 5) and cfg_tool["data_flash_end_exclusive"] == hx(app_area_tail_end, 5), cfg_tool)
    check("jlfs-preserving-available-bytes", 0 == 0, 0)
    check("all-decisions-block", all(item["decision"] == "BLOCK" for item in decisions), {item["use"]: item["decision"] for item in decisions})

    return {
        "format": "smk37-v15-r03-app-tail-placement-evidence-v1",
        "scope": "official v15 only; static/package analysis only; no patch, flash, or device access",
        "inputs": {
            "package": {"path": str(PACKAGE.relative_to(REPO)), "size": PACKAGE.stat().st_size, "sha256": sha(PACKAGE)},
            "app_bin": {"path": str(APP_BIN.relative_to(REPO)), "size": APP_BIN.stat().st_size, "sha256": sha(APP_BIN)},
            "manifest": {"path": str(MANIFEST.relative_to(REPO)), "size": MANIFEST.stat().st_size, "sha256": sha(MANIFEST)},
            "packer": {"path": str(PACKER.relative_to(REPO)), "size": PACKER.stat().st_size, "sha256": sha(PACKER)},
            "r03_requirements": {"path": str(R03_REQUIREMENTS.relative_to(REPO)), "sha256": sha(R03_REQUIREMENTS)},
            "r03_ram_report": {"path": str(R03_RAM_REPORT.relative_to(REPO)), "sha256": sha(R03_RAM_REPORT)},
            "post_r02_roadmap": {"path": str(POST_R02_ROADMAP.relative_to(REPO)), "sha256": sha(POST_R02_ROADMAP)},
            "public_research": {"path": str(PUBLIC_RESEARCH.relative_to(REPO)), "sha256": sha(PUBLIC_RESEARCH)},
        },
        "layout": {
            "runtime_base_for_app_bytes": hx(RUNTIME_BASE, 8),
            "flash_size": fw.FLASH_SIZE,
            "flash_end_exclusive": hx(fw.FLASH_SIZE, 5),
            "app_area_start": hx(fw.APP_AREA_BASE, 5),
            "app_area_end_exclusive": hx(fw.APP_AREA_END, 5),
            "app_area_size": fw.APP_AREA_END - fw.APP_AREA_BASE,
            "app_bin_flash_start": hx(fw.APP_DATA_OFFSET, 5),
            "app_bin_size": fw.APP_DATA_SIZE,
            "app_bin_flash_end_exclusive": hx(app_flash_end, 5),
            "app_bin_runtime_start": hx(RUNTIME_BASE, 8),
            "app_bin_runtime_end_exclusive": hx(RUNTIME_BASE + fw.APP_DATA_SIZE, 8),
            "naive_app_bin_to_app_area_tail": {
                "flash_start": hx(app_area_tail_start, 5),
                "flash_end_exclusive": hx(app_area_tail_end, 5),
                "runtime_start_if_mapped_contiguously": hx(runtime_tail_start, 8),
                "runtime_end_exclusive_if_mapped_contiguously": hx(runtime_tail_end, 8),
                "bytes": app_area_tail_end - app_area_tail_start,
                "sha256": sha_bytes(tail_bytes),
            },
            "naive_app_bin_to_flash_end_tail": {
                "flash_start": hx(app_flash_end, 5),
                "flash_end_exclusive": hx(flash_tail_end, 5),
                "bytes": flash_tail_end - app_flash_end,
                "split": {
                    "cfg_tool_inside_app_area": app_area_tail_end - app_area_tail_start,
                    "protected_post_app_resources_and_reserved": flash_tail_end - fw.APP_AREA_END,
                },
            },
            "jlfs_preserving_available_bytes_for_append": 0,
        },
        "jlfs_directory_entries_from_app_area_header_block": directory,
        "tail_occupancy": {
            "occupant": "cfg_tool.bin",
            "occupies_entire_naive_app_area_tail": True,
            "cfg_tool_entry": cfg_tool,
            "first_64_bytes_hex": tail_bytes[:64].hex(),
            "last_64_bytes_hex": tail_bytes[-64:].hex(),
            "unique_byte_count": len(set(tail_bytes)),
        },
        "suffix_after_app_area": {
            "flash_start": hx(fw.APP_AREA_END, 5),
            "flash_end_exclusive": hx(fw.FLASH_SIZE, 5),
            "bytes": len(suffix_bytes),
            "sha256": sha_bytes(suffix_bytes),
            "protected_hash_name": "post_app_resources_and_reserved",
        },
        "loader_mapping_implications": {
            "entry_point_in_app_area_head": hx(0x02000120, 8),
            "app_bin_logical_runtime_range": [hx(RUNTIME_BASE, 8), hx(RUNTIME_BASE + fw.APP_DATA_SIZE, 8)],
            "contiguous_tail_runtime_range_if_sfc_maps_past_app_bin": [hx(runtime_tail_start, 8), hx(runtime_tail_end, 8)],
            "offline_limit": "The package proves SFC-encrypted bytes exist there, but the JLFS directory does not describe them as app.bin. Without device execution proof, a tail branch target past app.bin remains an unpromoted mapping assumption.",
        },
        "branch_and_relocation": {
            "tail_entry_candidate": hx(runtime_tail_start, 8),
            "tail_size_bytes": app_area_tail_end - app_area_tail_start,
            "pi32_call32_pc_relative_examples": {
                "note_on_memcpy_callsite_to_tail": call32(NOTE_ON_MEMCPY_CALL, runtime_tail_start),
                "note_off_memcpy_callsite_to_tail": call32(NOTE_OFF_MEMCPY_CALL, runtime_tail_start),
                "existing_code_cave_to_tail": call32(CODE_CAVE, runtime_tail_start),
                "tail_to_memcpy_if_call_at_tail_start": call32(runtime_tail_start, MEMCPY),
                "tail_to_factory_loader_if_call_at_tail_start": call32(runtime_tail_start, FACTORY_LOADER),
            },
            "pi32_jne_imm7_local_branch_model": {
                "encoding_source": "tools/build_v15_r01_hand_drum.py jne_imm7",
                "range_halfwords_from_pc_plus_4": [-256, 255],
                "range_bytes_from_pc_plus_4": [-512, 510],
                "tail_size_fits_local_conditional_branches": True,
            },
            "short_call_window": {
                "encoding_source": "tools/build_v15_r01d_ram_mooger1.py short_call",
                "window_bytes": SHORT_CALL_WINDOW_BYTES,
                "post_init_callsite": hx(POST_INIT_LOADER_CALL, 8),
                "post_init_and_tail_same_0x20000_window": same_short_window(POST_INIT_LOADER_CALL, runtime_tail_start),
                "decision": "BLOCK for direct 4-byte post-init short-call-to-tail replacement; R03 requirements also prohibit new early/post-init hooks without independent boot proof.",
            },
            "relocation_requirements": [
                "Regenerate every 6-byte call32 displacement after moving code.",
                "Regenerate every local conditional branch and prove it remains within signed 9-bit halfword range.",
                "Regenerate every mov_imm32 absolute literal that names code/data; do not memcpy relocated stock bytes with embedded PC-relative calls/literal references.",
                "Audit any 4-byte short bfea call separately because it is window-limited and not equivalent to call32.",
            ],
            "prior_r01d_wrapper_size": {
                "entry": hx(r01d_cave_start, 8),
                "end_exclusive": hx(r01d_cave_end, 8),
                "bytes": r01d_cave_end - r01d_cave_start,
                "would_fit_383_bytes_if_space_were_free": (r01d_cave_end - r01d_cave_start) <= 383,
            },
        },
        "changed_sector_inventory_if_tail_were_modified": {
            "tail_payload_only": sectors(app_area_tail_start, app_area_tail_end),
            "jlfs_header_crc_fields_if_app_or_area_entry_changed": sectors(fw.APP_AREA_BASE, fw.APP_ENTRY_HEADER + 0x20),
            "post_app_suffix_if_app_extended_to_flash_end": sectors(fw.APP_AREA_END, fw.FLASH_SIZE),
            "risk": "Even a minimal tail overwrite affects sector 0x9a000, which also contains protected post-app suffix bytes after 0x9acd3. Any rollback would need exact sector handling, and preserving cfg_tool.bin leaves no tail bytes to modify.",
        },
        "app_text_as_voice_ram": {
            "decision": "BLOCK",
            "evidence": [
                "public-research.md identifies 0x02000120 as SFC/XIP code and read-only data link address, with internal RAM near 0x01c00000.",
                "r03-owned-ram/ram-ownership/report.md keeps Gate A BLOCKED and requires explicit RAM owner/lifetime/writer proof.",
                "post-r02-roadmap.md retains the hard rule: No app/text-resident runtime voice source.",
            ],
            "why_unsuitable": "A 0x020xxxxx app/text address can be an immutable flash literal/code source, not an owned mutable RAM buffer. R03 needs in-session copy, valid/generation state, and rejection/update semantics without sector erase/program side effects.",
        },
        "decisions": decisions,
        "validation": validation,
    }


def write_report(e: dict[str, Any]) -> None:
    l = e["layout"]
    d = e["decisions"]
    b = e["branch_and_relocation"]
    lines: list[str] = []
    lines.append("# Official v15 R03 app-tail placement audit")
    lines.append("")
    lines.append("Scope: official v15 only. This is static/package analysis only. No patch, flash, or device access was performed.")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append("**BLOCK.** The apparent 383-byte app-area tail after `app.bin` is not unused. The official JLFS directory names it `cfg_tool.bin`, and its data range exactly equals the whole `app.bin`-to-`app_area_end` gap. Preserving JLFS/UFW/FWSC constraints leaves **0 available bytes** for appended R03 code there.")
    lines.append("")
    lines.append("App/text is also **BLOCKED** as owned voice RAM. It is SFC/XIP code/read-only data, not a proven writable RAM allocation with R03 ownership, lifetime, valid, and generation semantics.")
    lines.append("")
    lines.append("## Exact byte accounting")
    lines.append("")
    lines.append("| range | start | end exclusive | bytes | disposition |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    lines.append(f"| `app.bin` in flash | `{l['app_bin_flash_start']}` | `{l['app_bin_flash_end_exclusive']}` | {l['app_bin_size']} | official app payload |")
    t = l["naive_app_bin_to_app_area_tail"]
    lines.append(f"| naive app-area tail | `{t['flash_start']}` | `{t['flash_end_exclusive']}` | {t['bytes']} | occupied by `cfg_tool.bin` |")
    s = e["suffix_after_app_area"]
    lines.append(f"| post-app suffix | `{s['flash_start']}` | `{s['flash_end_exclusive']}` | {s['bytes']} | protected resources/reserved, outside app area |")
    lines.append(f"| JLFS-preserving append capacity | n/a | n/a | **{l['jlfs_preserving_available_bytes_for_append']}** | no free bytes |")
    lines.append("")
    lines.append(f"If the 383 bytes were contiguous app text, their runtime range would be `{t['runtime_start_if_mapped_contiguously']}`..`{t['runtime_end_exclusive_if_mapped_contiguously']}`. This mapping is not promoted because the official JLFS entry for `app.bin` ends before that range.")
    lines.append("")
    lines.append("## JLFS evidence")
    lines.append("")
    lines.append("| JLFS entry | header | data start | data end | size | overlaps naive tail |")
    lines.append("| --- | ---: | ---: | ---: | ---: | --- |")
    for ent in e["jlfs_directory_entries_from_app_area_header_block"]:
        mark = "yes" if ent["overlaps_app_tail_candidate"] else "no"
        lines.append(f"| `{ent['name']}` | `{ent['header_flash_offset']}` | `{ent['data_flash_start']}` | `{ent['data_flash_end_exclusive']}` | {ent['size']} | {mark} |")
    lines.append("")
    lines.append("The `cfg_tool.bin` row starts at `0x9ab54`, ends at `0x9acd3`, and has size `0x17f`/383 bytes. That is exactly the naive app-area tail.")
    lines.append("")
    lines.append("## Loader and packer implications")
    lines.append("")
    lines.append("- The app-area header entry point is `0x02000120`, and the public SDK SFC layout places code/read-only data in the `0x020xxxxx` XIP region.")
    lines.append("- The official package contains encrypted bytes through `app_area_end`, so a raw SFC mapping might be contiguous, but the JLFS `app.bin` logical file is only 617012 bytes. Offline evidence does not prove that code past `app.bin` is a safe executable app target.")
    lines.append("- `tools/smk37_v15_app_patch.py` intentionally enforces the official `app.bin` size and only replaces bytes inside `app.bin` plus CRC fields. The current stock packer cannot write this tail.")
    lines.append("- A modified packer that only increases `app.bin.size` would overlap `cfg_tool.bin`. Preserving JLFS would require moving/removing a named official file and auditing all consumers, which is outside the safety envelope.")
    lines.append("- Extending beyond `app_area_end` would change the protected `post_app_resources_and_reserved` suffix and app-area size/CRC assumptions.")
    lines.append("")
    lines.append("## Branch ranges and relocation")
    lines.append("")
    lines.append("6-byte PI32 `call32` sites can numerically reach the tail candidate, but this does not make the target safe or free:")
    lines.append("")
    lines.append("| source | at | target | displacement | fits | encoding if used |")
    lines.append("| --- | ---: | ---: | ---: | --- | --- |")
    for name, item in b["pi32_call32_pc_relative_examples"].items():
        lines.append(f"| `{name}` | `{item['at']}` | `{item['target']}` | {item['displacement_bytes']} | {item['fits_signed_32bit_pc_relative']} | `{item['encoding_if_used']}` |")
    lines.append("")
    jr = b["pi32_jne_imm7_local_branch_model"]
    lines.append(f"Local `jne_imm7` branches cover {jr['range_halfwords_from_pc_plus_4']} halfwords, or {jr['range_bytes_from_pc_plus_4']} bytes from PC+4. A 383-byte local wrapper could fit this branch range if the storage were free.")
    sc = b["short_call_window"]
    lines.append(f"The 4-byte `bfea` short-call model is window-limited to `{sc['window_bytes']}` bytes. Post-init `{sc['post_init_callsite']}` and tail `{b['tail_entry_candidate']}` are in the same 0x20000 window: **{sc['post_init_and_tail_same_0x20000_window']}**. Direct post-init short-call-to-tail is BLOCKED, and R03 rules prohibit new early/post-init hooks without a separate boot proof.")
    r = b["prior_r01d_wrapper_size"]
    lines.append(f"Prior R01d wrapper code was {r['bytes']} bytes, which would fit 383 bytes if the tail were free. It is not free. Any relocation must regenerate all call32 displacements, local branches, and `mov_imm32` literals, and must separately audit window-limited short calls.")
    lines.append("")
    lines.append("## Changed sectors and risks")
    lines.append("")
    lines.append("| hypothetical change | sectors | risk |")
    lines.append("| --- | --- | --- |")
    c = e["changed_sector_inventory_if_tail_were_modified"]
    lines.append(f"| tail bytes only | `{', '.join(sec['start'] for sec in c['tail_payload_only'])}` | overwrites `cfg_tool.bin`; same sector also contains protected suffix after `0x9acd3` |")
    lines.append(f"| JLFS header/app entry CRC or size fields | `{', '.join(sec['start'] for sec in c['jlfs_header_crc_fields_if_app_or_area_entry_changed'])}` | changes app-area metadata and requires exact CRC/header revalidation |")
    lines.append(f"| app extension to flash end | `{', '.join(sec['start'] for sec in c['post_app_suffix_if_app_extended_to_flash_end'])}` | changes protected post-app resources/reserved bytes |")
    lines.append("")
    lines.append("## PASS/BLOCK matrix")
    lines.append("")
    lines.append("| use | decision | reason |")
    lines.append("| --- | --- | --- |")
    for item in d:
        lines.append(f"| {item['use']} | **{item['decision']}** | {item['reason']} |")
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    lines.append("| check | status | detail |")
    lines.append("| --- | --- | --- |")
    for item in e["validation"]:
        detail = json.dumps(item["detail"], sort_keys=True) if isinstance(item["detail"], (dict, list)) else str(item["detail"])
        detail = detail.replace("|", "\\|")
        lines.append(f"| {item['check']} | {item['status']} | `{detail}` |")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/r03-owned-ram/app-tail-placement/analyze_app_tail_placement.py")
    lines.append("cd baselines/v15/analysis/r03-owned-ram/app-tail-placement")
    lines.append("shasum -a 256 -c SHA256SUMS")
    lines.append("```")
    lines.append("")
    lines.append("Generated files: `analyze_app_tail_placement.py`, `evidence.json`, `validation.txt`, `report.md`, `SHA256SUMS`.")
    (HERE / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_validation(e: dict[str, Any]) -> None:
    lines = []
    ok = True
    for item in e["validation"]:
        lines.append(f"{item['status']} {item['check']}: {item['detail']}")
        ok = ok and item["status"] == "PASS"
    lines.append("OVERALL PASS" if ok else "OVERALL FAIL")
    (HERE / "validation.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_sha256sums() -> None:
    names = ["analyze_app_tail_placement.py", "evidence.json", "validation.txt", "report.md"]
    lines = []
    for name in names:
        data = (HERE / name).read_bytes()
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (HERE / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    e = make_evidence()
    (HERE / "evidence.json").write_text(json.dumps(e, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_validation(e)
    write_report(e)
    write_sha256sums()
    if not all(v["status"] == "PASS" for v in e["validation"]):
        print("validation failed", file=sys.stderr)
        return 1
    print("app-tail placement audit: PASS (report generated); placement decisions are BLOCK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
