#!/usr/bin/env python3
"""Official-v15 app.bin extension safety audit.

This script is read-only. It parses the exact official v15 FWSC/UFW/JLFS
headers and emits deterministic evidence for whether app.bin can be extended
past its current 0x96a34 size without overwriting stock bytes, and whether any
post-app bytes are positively proven as runtime executable space.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[6]
OUT = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension"
APP = ROOT / "build/v15-official-app.bin"
FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
OFFICIAL_MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
REPACKER = ROOT / "tools/smk37_v15_app_patch.py"
PUBLIC_RESEARCH = ROOT / "baselines/v15/analysis/public-research.md"
PERSISTENCE_REPORT = ROOT / "baselines/v15/analysis/patch-set-ui/persistence/report.md"
APP_TAIL_REPORT = ROOT / "baselines/v15/analysis/r03-owned-ram/app-tail-placement/report.md"
EXEC_PLACEMENT_REPORT = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/report.md"

APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
SDK_COMMIT = "e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d"


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def hx(value: int, width: int = 0) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def load_repacker():
    spec = importlib.util.spec_from_file_location("smk37_v15_app_patch", REPACKER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {REPACKER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parse_jlfs_directory(p, plain_flash: bytes | bytearray) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for index in range(8):
        header = p.APP_ENTRY_HEADER + index * 0x20
        entry = p.parse_jlfs_entry(plain_flash, header)
        physical_start = p.APP_AREA_BASE + entry.offset
        physical_end = physical_start + entry.size
        in_flash = physical_end <= len(plain_flash)
        crc_region = bytes(plain_flash[physical_start:physical_end]) if in_flash else b""
        computed_crc = p.crc16(crc_region) if in_flash else None
        entries.append(
            {
                "index": index,
                "name": entry.name,
                "header_flash_offset": hx(header, 5),
                "header_crc16": hx(entry.header_crc, 4),
                "data_crc16": hx(entry.data_crc, 4),
                "computed_data_crc16": hx(computed_crc, 4) if computed_crc is not None else None,
                "data_crc_checkable_in_flash_bin": in_flash,
                "crc_valid": (computed_crc == entry.data_crc) if computed_crc is not None else None,
                "relative_offset": hx(entry.offset, 5),
                "physical_start": hx(physical_start, 5),
                "physical_end_exclusive": hx(physical_end, 5),
                "size": entry.size,
                "size_hex": hx(entry.size),
                "flags": hx(entry.flags, 2),
                "reserved": hx(entry.reserved, 2),
            }
        )
    return entries


def classify_bytes(data: bytes) -> dict[str, Any]:
    counts = {"00": data.count(0), "ff": data.count(0xFF), "other": len(data) - data.count(0) - data.count(0xFF)}
    strings = [m.group(0).decode("ascii", "replace") for m in re.finditer(rb"[\x20-\x7e]{4,}", data)]
    return {
        "size": len(data),
        "sha256": sha256_bytes(data),
        "byte_counts": counts,
        "first_32_hex": data[:32].hex(),
        "last_32_hex": data[-32:].hex() if data else "",
        "ascii_strings_first_20": strings[:20],
    }


def sector_span(start: int, end: int, sector_size: int = 0x1000) -> list[str]:
    if start >= end:
        return []
    first = start // sector_size * sector_size
    last = (end - 1) // sector_size * sector_size
    return [hx(base, 5) for base in range(first, last + 1, sector_size)]


def make_evidence() -> dict[str, Any]:
    p = load_repacker()
    raw = FWSC.read_bytes()
    payload, _metadata = p.unpack_fwsc(raw)
    ufw = p.Ufw.parse(payload)
    encrypted_flash = ufw.flash()
    app_image = p.AppImage.parse(encrypted_flash)
    plain_flash = app_image.plain_flash
    app_bytes = app_image.app_bytes()
    app_file = APP.read_bytes()
    assert app_bytes == app_file

    flash_entry = ufw.flash_entry()
    ufw_entries = []
    for entry in ufw.entries:
        ufw_entries.append(
            {
                "index": entry.index_in_list,
                "type": entry.entry_type,
                "name": entry.name,
                "offset": hx(entry.offset),
                "size": entry.size,
                "size_hex": hx(entry.size),
                "aligned_size": entry.aligned_size,
                "aligned_size_hex": hx(entry.aligned_size),
                "end_exclusive": hx(entry.offset + entry.size),
                "aligned_end_exclusive": hx(entry.offset + entry.aligned_size),
                "data_crc16": hx(entry.data_crc, 4),
            }
        )

    sorted_entries = sorted(ufw.entries, key=lambda e: (e.offset, e.index_in_list))
    ufw_gaps = []
    for cur, nxt in zip(sorted_entries, sorted_entries[1:]):
        cur_end = cur.offset + cur.aligned_size
        gap = max(0, nxt.offset - cur_end)
        ufw_gaps.append(
            {
                "after": cur.name,
                "before": nxt.name,
                "gap_start": hx(cur_end),
                "gap_end_exclusive": hx(nxt.offset),
                "gap_bytes": gap,
            }
        )

    directory = parse_jlfs_directory(p, plain_flash)
    by_name = {entry["name"]: entry for entry in directory}
    app = by_name["app.bin"]
    cfg_tool = by_name["cfg_tool.bin"]
    area = app_image.area

    app_start = int(app["physical_start"], 16)
    app_end = int(app["physical_end_exclusive"], 16)
    cfg_start = int(cfg_tool["physical_start"], 16)
    cfg_end = int(cfg_tool["physical_end_exclusive"], 16)
    app_area_end = p.APP_AREA_END
    flash_end = flash_entry.size
    post_app_gap_start = app_area_end
    post_app_gap_end = flash_end
    stock_physical_extension = 0
    logical_relocation_nominal_extension = flash_end - app_area_end
    max_app_size_if_cfg_tool_relocated_to_flash_end = flash_end - p.APP_DATA_OFFSET - int(cfg_tool["size"])

    protected = p.protected_hashes(encrypted_flash)
    isd_raw = bytes(encrypted_flash[0x38D0:0x3B8B])
    uboot_raw = bytes(encrypted_flash[0x00A0:0x38D0])
    post_app_raw = bytes(encrypted_flash[post_app_gap_start:post_app_gap_end])
    cfg_tool_plain = bytes(plain_flash[cfg_start:cfg_end])

    validation_checks = [
        {"check": "official-fwsc-sha", "status": sha256_path(FWSC) == p.OFFICIAL_V15_SHA256, "detail": sha256_path(FWSC)},
        {"check": "official-app-sha", "status": sha256_path(APP) == APP_SHA, "detail": sha256_path(APP)},
        {"check": "app-file-equals-jlfs-app-bytes", "status": app_bytes == app_file, "detail": f"{len(app_bytes)} bytes"},
        {"check": "app-size-is-0x96a34", "status": len(app_bytes) == 0x96A34, "detail": hx(len(app_bytes))},
        {"check": "cfg-tool-starts-at-app-end", "status": cfg_start == app_end, "detail": f"{hx(cfg_start,5)} == {hx(app_end,5)}"},
        {"check": "cfg-tool-consumes-naive-app-tail", "status": cfg_end == app_area_end, "detail": f"{hx(cfg_start,5)}..{hx(cfg_end,5)}"},
        {"check": "flash-bin-has-no-gap-before-next-ufw-entry", "status": sorted_entries[2].offset == flash_entry.offset + flash_entry.size, "detail": f"flash.bin aligned end {hx(flash_entry.offset + flash_entry.size)}; USR starts {hx(sorted_entries[2].offset)}"},
        {"check": "checkable-jlfs-data-crcs-valid", "status": all(e["crc_valid"] is not False for e in directory), "detail": "app.bin/cfg_tool.bin checkable in flash.bin; out-of-flash JLFS data entries have 0xffff CRC placeholders"},
        {"check": "app-area-entry-point", "status": area.offset == 0x02000120, "detail": hx(area.offset, 8)},
        {"check": "app-area-size", "status": area.size == p.APP_AREA_END - p.APP_AREA_BASE, "detail": hx(area.size)},
    ]

    decisions = [
        {
            "claim": "Extend exact official app.bin while leaving every stock flash byte at its official physical offset",
            "decision": "BLOCK",
            "maximum_extension_bytes": stock_physical_extension,
            "reason": "The first byte after app.bin is the first byte of named JLFS file cfg_tool.bin. Any positive extension changes stock flash bytes at or after 0x9ab54.",
        },
        {
            "claim": "Extend app.bin by only increasing app.bin.size inside current app_area_head envelope",
            "decision": "BLOCK",
            "maximum_extension_bytes_before_stock_overlap": 0,
            "reason": "app.bin end 0x9ab54 equals cfg_tool.bin start 0x9ab54; the 383-byte apparent tail is fully occupied by cfg_tool.bin.",
        },
        {
            "claim": "Preserve cfg_tool.bin logical bytes by relocating it toward flash.bin end and growing app_area_head",
            "decision": "BLOCK",
            "nominal_extra_bytes_before_flash_bin_end": logical_relocation_nominal_extension,
            "hypothetical_max_app_size": max_app_size_if_cfg_tool_relocated_to_flash_end,
            "hypothetical_max_app_size_hex": hx(max_app_size_if_cfg_tool_relocated_to_flash_end),
            "reason": "This moves a named stock JLFS file, changes app.bin/cfg_tool/app_area_head CRC/size/offset headers, consumes protected post-app bytes, and lacks boot/loader/runtime consumer proof.",
        },
        {
            "claim": "Grow UFW flash.bin past 0x9c000",
            "decision": "BLOCK",
            "maximum_extension_bytes_before_next_ufw_entry": 0,
            "reason": "The next UFW payload entry starts immediately at flash.bin end 0x9c400, and the UFW payload has no trailing gap after tail.bin.",
        },
        {
            "claim": "Appended bytes beyond official app.bin are positively proven readable/executable at runtime",
            "decision": "BLOCK",
            "positive_evidence_for_current_app_only": True,
            "reason": "Official and public evidence support SFC/XIP execution for the current app image, but no exact v15 loader/MPU/cache proof promotes cfg_tool.bin or post-app protected bytes as app-owned executable targets.",
        },
    ]

    runtime = {
        "runtime_base_for_current_app_evidence": "0x02000000",
        "official_app_runtime_range": {"start": "0x02000000", "end_exclusive": hx(0x02000000 + len(app_bytes), 8)},
        "cfg_tool_range_if_raw_contiguous_mapping": {"start": hx(0x02000000 + (cfg_start - p.APP_DATA_OFFSET), 8), "end_exclusive": hx(0x02000000 + (cfg_end - p.APP_DATA_OFFSET), 8)},
        "post_app_gap_if_raw_contiguous_mapping": {"start": hx(0x02000000 + (post_app_gap_start - p.APP_DATA_OFFSET), 8), "end_exclusive": hx(0x02000000 + (post_app_gap_end - p.APP_DATA_OFFSET), 8)},
        "entry_point_from_app_area_head": hx(area.offset, 8),
        "public_sdk_sfc_linker_evidence": {
            "commit": SDK_COMMIT,
            "sdk_ld_sfc_c": {
                "rom_origin": "0x02000120",
                "rom_permissions": "rx",
                "rom_length_symbol": "__FLASH_SIZE__",
                "text_sections": ["startup.S.o(.text)", "*(.boot_code)", "*(.text*)", "*(.rodata*)"],
                "ram_copy_lma_symbols": ["data_lma = text_begin + SIZEOF(.text)", "_ram0_data_lma = text_begin + SIZEOF(.text) + SIZEOF(.data) + SIZEOF(.dynamic_data)"],
            },
            "isd_config_rule_c": {
                "sfc_entry": "ENTRY=0x2000120 when CONFIG_SFC_ENABLE or CONFIG_NO_SDRAM_ENABLE",
                "sdram_entry": "ENTRY=0x4000120 otherwise",
                "force_4k_align": "FORCE_4K_ALIGN=YES",
            },
        },
        "limit": "These SDK facts prove the public SFC/XIP model, not that bytes outside official JLFS app.bin are admitted by the exact SMK-37 Pro v15 boot path as executable app bytes.",
    }

    sectors = {
        "tail_payload_only_overlaps": sector_span(app_end, cfg_end),
        "post_app_gap_overlaps": sector_span(post_app_gap_start, post_app_gap_end),
        "relocate_cfg_tool_and_extend_to_flash_end_overlaps": sector_span(app_end, flash_end),
        "rollback_implication": "Any hypothetical tail/post-app change touches sector 0x9a000 and/or 0x9b000; preserving stock rollback would require exact original sector backups and still would not prove runtime execution.",
    }

    source_hashes = {
        str(path.relative_to(ROOT)): sha256_path(path)
        for path in [FWSC, APP, OFFICIAL_MANIFEST, REPACKER, PUBLIC_RESEARCH, PERSISTENCE_REPORT, APP_TAIL_REPORT, EXEC_PLACEMENT_REPORT]
        if path.exists()
    }

    evidence: dict[str, Any] = {
        "format": "smk37-v15-app-extension-audit-v1",
        "scope": "read-only exact official v15 package/app evidence; no firmware candidate, flash, OTA, or device access",
        "inputs": source_hashes,
        "exact_headers": {
            "fwsc": {"size": len(raw), "sha256": sha256_bytes(raw)},
            "ufw_header": {
                "image_size": len(payload),
                "entry_count": len(ufw.entries),
                "chip_name": "AC791N",
                "flash_entry_offset": hx(flash_entry.offset),
                "flash_entry_size": hx(flash_entry.size),
            },
            "ufw_entries": ufw_entries,
            "ufw_aligned_gaps": ufw_gaps,
            "app_area_head": {
                "header_flash_offset": hx(p.APP_AREA_BASE, 5),
                "entry_point_or_offset_field": hx(area.offset, 8),
                "size": area.size,
                "size_hex": hx(area.size),
                "physical_start": hx(p.APP_AREA_BASE, 5),
                "physical_end_exclusive": hx(p.APP_AREA_END, 5),
                "data_crc16": hx(area.data_crc, 4),
                "header_crc16": hx(area.header_crc, 4),
            },
            "jlfs_directory_entries": directory,
        },
        "byte_accounting": {
            "app_bin": {"physical_start": hx(app_start, 5), "physical_end_exclusive": hx(app_end, 5), "size": len(app_bytes), "size_hex": hx(len(app_bytes)), "sha256": sha256_bytes(app_bytes)},
            "naive_tail_after_app_inside_app_area": {"physical_start": hx(app_end, 5), "physical_end_exclusive": hx(app_area_end, 5), "size": app_area_end - app_end, "owner": "cfg_tool.bin"},
            "cfg_tool_bin": {"physical_start": hx(cfg_start, 5), "physical_end_exclusive": hx(cfg_end, 5), "size": int(cfg_tool["size"]), "sha256_plain": sha256_bytes(cfg_tool_plain)},
            "post_app_area_to_flash_bin_end": {"physical_start": hx(post_app_gap_start, 5), "physical_end_exclusive": hx(post_app_gap_end, 5), "size": post_app_gap_end - post_app_gap_start, "classification": "protected post-app resources/reserved bytes, outside app_area_head CRC envelope", **classify_bytes(post_app_raw)},
            "ufw_flash_bin": {"payload_offset": hx(flash_entry.offset), "physical_size": flash_entry.size, "physical_size_hex": hx(flash_entry.size), "payload_end_exclusive": hx(flash_entry.offset + flash_entry.size)},
        },
        "protected_regions": {
            **protected,
            "uboot_boot_raw_0x00a0_0x38cf_detail": classify_bytes(uboot_raw),
            "isd_config_raw_0x38d0_0x3b8a_detail": classify_bytes(isd_raw),
        },
        "extension_decisions": decisions,
        "runtime_mapping_and_execution": runtime,
        "crc_size_alignment_implications": {
            "fixed_size_packer": "tools/smk37_v15_app_patch.py requires replacement app.bin length == 0x96a34 and repacked FWSC/UFW/flash sizes unchanged.",
            "fields_changed_by_fixed_size_app_patch": ["app.bin data_crc16", "app_area_head data_crc16", "UFW flash.bin data_crc16", "UFW encrypted entry-list CRC", "UFW header CRC"],
            "extra_fields_if_size_or_relocation_changed": ["app.bin size", "cfg_tool.bin offset if preserved", "cfg_tool.bin header CRC", "app_area_head size if extended", "app_area_head data CRC/header CRC", "possibly UFW flash.bin size/offset list CRC/header CRC if grown"],
            "alignment": "Public ISD rule uses FORCE_4K_ALIGN=YES for reserved files. Official app.bin and cfg_tool.bin are not 4 KiB-aligned, and app_area_head end is not 4 KiB-aligned. This does not create an owned extension allocation.",
        },
        "cache_mpu_notes": {
            "public_sdk": "AC79/WL82 docs/source identify I-cache, D-cache, MMU/TLB, and cache_ram. sdk_ld_sfc.c varies TLB_SIZE under CONFIG_MMU_ENABLE and sets FREE_IACHE_WAY/FREE_DACHE_WAY.",
            "blocker": "No exact official v15 boot/MPU/cache bounds were recovered that authorize instruction fetch beyond the JLFS app.bin logical file or into post-app protected bytes.",
        },
        "entry_branch_reach": {
            "entry": "Exact app_area_head entry is 0x02000120, inside current official app.bin range.",
            "branch_reach": "Not promoted. Because maximum safe extension is 0, no branch target exists. Prior S1-C2 executable-placement evidence requires exact overwritten range and branch/call bytes before promoting reach; app tail remains blocked.",
        },
        "resources_and_rollback": {
            "resource_overlap": "Immediate app extension overlaps cfg_tool.bin. Extension to flash.bin end overlaps protected post-app resources/reserved bytes. UFW flash.bin growth overlaps the UFW USR entry.",
            "rollback_sectors": sectors,
        },
        "validation_checks": validation_checks,
        "overall_decision": "BLOCK",
        "maximum_safe_extension_bytes": 0,
    }
    return evidence


def render_report(e: dict[str, Any]) -> str:
    l = e["byte_accounting"]
    app = l["app_bin"]
    tail = l["naive_tail_after_app_inside_app_area"]
    post = l["post_app_area_to_flash_bin_end"]
    decisions = e["extension_decisions"]
    runtime = e["runtime_mapping_and_execution"]
    lines: list[str] = []
    lines.append("# Official v15 app.bin extension audit")
    lines.append("")
    lines.append("Status: **BLOCK**. No firmware candidate, flashing, OTA, reset, or device access was used.")
    lines.append("")
    lines.append("## Answer")
    lines.append("")
    lines.append("The exact official v15 `app.bin` cannot be safely extended beyond `0x96a34` under the requested constraints. The maximum extension that preserves every stock byte at its official physical address is **0 bytes**.")
    lines.append("")
    lines.append("Positive runtime evidence exists for the current SFC/XIP app image, not for bytes appended after the JLFS `app.bin` logical file. Bytes after `app.bin` are either named stock JLFS content (`cfg_tool.bin`) or protected post-app bytes outside the `app_area_head` CRC envelope. Therefore appended bytes are **not proven readable/executable app bytes** at runtime.")
    lines.append("")
    lines.append("## Exact byte accounting")
    lines.append("")
    lines.append("| Region | Start | End exclusive | Size | Owner/classification |")
    lines.append("|---|---:|---:|---:|---|")
    lines.append(f"| official `app.bin` | `{app['physical_start']}` | `{app['physical_end_exclusive']}` | `{app['size_hex']}` | JLFS `app.bin` |")
    lines.append(f"| naive tail after app | `{tail['physical_start']}` | `{tail['physical_end_exclusive']}` | `{tail['size']}` | `{tail['owner']}` |")
    lines.append(f"| post app-area to flash.bin end | `{post['physical_start']}` | `{post['physical_end_exclusive']}` | `{post['size']}` | {post['classification']} |")
    lines.append("")
    lines.append("The first byte after `app.bin` (`0x9ab54`) is also the first byte of `cfg_tool.bin`. The current `app_area_head` ends at `0x9acd3`; the remaining `0x132d` bytes before UFW `flash.bin` end are protected post-app bytes, not part of the app-area JLFS envelope.")
    lines.append(f"The protected post-app range is not empty padding: SHA-256 `{post['sha256']}`, byte counts `{post['byte_counts']}`, first 32 bytes `{post['first_32_hex']}`.")
    lines.append("")
    lines.append("## Header evidence")
    lines.append("")
    lines.append("| Header | Fact |")
    lines.append("|---|---|")
    lines.append(f"| UFW `flash.bin` | offset `{e['exact_headers']['ufw_header']['flash_entry_offset']}`, size `{e['exact_headers']['ufw_header']['flash_entry_size']}` |")
    lines.append(f"| app_area_head | entry/offset `{e['exact_headers']['app_area_head']['entry_point_or_offset_field']}`, size `{e['exact_headers']['app_area_head']['size_hex']}`, end `{e['exact_headers']['app_area_head']['physical_end_exclusive']}` |")
    for row in e["exact_headers"]["jlfs_directory_entries"]:
        if row["name"] in {"app.bin", "cfg_tool.bin", "VM", "PRCT", "USRFLASH", "USR"}:
            crc_status = row["crc_valid"] if row["crc_valid"] is not None else "not in flash.bin"
            lines.append(f"| JLFS `{row['name']}` | offset `{row['relative_offset']}`, physical `{row['physical_start']}..{row['physical_end_exclusive']}`, size `{row['size_hex']}`, CRC valid `{crc_status}` |")
    lines.append("")
    lines.append("## Decision matrix")
    lines.append("")
    lines.append("| Claim | Decision | Max/nominal bytes | Reason |")
    lines.append("|---|---|---:|---|")
    for d in decisions:
        max_bytes = d.get("maximum_extension_bytes", d.get("maximum_extension_bytes_before_stock_overlap", d.get("nominal_extra_bytes_before_flash_bin_end", d.get("maximum_extension_bytes_before_next_ufw_entry", "n/a"))))
        lines.append(f"| {d['claim']} | **{d['decision']}** | `{max_bytes}` | {d['reason']} |")
    lines.append("")
    lines.append("## Runtime mapping, loader, and XIP evidence")
    lines.append("")
    lines.append(f"- Current app runtime model: `{runtime['runtime_base_for_current_app_evidence']}`, official app range `{runtime['official_app_runtime_range']['start']}..{runtime['official_app_runtime_range']['end_exclusive']}`.")
    lines.append(f"- If raw-contiguous mapped, `cfg_tool.bin` would be `{runtime['cfg_tool_range_if_raw_contiguous_mapping']['start']}..{runtime['cfg_tool_range_if_raw_contiguous_mapping']['end_exclusive']}`. This is not promoted because JLFS names it `cfg_tool.bin`, not `app.bin`.")
    lines.append(f"- If raw-contiguous mapped, the post-app gap would be `{runtime['post_app_gap_if_raw_contiguous_mapping']['start']}..{runtime['post_app_gap_if_raw_contiguous_mapping']['end_exclusive']}`. This is not promoted because it is outside `app_area_head` size/CRC.")
    lines.append("- Public AC79/WL82 `sdk_ld_sfc.c` at pinned commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` defines `rom(rx) ORIGIN = 0x02000120, LENGTH = __FLASH_SIZE__`, puts `.text*` and `.rodata*` in `rom`, and defines RAM LMAs after text. This supports the SFC/XIP model for a linked image.")
    lines.append("- Public `isd_config_rule.c` at the same commit selects `ENTRY=0x2000120` for SFC mode and includes `FORCE_4K_ALIGN=YES`. This matches the exact v15 `app_area_head` entry, but does not prove bytes outside official `app.bin` are executable app-owned bytes.")
    lines.append("- The exact official U-Boot/ISD raw regions are preserved/protected by existing packer evidence. The recovered raw ISD strings include SPI and clock configuration, but no exact v15 loader bound was recovered that authorizes appended post-app code.")
    lines.append("")
    lines.append("## CRC, size, alignment, cache/MPU, branch, resources, rollback")
    lines.append("")
    lines.append("- Fixed-size app patches update only `app.bin` data CRC, `app_area_head` data/header CRC, UFW flash.bin data CRC, UFW entry-list CRC, and UFW header CRC. The official repacker rejects any app size change.")
    lines.append("- Any real extension would additionally change `app.bin.size`; preserving `cfg_tool.bin` would change its offset/header CRC; extending beyond `app_area_head` would change `app_area_head.size`; growing UFW `flash.bin` would collide with UFW `USR` at payload offset `0x9c400`.")
    lines.append("- Cache/MPU: public SDK uses I-cache/D-cache/MMU/TLB concepts, but no exact v15 cache/MPU bound proves instruction fetch from appended bytes after `app.bin`.")
    lines.append("- Entry/branch reach: the entry point is inside current app.bin. Since safe extension size is 0, no tail branch target is promoted. Prior S1-C2 placement evidence requires exact branch/call bytes and ownership proof before reach is accepted.")
    lines.append("- Resources: immediate extension overwrites `cfg_tool.bin`; extension to flash end consumes protected post-app resources/reserved bytes; UFW flash.bin growth overlaps the UFW `USR` entry.")
    lines.append(f"- Rollback sectors for a hypothetical tail/post-app mutation: `{', '.join(e['resources_and_rollback']['rollback_sectors']['relocate_cfg_tool_and_extend_to_flash_end_overlaps'])}`. Rollback sector availability does not make the extension safe.")
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    for check in e["validation_checks"]:
        lines.append(f"- {'PASS' if check['status'] else 'FAIL'} `{check['check']}`: {check['detail']}")
    lines.append("")
    lines.append("Reproduce:")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension/analyze_app_extension.py")
    lines.append("shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension/SHA256SUMS")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    evidence = make_evidence()
    if not all(check["status"] for check in evidence["validation_checks"]):
        failed = [check for check in evidence["validation_checks"] if not check["status"]]
        raise SystemExit(f"validation failed: {failed!r}")
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUT / "report.md").write_text(render_report(evidence), encoding="utf-8")
    validation_lines = [f"PASS\t{check['check']}\t{check['detail']}" for check in evidence["validation_checks"]]
    validation_lines.append("OVERALL\tPASS\tBLOCK maximum_safe_extension_bytes=0")
    (OUT / "validation.txt").write_text("\n".join(validation_lines) + "\n", encoding="utf-8")
    sha_targets = ["analyze_app_extension.py", "evidence.json", "report.md", "validation.txt"]
    sha_lines = []
    for name in sha_targets:
        path = OUT / name
        sha_lines.append(f"{sha256_path(path)}  {path.relative_to(ROOT)}")
    (OUT / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
