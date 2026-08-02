#!/usr/bin/env python3
"""Reproduce the official-v15-only Ch10 patch-set persistence analysis.

This tool reads existing local artifacts only. It does not patch firmware, build
an OTA image, access a device, or write outside this analysis directory.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUTDIR = Path(__file__).resolve().parent
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
OFFICIAL_FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
H2_APP = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
APP_PATCH_TOOL = ROOT / "tools/smk37_v15_app_patch.py"

SOURCE_FILES = {
    "state_persistence": ROOT / "baselines/v15/analysis/ui-preflash/state-persistence/state_persistence_evidence.json",
    "persistence_direction": ROOT / "baselines/v15/analysis/ui-preflash/followup/persistence-direction.json",
    "runtime_source": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/runtime_source_trace.json",
    "factory_loader": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/factory_loader_evidence.json",
    "h2_manifest": ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json",
    "h2_live_validation": ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md",
    "roadmap": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/post-r02-roadmap.md",
    "app_tail": ROOT / "baselines/v15/analysis/r03-owned-ram/app-tail-placement/evidence.json",
    "official_manifest": ROOT / "baselines/v15/official/package-manifest.json",
    "app_patch_tool": APP_PATCH_TOOL,
}

EXPECTED_SHA256 = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "h2_app": "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
    "listing": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
}

RUNTIME_BASE = 0x02000000
SAVE_WRITE = 0x02026DA6
SAVE_PACKER_CALL = 0x02026DAC
JLFS_HEADERS = [0x4020 + index * 0x20 for index in range(8)]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hx(value: int, width: int = 0) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("smk37_v15_app_patch", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require(condition: bool, message: str, checks: list[str]) -> None:
    if not condition:
        raise AssertionError(message)
    checks.append(f"PASS {message}")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_record_format(slot_count: int) -> dict[str, Any]:
    payload = slot_count * 0x9C
    header = 0x40
    total = header + payload
    return {
        "slot_count": slot_count,
        "voice_bytes_per_slot": 0x9C,
        "payload_bytes": payload,
        "header_bytes_example": header,
        "record_bytes_example": total,
        "fits_one_0x1000_erase_domain": total <= 0x1000,
        "a_b_bytes_rounded_to_0x1000_domains": 2 * ((total + 0xFFF) // 0x1000) * 0x1000,
    }


def main() -> None:
    checks: list[str] = []
    actual_sha = {
        "official_app": sha256(OFFICIAL_APP),
        "official_fwsc": sha256(OFFICIAL_FWSC),
        "h2_app": sha256(H2_APP),
        "listing": sha256(LISTING),
    }
    for name, expected in EXPECTED_SHA256.items():
        require(actual_sha[name] == expected, f"{name} SHA-256 matches {expected}", checks)

    fw = load_module(APP_PATCH_TOOL)
    raw_fwsc = OFFICIAL_FWSC.read_bytes()
    payload, _metadata = fw.unpack_fwsc(raw_fwsc)
    ufw = fw.Ufw.parse(payload)
    encrypted_flash = ufw.flash()
    app_image = fw.AppImage.parse(encrypted_flash)
    plain_flash = app_image.plain_flash

    jlfs_entries = []
    for header in JLFS_HEADERS:
        entry = fw.parse_jlfs_entry(plain_flash, header)
        jlfs_entries.append({
            "name": entry.name,
            "header_offset": hx(header, 5),
            "entry_offset": hx(entry.offset, 5),
            "physical_data_start": hx(0x4000 + entry.offset, 5),
            "physical_end_exclusive": hx(0x4000 + entry.offset + entry.size, 5),
            "size": entry.size,
            "size_hex": hx(entry.size),
            "flags": hx(entry.flags),
            "index": entry.index,
            "data_crc16": f"0x{entry.data_crc:04x}",
            "header_crc16": f"0x{entry.header_crc:04x}",
        })

    expected_jlfs = {
        "app.bin": (0x120, 617012),
        "cfg_tool.bin": (0x96B54, 0x17F),
        "VM": (0x9C000, 0x24000),
        "PRCT": (0x0000, 0x9C000),
        "BTIF": (0xC0000, 0x1000),
        "USRTRIM": (0xC1000, 0x1000),
        "USRFLASH": (0xC2000, 0x29000),
        "USR": (0xF4000, 0xA000),
    }
    by_name = {entry["name"]: entry for entry in jlfs_entries}
    require(set(by_name) == set(expected_jlfs), "official JLFS directory has the expected eight named entries", checks)
    for name, (offset, size) in expected_jlfs.items():
        require(
            by_name[name]["entry_offset"] == hx(offset, 5) and by_name[name]["size"] == size,
            f"JLFS {name} offset and size match official v15",
            checks,
        )

    flash_entry = ufw.flash_entry()
    require(flash_entry.offset == 0x400 and flash_entry.size == 0x9C000, "UFW flash.bin is 0x9c000 bytes at payload offset 0x400", checks)
    require(0x9C000 <= 0xA0000, "UFW flash.bin ends before the VM region", checks)
    require(0x9C000 <= 0xC6000, "UFW flash.bin ends before the USRFLASH region", checks)
    require(by_name["cfg_tool.bin"]["physical_data_start"] == hx(0x9AB54, 5), "cfg_tool.bin begins exactly at app.bin end", checks)
    require(by_name["cfg_tool.bin"]["physical_end_exclusive"] == hx(0x9ACD3, 5), "cfg_tool.bin consumes the full app-area tail", checks)

    official_app = OFFICIAL_APP.read_bytes()
    h2_app = H2_APP.read_bytes()
    save_off = SAVE_WRITE - RUNTIME_BASE
    packer_off = SAVE_PACKER_CALL - RUNTIME_BASE
    h2_bytes = {
        "official_first_write_call": official_app[save_off:save_off + 4].hex(),
        "h2_first_write_site": h2_app[save_off:save_off + 4].hex(),
        "official_packer_call": official_app[packer_off:packer_off + 4].hex(),
        "h2_packer_call_site": h2_app[packer_off:packer_off + 4].hex(),
        "h2_surrounding": h2_app[save_off:save_off + 12].hex(),
    }
    require(h2_bytes["official_first_write_call"] == "beeaacee", "official 0x02026da6 is call 0x02004b02", checks)
    require(h2_bytes["h2_first_write_site"] == "04960000", "H2 0x02026da6 branches to the local exit before writes", checks)
    require(h2_bytes["official_packer_call"] == "bfeac7b9", "official 0x02026dac calls the stock packer", checks)
    require(h2_bytes["h2_packer_call_site"] == "00000000", "H2 0x02026dac neutralizes the later packer call", checks)

    persistence = read_json(SOURCE_FILES["persistence_direction"])
    require(persistence["conclusions"]["direction"].startswith("0x02004b02 -> 0x02004a7a is statically write"), "v15 write-wrapper direction is RAM to storage", checks)
    require("returns length on full success and 0 otherwise" in persistence["conclusions"]["wrapper_contract"], "write wrapper has count-style full-success return", checks)
    require("not propagated" in persistence["conclusions"]["save_failure_path"].lower(), "stock SAVE ignores wrapper failure", checks)

    h2_manifest = read_json(SOURCE_FILES["h2_manifest"])
    require(h2_manifest["h2_policy"]["copy_size"] == 156, "H2 owned source copy size is 0x9c", checks)
    require(h2_manifest["h2_policy"]["save_policy"].startswith("blocked before first persistent write"), "H2 manifest declares no-write SAVE policy", checks)

    packed_bank_start = 0x0000
    packed_bank_end = 4 * 0x1000
    raw_record_start = 0x4000
    raw_record_bytes = 4 * 32 * 0xA3
    raw_record_end = raw_record_start + raw_record_bytes
    flags_start = 0x9180
    flags_end = flags_start + 0x80
    selection_start = 0x9200
    selection_end = selection_start + 0x9
    require(raw_record_end == flags_start, "128 stock 0xa3 records end exactly at flag table 0x9180", checks)
    require(flags_end == selection_start, "0x80 flag table ends exactly at selection block 0x9200", checks)
    require(selection_end == 0x9209, "known stock patch store extent is 0x9209 bytes", checks)

    vm_size = expected_jlfs["VM"][1]
    usrflash_size = expected_jlfs["USRFLASH"][1]
    require(vm_size == 0x24000 and usrflash_size == 0x29000, "official VM and USRFLASH capacities match JLFS", checks)

    source_hashes = {name: {"path": str(path.relative_to(ROOT)), "sha256": sha256(path)} for name, path in SOURCE_FILES.items()}
    budget_16 = make_record_format(16)
    budget_128 = make_record_format(128)
    require(budget_16["fits_one_0x1000_erase_domain"], "16-slot 0x9c payload plus 0x40 header fits one 4 KiB domain", checks)
    require(not budget_128["fits_one_0x1000_erase_domain"], "128-slot 0x9c payload does not fit one 4 KiB domain", checks)

    evidence: dict[str, Any] = {
        "format": "smk37-v15-h2-patch-set-persistence-analysis-v1",
        "scope": {
            "firmware_basis": "official v15 only, with H2 as the current volatile owned-RAM checkpoint",
            "operations": ["static repository analysis", "local binary parsing", "deterministic arithmetic"],
            "prohibited_and_not_performed": ["firmware patch", "OTA or flash", "device access"],
        },
        "sha_gates": {
            name: {"actual": actual_sha[name], "expected": EXPECTED_SHA256[name], "status": "PASS"}
            for name in EXPECTED_SHA256
        },
        "source_bindings": source_hashes,
        "official_layout": {
            "ufw_flash_entry": {
                "payload_offset": hx(flash_entry.offset),
                "size": flash_entry.size,
                "size_hex": hx(flash_entry.size),
                "end_exclusive_in_physical_flash_model": hx(flash_entry.size),
            },
            "jlfs_entries": jlfs_entries,
            "app_tail": {
                "app_end": hx(0x9AB54),
                "app_area_end": hx(0x9ACD3),
                "bytes": 0x17F,
                "owner": "cfg_tool.bin",
                "safe_append_bytes": 0,
            },
            "persistence_regions_outside_ufw_flash_bin": {
                "VM": {"start": hx(0xA0000), "size": vm_size, "end_exclusive": hx(0xC4000)},
                "USRFLASH": {"start": hx(0xC6000), "size": usrflash_size, "end_exclusive": hx(0xEF000)},
                "implication": "Runtime writes there do not alter the v15 FWSC flash.bin entry. The directory capacity alone does not prove unused allocation space or identify which region backs obj+0x160.",
            },
        },
        "stock_patch_store": {
            "base": "*(0x01c33260+0x160)",
            "known_extent_bytes": selection_end,
            "known_extent_hex": hx(selection_end),
            "segments": [
                {"name": "packed_bank_records", "start": hx(packed_bank_start), "end_exclusive": hx(packed_bank_end), "bytes": packed_bank_end - packed_bank_start, "formula": "4 banks * 0x1000"},
                {"name": "expanded_or_current_saved_records", "start": hx(raw_record_start), "end_exclusive": hx(raw_record_end), "bytes": raw_record_bytes, "formula": "4 * 32 * 0xa3"},
                {"name": "saved_flag_table", "start": hx(flags_start), "end_exclusive": hx(flags_end), "bytes": 0x80},
                {"name": "selected_bank_preset_block", "start": hx(selection_start), "end_exclusive": hx(selection_end), "bytes": 0x9},
            ],
            "apparent_capacity_if_region_were_VM": vm_size - selection_end,
            "apparent_capacity_if_region_were_USRFLASH": usrflash_size - selection_end,
            "safe_unallocated_budget": 0,
            "why_zero": "No official-v15 evidence proves that bytes after +0x9209 are unallocated, that obj+0x160 equals the start of VM or USRFLASH, or that no stock allocator/journal uses the remainder.",
        },
        "patch_set_budgets": {
            "reference_only": {
                "16_slots_bank_preset_bytes": 16 * 2,
                "128_notes_bank_preset_bytes": 128 * 2,
                "status": "smallest format, but deterministic boot materialization and lifecycle side effects are not yet proven",
            },
            "runtime_voice_0x9c": {
                "16_slots": budget_16,
                "128_notes": budget_128,
                "preferred_first_persistent_payload": "16 exact H2-proven runtime voices, after a storage allocation is proven",
            },
            "full_stock_0xa3": {
                "16_slots_payload_bytes": 16 * 0xA3,
                "128_notes_payload_bytes": 128 * 0xA3,
                "warning": "Do not change the stock 0xa3 schema or overwrite the existing 128-record library for custom mapping metadata.",
            },
        },
        "save_interception": {
            "official_and_h2_bytes": h2_bytes,
            "official_flow": [
                "write current 0xa3 snapshot to +0x4000+index*0xa3",
                "call stock packer to update packed 0x80 record",
                "set saved flag",
                "flush 0x80 flag table",
            ],
            "h2_flow": "branch to stock local exit before the first persistent write, with the later packer call neutralized",
            "production_requirement": "Do not attach custom persistence to the stock SAVE writer while H2 replaces the stock packer body. First relocate H2 producer code, restore the official packer and stock SAVE path, then dispatch a separate custom commit only from a proven Drum Set context.",
        },
        "safe_options_now": [
            {"option": "volatile host-loaded 16-slot set", "decision": "PASS NOW", "reason": "Extends H2/R04 without touching persistent storage. Boot fallback is stock or invalid-until-loaded."},
            {"option": "reuse stock 128 patch records as the patch library and keep a volatile note-to-record map", "decision": "PASS NOW", "reason": "No new persistent bytes. It preserves stock record format and avoids loader calls in the Note hot path after slots are preloaded."},
            {"option": "persist custom data after +0x9209", "decision": "BLOCK", "reason": "Large apparent headroom exists, but allocation ownership and backing-region identity are unproven."},
            {"option": "overwrite cfg_tool.bin or append to app.bin", "decision": "BLOCK", "reason": "The app-area tail has zero free bytes and is a named JLFS file."},
            {"option": "preseed VM or USRFLASH by FWSC repack", "decision": "BLOCK", "reason": "The FWSC flash.bin entry ends before both regions. The package provides layout metadata, not a validated preseed/update path for their live contents."},
            {"option": "piggyback custom data into stock SAVE records, flags, or selection bytes", "decision": "BLOCK", "reason": "Those bytes have exact stock meanings and failure behavior. Repurposing them corrupts stock compatibility and rollback."},
        ],
        "recommended_persistent_design_after_gates": {
            "storage": "a separately proven allocation in the runtime storage region, outside every stock allocation and journal range",
            "format": {
                "magic": "fixed custom magic",
                "version": "v1",
                "payload_kind": "16 exact 0x9c runtime voices first, not a modified stock 0xa3 record",
                "fields": ["header length", "payload length", "slot count", "sequence", "payload CRC16 or CRC32", "header CRC", "commit state"],
                "atomicity": "two 0x1000-aligned copies for the 16-slot set, payload first and commit header last, then readback verification",
            },
            "write_contract": "Treat 0x02004b02 success only when return equals requested length. Never copy stock SAVE behavior that ignores failure.",
            "read_contract": "Use 0x02004870 only after storage initialization. Accept only exact magic/version/length/slot count/CRC and a fully committed newest sequence.",
            "power_loss": "On any short write, invalid CRC, torn header, or ambiguous sequence, retain the previous valid copy and expose volatile fallback rather than SAVED.",
        },
        "boot_load_lifecycle": [
            {"stage": 0, "action": "Stock storage and UI initialization complete. Do not add an early boot hook."},
            {"stage": 1, "action": "At a separately proven post-storage hook, read only the small A/B headers with 0x02004870."},
            {"stage": 2, "action": "Validate bounds, magic, version, committed state, sequence, payload length, and CRC before touching owned Ch10 RAM."},
            {"stage": 3, "action": "Read the selected payload into scratch or inactive owned RAM, verify again, then publish valid and generation last."},
            {"stage": 4, "action": "Note On and Note Off select the same immutable slot and generation. No loader, storage I/O, or global bank switch occurs in the Note path."},
            {"stage": 5, "action": "Missing or corrupt records leave valid clear and fall back safely to stock or explicit host-loaded volatile data."},
        ],
        "crc_and_repack": {
            "runtime_persistence": "No FWSC, UFW, SFC, app.bin, or JLFS-directory CRC changes when firmware writes an already allocated VM or USRFLASH range at runtime. The custom record still needs its own integrity and commit checks.",
            "fixed_size_app_patch": [
                "update app.bin JLFS data CRC and header CRC",
                "update app_area_head data CRC and header CRC",
                "SFC re-encrypt the fixed app area",
                "update UFW flash.bin data CRC",
                "update encrypted UFW entry-list CRC and UFW header CRC",
                "repack FWSC at unchanged size and preserve metadata slots",
            ],
            "layout_change": "Changing app.bin size, JLFS VM/USRFLASH offsets or sizes, or UFW flash.bin size is outside the validated fixed-layout packer and is blocked.",
        },
        "rollback_boundaries": {
            "firmware": "H2 itself changes exact app sectors 0x04000, 0x20000, 0x22000, 0x2a000, and 0x62000. Any future persistence implementation needs a new exact changed-sector inventory and rollback bundle.",
            "persistent_data": "The official UFW flash.bin stops at 0x9c000, before VM and USRFLASH. Restoring official app sectors does not prove deletion of a custom persistent record.",
            "safe_rollback_rule": "Official firmware must ignore the custom namespace after app rollback. Prefer version rejection or a separately guarded tombstone operation. Never erase a broad VM or USRFLASH region without a proven allocation map.",
            "stock_save": "Restore stock packer and SAVE bytes before claiming stock Patch SAVE compatibility. A rollback from a custom build must restore both code and any modified stock data records independently.",
        },
        "staged_path": [
            {"phase": "P0 volatile single voice", "state": "H2 LIVE PASS", "persistence": "none", "gate": "owned RAM and matched Note On/Off already proven for one voice"},
            {"phase": "P1 volatile 16-slot set", "state": "next", "persistence": "none", "gate": "note map, generation, active-note identity, overlap and release stress"},
            {"phase": "P2 read-only storage probe", "state": "blocked on code proof", "persistence": "read headers only", "gate": "prove storage base, total bound, allocation map, post-storage hook, and no stock overlap"},
            {"phase": "P3 guarded custom commit", "state": "blocked on P2", "persistence": "A/B 4 KiB records via separate host command", "gate": "short-write, corrupt-record, readback, reboot, and power-loss tests"},
            {"phase": "P4 UI SAVE integration", "state": "last", "persistence": "custom SAVE only in proven Drum Set page", "gate": "restore stock packer/SAVE, prove event context and SAVED only after verified commit"},
        ],
        "residual_unknowns": [
            "Which JLFS region and suballocation obj+0x160 actually names at runtime",
            "The runtime value of the storage bound at 0x01c454b0+0x18",
            "All allocations and journal ranges after stock patch offset +0x9209",
            "Exact erase, open, and commit semantics of 0x02004a54 modes",
            "Power-loss and media-error behavior below 0x02063260",
            "A proven post-storage boot hook that is safe on every boot path",
        ],
    }

    evidence_path = OUTDIR / "evidence.json"
    validation_path = OUTDIR / "validation.txt"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    validation_lines = [
        "SMK37 Pro official v15 H2 patch-set persistence analysis validation",
        "",
        *checks,
        "",
        f"PASS wrote {evidence_path.relative_to(ROOT)}",
        f"PASS total checks: {len(checks)}",
        "RESULT PASS",
    ]
    validation_path.write_text("\n".join(validation_lines) + "\n", encoding="utf-8")
    print("\n".join(validation_lines))


if __name__ == "__main__":
    main()
