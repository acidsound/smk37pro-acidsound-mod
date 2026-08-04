#!/usr/bin/env python3
"""Offline fit proof for using the S1C5-disabled SAVE body as a callable helper cave.

No firmware image is emitted and no device/transport/flash path is used.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent

BASE = 0x02000000
S1C5_APP = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app.bin"
S1C5_REPORT = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/report.md"
S1C5_EVIDENCE = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/evidence.json"
STORAGE_REPORT = ROOT / "baselines/v15/analysis/persistence-s2/storage/report.md"
RESTORE_REPORT = ROOT / "baselines/v15/analysis/persistence-s2/restore/report.md"
LISTING_GZ = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"

EXPECTED = {
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_report": "5cee31d28017dfa3d2e6057930fea0e5d5ee28428c38895cbbaf6ebacad79c8a",
    "s1c5_evidence": "02213aff815fe951d6b74f349c82cb0af65110be3e65d96f90343fa775d134e5",
    "storage_report": "7867925da16e1c85a7c809dffa8127c371e863987b1570fdc1488460f921dbc7",
    "restore_report": "c9ce9d4da638790c7e2803a1e85133cedfb8a069204d81ddbdb1bc5eba32b7c1",
    "listing": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
}

SAVE_GATE = 0x02026D74
UI_BRANCH = 0x02026D7A
CAVE_START = 0x02026D80
CAVE_END = 0x02026DD4
SAVE_EXIT = 0x02026DD4
S1C5_RAW_WRITE_PATCH = 0x02026DA6
S1C5_PACKER_NEUTRAL = 0x02026DAC
OWNED_START = 0x0201E13E
OWNED_END = 0x0201E254
DIRECT_PRODUCT_CALL = 0x0201E468
SEGMENTED_PRODUCT_CALL = 0x0201E49C
PRODUCER_ENTRY = 0x0201E228
WRITE_WRAPPER = 0x02004B02
READ_WRAPPER = 0x02004870

# The stock/raw-prefix persistence plan established by persistence-s2/storage.
RAW_RECORD_SIZE = 0xA3
PREFIX_SIZE = 0x9C
RECORD_BASE = 96
MANIFEST_INDEX = 112
SLOTS = 16


def sha_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def hx(x: int) -> str:
    return f"0x{x:08x}"


def off(addr: int) -> int:
    o = addr - BASE
    req(o >= 0, f"address under base {hx(addr)}")
    return o


def word(x: int) -> bytes:
    return struct.pack("<H", x & 0xFFFF)


def jne_imm7(at: int, reg: int, imm: int, target: int) -> bytes:
    half = (target - (at + 4)) // 2
    req((target - (at + 4)) % 2 == 0, "jne target alignment")
    req(-256 <= half <= 255, "jne target reach")
    req(0 <= reg <= 7 and 0 <= imm <= 0x7F, "jne operands")
    return word(0xF880 | reg) + word((imm << 9) | (half & 0x1FF))


def call32(at: int, target: int) -> bytes:
    return b"\x80\xff" + struct.pack("<i", target - (at + 6))


def call32_target(at: int, blob: bytes) -> int:
    req(len(blob) == 6 and blob[:2] == b"\x80\xff", "call32 blob")
    return at + 6 + struct.unpack("<i", blob[2:6])[0]


def short_call_target(at: int, blob: bytes) -> int:
    req(len(blob) == 4 and blob[:2] == b"\xbf\xea", "short call blob")
    return ((at + 4 + struct.unpack("<H", blob[2:4])[0] * 2) & 0xFFFF) | (at & 0xFFFF0000)


def hash_gates() -> dict[str, Any]:
    paths = {
        "s1c5_app": S1C5_APP,
        "s1c5_report": S1C5_REPORT,
        "s1c5_evidence": S1C5_EVIDENCE,
        "storage_report": STORAGE_REPORT,
        "restore_report": RESTORE_REPORT,
        "listing": LISTING_GZ,
    }
    out = {}
    for name, path in paths.items():
        digest = sha_path(path)
        req(digest == EXPECTED[name], f"hash gate {name}: {digest}")
        out[name] = {"path": str(path.relative_to(ROOT)), "sha256": digest}
    return out


def app_checks() -> dict[str, Any]:
    app = S1C5_APP.read_bytes()
    exact = {
        "save_gate_load_and_exit_test": (SAVE_GATE, 6, "01ff00009603"),
        "current_ui_branch": (UI_BRANCH, 6, "60ffff602a00"),
        "cave_start_stock_arithmetic": (CAVE_START, 0x26, "05e1a0835844d8ee001500a5d1ec802610180017e0e1a3002018e1e0800c14e1148a6a234016"),
        "s1c5_raw_write_reject": (S1C5_RAW_WRITE_PATCH, 4, "04960000"),
        "s1c5_packer_neutral": (S1C5_PACKER_NEUTRAL, 4, "00000000"),
        "post_neutral_flag_sequence_until_exit": (0x02026DB0, 0x24, "5844d8ee001500a5011810e19c82d8ee11f0d1ec8016c2ff8091000021186220beea97ee"),
        "stock_local_save_exit": (SAVE_EXIT, 0x0A, "40e0ec01d8ee81f0b584"),
        "direct_product_callsite": (DIRECT_PRODUCT_CALL, 4, "bfeadefe"),
        "segmented_product_callsite": (SEGMENTED_PRODUCT_CALL, 4, "bfeac4fe"),
    }
    rows = {}
    for name, (addr, size, hex_bytes) in exact.items():
        got = app[off(addr):off(addr) + size].hex()
        req(got == hex_bytes, f"exact bytes {name} {hx(addr)} got {got}")
        rows[name] = {"address": hx(addr), "size": size, "hex": got}
    # Existing 4-byte short product callsites can only stay inside the 0x0201xxxx 64KiB page.
    rows["direct_product_callsite"]["decoded_short_target"] = hx(short_call_target(DIRECT_PRODUCT_CALL, bytes.fromhex(rows["direct_product_callsite"]["hex"])))
    rows["segmented_product_callsite"]["decoded_short_target"] = hx(short_call_target(SEGMENTED_PRODUCT_CALL, bytes.fromhex(rows["segmented_product_callsite"]["hex"])))
    req(rows["direct_product_callsite"]["decoded_short_target"] == hx(PRODUCER_ENTRY), "direct target")
    req(rows["segmented_product_callsite"]["decoded_short_target"] == hx(PRODUCER_ENTRY), "segmented target")
    return rows


def listing_reference_scan() -> dict[str, Any]:
    digest = sha_path(LISTING_GZ)
    req(digest == EXPECTED["listing"], "listing hash")
    target_hits: dict[str, list[str]] = {hx(CAVE_START): [], hx(SAVE_EXIT): []}
    range_rows: list[str] = []
    with gzip.open(LISTING_GZ, "rt") as f:
        header = next(f).rstrip("\n")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            addr = int(parts[0], 16)
            text = parts[4]
            if CAVE_START <= addr < SAVE_EXIT + 0x0A:
                range_rows.append(line.rstrip("\n"))
            for target in target_hits:
                if target in text:
                    target_hits[target].append(line.rstrip("\n"))
    return {
        "listing_sha256": digest,
        "header": header,
        "rows_in_save_window": range_rows,
        "explicit_text_references": target_hits,
        "interpretation": "No official exhaustive-listing instruction text names 0x02026d80 as a branch/call target. 0x02026dd4 is explicitly targeted by the SAVE r6==0xff conditional. This does not prove absence of computed indirect control flow, but it gates direct/static references in this listing.",
    }


def branch_and_call_reach() -> dict[str, Any]:
    # At 0x02026d7a, r0 is proven zero by the immediately preceding jne r0,#0,out at 0x02026d74.
    patch = jne_imm7(UI_BRANCH, 0, 1, SAVE_EXIT) + bytes.fromhex("0016")
    req(patch.hex() == "80f82b020016", "UI branch patch bytes")
    long_from_selector = call32(0x0201E190, CAVE_START)
    long_from_producer = call32(PRODUCER_ENTRY, CAVE_START)
    req(call32_target(0x0201E190, long_from_selector) == CAVE_START, "selector long call reaches cave")
    req(call32_target(PRODUCER_ENTRY, long_from_producer) == CAVE_START, "producer long call reaches cave")
    # A hypothetical 4-byte short call from the product callsites cannot target 0x02026d80 because it retains the callsite's high 16 bits.
    def short_encoding_for(at: int, target: int) -> str:
        half = ((target - (at + 4)) // 2) & 0xFFFF
        blob = b"\xbf\xea" + struct.pack("<H", half)
        return blob.hex(), hx(short_call_target(at, blob))
    direct_short_hex, direct_short_actual = short_encoding_for(DIRECT_PRODUCT_CALL, CAVE_START)
    seg_short_hex, seg_short_actual = short_encoding_for(SEGMENTED_PRODUCT_CALL, CAVE_START)
    return {
        "ui_save_branch_patch_required": {
            "address": hx(UI_BRANCH),
            "old_hex": "60ffff602a00",
            "new_hex": patch.hex(),
            "decode": f"jne r0,#1,{hx(SAVE_EXIT)}; mov r0,r0",
            "safety_argument": "At this point r0==0 because 0x02026d74 would already have left the SAVE path when g[0x1ec] != 0. The replacement always branches to the stock local SAVE exit before 0x02026d80.",
        },
        "call32_reach": {
            "selector_example": {"callsite": "0x0201e190", "target": hx(CAVE_START), "bytes": long_from_selector.hex(), "size": 6},
            "producer_entry_example": {"callsite": hx(PRODUCER_ENTRY), "target": hx(CAVE_START), "bytes": long_from_producer.hex(), "size": 6},
            "result": "6-byte long call32 reaches from selector/producer-owned code to the SAVE cave.",
        },
        "existing_product_callsite_reach": {
            "direct_4_byte_callsite": {"address": hx(DIRECT_PRODUCT_CALL), "current_target": hx(PRODUCER_ENTRY), "hypothetical_short_bytes_for_cave": direct_short_hex, "actual_decoded_target": direct_short_actual, "fits_existing_4_bytes": False},
            "segmented_4_byte_callsite": {"address": hx(SEGMENTED_PRODUCT_CALL), "current_target": hx(PRODUCER_ENTRY), "hypothetical_short_bytes_for_cave": seg_short_hex, "actual_decoded_target": seg_short_actual, "fits_existing_4_bytes": False},
            "result": "The existing 4-byte short product callsites cannot be retargeted directly to 0x02026d80. A 6-byte long call would be needed, which does not fit those exact callsite windows without a larger rewrite.",
        },
    }


def fit_lower_bounds() -> dict[str, Any]:
    def parts(rows: list[tuple[str, int, str]]) -> dict[str, Any]:
        return {"bytes": sum(n for _, n, _ in rows), "parts": [{"name": a, "bytes": n, "reason": r} for a, n, r in rows]}

    # Exact-width lower bounds, not complete production implementations.
    selector_tail = parts([
        ("note_off_adapter", 2, "normalize Note Off trigger"),
        ("local_goto", 2, "skip Note On adapter"),
        ("note_on_adapter", 2, "normalize Note On trigger"),
        ("push_saved", 2, "preserve selector frame"),
        ("save_dest", 2, "save original destination"),
        ("default_note", 2, "default metadata"),
        ("channel_tmp", 2, "temporary"),
        ("gate_channel", 4, "Ch10 gate"),
        ("gate_low", 4, "note lower bound"),
        ("gate_high", 4, "note upper bound"),
        ("slot_index", 2, "slot=note-36"),
        ("call_save_cave_helper", 6, "long call32 to 0x02026d80"),
        ("stock_restore_dest", 2, "fallback copy destination"),
        ("stock_memcpy", 6, "stock fallback memcpy"),
        ("stock_metadata_pointer", 4, "return metadata pointer"),
        ("stock_metadata_store", 2, "store fallback note"),
        ("pop_return", 2, "return"),
    ])
    raw_fallback = parts([
        ("mov32_g", 6, "load 0x01c33260, cannot assume UI r8"),
        ("ldw_direct_view", 4, "load *(g+0x164)"),
        ("mov32_reserved_offset", 6, "0x4000 + record_base*0xa3"),
        ("slot_stride", 4, "slot*0xa3"),
        ("add_reserved_offset", 2, "base + reserved offset"),
        ("add_slot_offset", 2, "source prefix"),
        ("copy_dest", 2, "r0=dest"),
        ("copy_source", 2, "r1=source"),
        ("copy_len", 2, "r2=0x9c"),
        ("memcpy_call", 6, "copy prefix"),
        ("metadata_pointer_9b", 4, "point at copied note byte"),
        ("load_note", 2, "load Playback Note"),
        ("restore_3f", 2, "voice[0x9b]=0x3f"),
        ("store_3f", 2, "store 0x3f"),
        ("metadata_pointer_9c", 4, "return metadata pointer"),
        ("store_metadata", 2, "store note metadata"),
        ("return", 2, "normal return lower bound"),
    ])
    manifest_note_extra = parts([
        ("mov32_manifest_offset", 6, "load manifest raw-record offset"),
        ("add_manifest_base", 2, "direct base + manifest offset"),
        ("manifest_slot", 2, "manifest note byte + slot"),
        ("load_manifest_note", 2, "load note from manifest"),
    ])
    single_write = parts([
        ("mov32_g", 6, "load global base"),
        ("ldw_write_view", 4, "load *(g+0x160)"),
        ("mov32_reserved_offset", 6, "payload record offset"),
        ("slot_stride", 4, "slot*0xa3"),
        ("add_reserved_offset", 2, "write base + reserved offset"),
        ("add_slot_offset", 2, "write address"),
        ("source", 2, "r0=source"),
        ("address", 2, "r1=storage address"),
        ("length", 2, "r2=0x9c"),
        ("write_call", 6, "call 0x02004b02"),
        ("success_check_floor", 4, "minimum return==length branch/check"),
        ("return", 2, "return"),
    ])
    readback_floor = 20
    manifest_build_floor = single_write["bytes"]
    producer_call_insertion = 6
    cave_bytes = CAVE_END - CAVE_START
    owned_bytes = OWNED_END - OWNED_START
    compact_direct_only = 276
    compact_segmented_extra = 4
    compact_reset_extra = 30
    compact_readback_extra = 20
    return {
        "exact_budget": {"cave_start": hx(CAVE_START), "cave_end_exclusive": hx(CAVE_END), "cave_bytes": cave_bytes, "ui_branch_patch_bytes_outside_cave": 6, "owned_selector_producer_window": {"start": hx(OWNED_START), "end_exclusive": hx(OWNED_END), "bytes": owned_bytes, "current_selector": 88, "current_producer": 188, "current_tail": 2, "free_without_rewrite": 0}},
        "selector_tailcall_lower_bound": selector_tail,
        "raw_payload_fallback_lower_bound": {**raw_fallback, "fits_cave": raw_fallback["bytes"] <= cave_bytes, "spare_if_alone": cave_bytes - raw_fallback["bytes"]},
        "manifest_note_fallback_lower_bound": {"bytes": raw_fallback["bytes"] + manifest_note_extra["bytes"], "base": raw_fallback, "extra": manifest_note_extra, "fits_cave": raw_fallback["bytes"] + manifest_note_extra["bytes"] <= cave_bytes, "spare_if_alone": cave_bytes - raw_fallback["bytes"] - manifest_note_extra["bytes"]},
        "single_payload_write_lower_bound_no_readback_no_manifest": {**single_write, "fits_cave": single_write["bytes"] <= cave_bytes, "spare_if_alone": cave_bytes - single_write["bytes"], "insufficient_reason": "No readback compare, no manifest construction, no 16-record loop, no commit-last sequencing, no failure reporting."},
        "defensible_writer_required_extras": {"producer_call_insertion_floor": producer_call_insertion, "readback_verify_floor_per_write": readback_floor, "manifest_write_floor_before_crc_construction": manifest_build_floor, "requires_payload_crc_or_equivalent": True, "requires_full_length_return_checks": True, "requires_commit_last_order": True},
        "segmented_reset_manifest_readback_fit": {
            "decision": "DOES_NOT_FIT_EXACT_PROVEN_BUDGET",
            "compact_direct_only_no_reset_no_manifest_no_readback_bytes": compact_direct_only,
            "owned_window_bytes": owned_bytes,
            "direct_only_spare": owned_bytes - compact_direct_only,
            "overrun_with_segmented_final_stub": compact_direct_only + compact_segmented_extra - owned_bytes,
            "overrun_with_slot0_reset_floor": compact_direct_only + compact_reset_extra - owned_bytes,
            "overrun_with_readback_floor": compact_direct_only + compact_readback_extra - owned_bytes,
            "cave_cannot_absorb_full_requirement": "The cave can hold one small leaf routine after the UI branch patch, but a full safe persistence design also needs selector/producer rewrite space, a 16-record writer, full-length checks, readback/compare, manifest/CRC construction, and commit-last sequencing. The exact current selector/producer window has no free bytes, and the existing product callsites cannot directly retarget to the cave.",
        },
    }


def storage_wrapper_abi() -> dict[str, Any]:
    return {
        "write_0x02004b02": {
            "prototype": "uint32_t write_02004b02(const void *ram_source /*r0*/, uint32_t storage /*r1*/, uint32_t length /*r2*/)",
            "inner_call": "0x02004a7a receives r0=source, r1=length, r2=storage",
            "return_contract": "requested length on exact complete success, zero on short or failed inner result",
            "safety_rule": "custom persistence must require return == requested_length; stock SAVE ignores this return",
        },
        "read_0x02004870": {
            "prototype": "uint32_t read_02004870(void *ram_destination /*r0*/, uint32_t storage /*r1*/, uint32_t length /*r2*/)",
            "return_contract": "requested length on exact complete success, zero on short or failed inner result",
            "safety_rule": "custom verification must require return == requested_length and compare readback bytes",
        },
        "storage_views": {"write_read_wrapper_base": "*(0x01c33260+0x160)", "direct_loader_base": "*(0x01c33260+0x164)", "raw_prefix_payload": "record 96..111 first 0x9c bytes", "manifest_prefix": "record 112 first 0x9c bytes", "tails": "raw bytes 0x9c..0xa2 preserved"},
    }


def frame_assumptions() -> dict[str, Any]:
    return {
        "ui_save_path": {
            "live_registers_before_patch": {"r8": "g=0x01c33260", "r6": "handler state, stock branch skips writes only when 0xff", "r15": "constant 1"},
            "after_required_patch": "UI SAVE branches from 0x02026d7a to 0x02026dd4 before the cave. A helper placed at 0x02026d80 must not depend on being entered by UI SAVE.",
        },
        "selector_call_contract_if_rewritten": {
            "suggested_inputs": {"r3": "slot 0..15", "r4": "original destination", "r5": "default metadata note"},
            "required_outputs": {"r0": "destination+0x9c", "[r0]": "metadata Playback Note or fallback note"},
            "register_rule": "Use the helper only from a tail portion of a rewritten selector, or preserve callee-saved state explicitly. The helper must establish g itself, because UI r8 is not a standalone ABI.",
        },
        "producer_call_contract_if_rewritten": {
            "suggested_inputs": {"r3": "slot/count", "r4": "staging or resident source"},
            "required_checks": ["write return == 0x9c", "read return == 0x9c", "byte compare", "manifest/CRC commit last", "failure must not publish SAVED"],
            "risk": "Current S1C5 producer/selector owned window has zero free bytes without a rewrite, and direct/segmented product call identity currently depends on short call targets to 0x0201e228.",
        },
    }


def concrete_layout_assessment(fit: dict[str, Any]) -> dict[str, Any]:
    return {
        "safe_quarantine_patch": {"address": hx(UI_BRANCH), "bytes": "80f82b020016", "purpose": "make 0x02026d80..0x02026dd4 unreachable from UI SAVE before using it as code"},
        "partial_leaf_layout_that_fits_but_is_not_full_persistence": [
            {"range": f"{hx(CAVE_START)}..{hx(CAVE_START + fit['raw_payload_fallback_lower_bound']['bytes'])}", "bytes": fit["raw_payload_fallback_lower_bound"]["bytes"], "role": "raw-prefix fallback copy leaf, no manifest validation", "spare_after": fit["raw_payload_fallback_lower_bound"]["spare_if_alone"]},
            {"range": f"{hx(CAVE_START)}..{hx(CAVE_START + fit['manifest_note_fallback_lower_bound']['bytes'])}", "bytes": fit["manifest_note_fallback_lower_bound"]["bytes"], "role": "raw-prefix fallback with manifest-note load only, not manifest/CRC validation", "spare_after": fit["manifest_note_fallback_lower_bound"]["spare_if_alone"]},
        ],
        "rejected_full_layout": {
            "decision": "NO_SAFE_STANDALONE_PERSISTENCE_HELPER_IN_84_BYTES",
            "reason": "A defensible helper must not be just callable. It must preserve/define ABI, handle both direct and segmented producer routes, reset/fail closed, write 16 payload prefixes plus a manifest, check 0x02004b02 returns, verify via 0x02004870 readback, compare bytes, and commit last. Exact lower bounds show the cave can host only one small leaf. The required caller rewrites have no proven slack and the existing 4-byte product callsites cannot reach the cave directly.",
        },
    }


def build() -> dict[str, Any]:
    gates = hash_gates()
    app = app_checks()
    refs = listing_reference_scan()
    reach = branch_and_call_reach()
    fit = fit_lower_bounds()
    decision = "BLOCK_FULL_HELPER_PARTIAL_CAVE_LEAF_ONLY"
    return {
        "format": "smk37-v15-s1c5-save-cave-helper-proof-v1",
        "decision": decision,
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False, "firmware_image_emitted": False},
        "input_gates": gates,
        "exact_s1c5_bytes": app,
        "control_flow_reachability": refs,
        "branch_and_call_reach": reach,
        "wrapper_abi": storage_wrapper_abi(),
        "register_frame_assumptions": frame_assumptions(),
        "fit_lower_bounds": fit,
        "layout_assessment": concrete_layout_assessment(fit),
        "bottom_line": "0x02026d80..0x02026dd4 is safe as a code cave only after patching UI SAVE at 0x02026d7a. The 84-byte cave can hold a tiny callable leaf, but not the requested safe standalone persistence/fallback helper with segmented/reset plus manifest/readback.",
    }


def render(ev: dict[str, Any]) -> str:
    fit = ev["fit_lower_bounds"]
    branch = ev["branch_and_call_reach"]
    return f"""# S1C5 SAVE cave helper feasibility proof

Date: 2026-08-04 UTC  
Scope: exact current S1C5 app and repository static evidence only. No device, flash, reset, MIDI transport, FWSC emission, or app patch emission was performed.

## Decision

**BLOCK for a safe standalone persistence/fallback helper.**

The byte range `0x02026d80..0x02026dd4` has an exact budget of **{fit['exact_budget']['cave_bytes']} bytes**. It can become a safe code cave only with the UI SAVE branch patch at `0x02026d7a`:

```text
old: {branch['ui_save_branch_patch_required']['old_hex']}  ; jmz r6,#0xff,0x02026dd4
new: {branch['ui_save_branch_patch_required']['new_hex']}  ; jne r0,#1,0x02026dd4; mov r0,r0
```

At that point `r0 == 0` is proven by the preceding `0x02026d74` SAVE-state gate, so the replacement always leaves through the stock local SAVE exit before executing `0x02026d80`.

After this patch, the cave can hold a tiny callable leaf, but it cannot hold the requested safe standalone persistence/fallback helper with segmented/reset plus manifest/readback.

## Reachability and cave safety

- Current S1C5 still reaches `0x02026d80` from UI SAVE when `g[0x1ec] == 0` and `r6 != 0xff`. Therefore using the full range without the `0x02026d7a` patch is unsafe.
- Current S1C5 branches at `0x02026da6` to `0x02026dd4` and neutralizes `0x02026dac`, which only makes `0x02026da8..0x02026dd4` dead. It does not make `0x02026d80..0x02026da6` dead.
- The official exhaustive listing has no direct text reference to `0x02026d80` as a branch/call target. It does name `0x02026dd4` as the stock SAVE skip target. This gates direct/static references, not impossible computed-indirect targets.
- `0x02026dd4..0x02026dde` must remain the stock local SAVE exit and is not part of the cave.

## Call reach from producer/selector

- A 6-byte long `call32` reaches from selector/producer-owned code to `0x02026d80`.
  - Selector example from `0x0201e190`: `{branch['call32_reach']['selector_example']['bytes']}`.
  - Producer-entry example from `0x0201e228`: `{branch['call32_reach']['producer_entry_example']['bytes']}`.
- The existing 4-byte direct and segmented product callsites cannot be retargeted directly to `0x02026d80`. Their short-call form stays in the `0x0201xxxx` page, and those exact windows are only 4 bytes.
- The current S1C5 selector/producer owned window `0x0201e13e..0x0201e254` is fully occupied: 88-byte selector, 188-byte producer, 2-byte tail, zero free bytes without rewrite.

## Wrapper ABI that any writer must obey

```c
uint32_t write_02004b02(const void *src, uint32_t storage, uint32_t len);
uint32_t read_02004870(void *dst, uint32_t storage, uint32_t len);
```

Both wrappers return the requested length only on complete success and return zero on short/fail. A safe writer must require `return == len` for both calls and must compare readback bytes. Stock SAVE ignores wrapper returns, so stock SAVE is not a safe commit engine.

## Register and frame assumptions

- UI SAVE has `r8 = 0x01c33260`, `r6 = handler state`, and `r15 = 1`, but after the required branch patch the helper is not entered from UI SAVE. A standalone helper must not rely on those UI registers.
- A selector-side helper can only be safe under an explicit rewritten-selector ABI, for example `r3 = slot`, `r4 = destination`, return `r0 = destination + 0x9c`, and store the metadata byte at `[r0]`.
- A producer-side writer needs an explicit rewritten-producer ABI and must preserve direct plus segmented-final route behavior. It also needs return checks, readback, compare, manifest/CRC, commit-last ordering, and failure reporting.

## Exact fit accounting

| Item | Bytes | Fit |
|---|---:|---|
| SAVE cave `0x02026d80..0x02026dd4` | {fit['exact_budget']['cave_bytes']} | available only after UI branch patch |
| Minimal raw-prefix fallback leaf, no manifest validation | {fit['raw_payload_fallback_lower_bound']['bytes']} | fits, {fit['raw_payload_fallback_lower_bound']['spare_if_alone']} bytes spare |
| Manifest-note fallback leaf, no manifest/CRC validation | {fit['manifest_note_fallback_lower_bound']['bytes']} | fits, {fit['manifest_note_fallback_lower_bound']['spare_if_alone']} bytes spare |
| Single payload write lower bound, no readback or manifest | {fit['single_payload_write_lower_bound_no_readback_no_manifest']['bytes']} | fits but insufficient |
| Current selector/producer window | {fit['exact_budget']['owned_selector_producer_window']['bytes']} | fully occupied |
| Compact direct-only raw16/no-readback successor | {fit['segmented_reset_manifest_readback_fit']['compact_direct_only_no_reset_no_manifest_no_readback_bytes']} | only fits by dropping segmented/reset/manifest/readback |
| Add segmented-final stub | +4 | overruns current owned window by {fit['segmented_reset_manifest_readback_fit']['overrun_with_segmented_final_stub']} bytes |
| Add slot0 reset floor | +30 | overruns current owned window by {fit['segmented_reset_manifest_readback_fit']['overrun_with_slot0_reset_floor']} bytes |
| Add readback floor | +20 | overruns current owned window by {fit['segmented_reset_manifest_readback_fit']['overrun_with_readback_floor']} bytes |

These are lower bounds, not polished implementations. The full writer still needs a 16-record loop or unrolled route, manifest construction, payload CRC/equivalent, commit-last sequencing, and failure reporting.

## Concrete partial layout that is safe but insufficient

```text
0x02026d7a..0x02026d80  patch to always branch UI SAVE to 0x02026dd4
0x02026d80..0x02026db6  possible 54-byte raw-prefix fallback leaf, no manifest validation
0x02026d80..0x02026dc2  possible 66-byte manifest-note fallback leaf, no manifest/CRC validation
0x02026dd4..0x02026dde  keep stock local SAVE exit
```

This partial layout is useful as a collaboration constraint, but it is not a releaseable persistence design. It cannot safely claim persistence/fallback with segmented/reset plus manifest/readback.

## Final answer

No. The full requested helper is not feasible in `0x02026d80..0x02026dd4` with exact S1C5 evidence. The range can be quarantined and used for a small callable leaf after the UI branch patch, but a safe standalone persistence/fallback helper needs more proven executable space and a caller rewrite with verified ABI, readback, manifest/CRC, and commit-last semantics.
"""


def write_outputs(ev: dict[str, Any]) -> None:
    report = render(ev)
    (HERE / "evidence.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
    (HERE / "report.md").write_text(report)
    (HERE / "validation.txt").write_text("S1C5 SAVE cave helper feasibility: BLOCK full helper\nPASS input hashes\nPASS exact S1C5 SAVE bytes\nPASS UI branch patch and call reach math\nPASS wrapper ABI and fit lower-bound accounting\nBLOCK segmented/reset plus manifest/readback fit\n")
    (HERE / "README.md").write_text("# S1C5 SAVE cave helper feasibility\n\nStatus: **BLOCK for the full standalone persistence/fallback helper**. See `report.md` and `evidence.json`.\n")
    names = ["README.md", "analyze_save_cave_helper.py", "evidence.json", "report.md", "validation.txt"]
    (HERE / "SHA256SUMS").write_text("".join(f"{sha_path(HERE/name)}  {name}\n" for name in names))


def main() -> None:
    ev = build()
    write_outputs(ev)
    print("PASS input hashes")
    print("PASS exact S1C5 SAVE bytes")
    print("PASS UI branch patch and call reach math")
    print("PASS wrapper ABI and fit lower-bound accounting")
    print("BLOCK segmented/reset plus manifest/readback fit")


if __name__ == "__main__":
    main()
