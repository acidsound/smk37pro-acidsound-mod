#!/usr/bin/env python3
"""Fit-first offline analysis for an official-v15/S1C5 persistence successor.

This evaluates the raw-record persistence architecture and the selector-side
fallback proposal without accessing a device, MIDI transport, OTA path, or flash.
It reuses the exact PI32 assembler helpers from the accepted S1C4/S1C5 lineage
for concrete lower-bound byte accounting.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FLASH = HERE.parent
ANALYSIS = HERE.parents[1]
S1C5 = FLASH / "S1C5-playback-register-return"
S1C4 = FLASH / "S1C4-playback-note-v3-segmented-final"
STORAGE = ANALYSIS / "persistence-s2" / "storage"
RESTORE = ANALYSIS / "persistence-s2" / "restore"
WRITER = HERE / "persistence_writer.py"

BASE = 0x02000000
SEL_START = 0x0201E13E
OWNED_END = 0x0201E254
SAVE_BRANCH = 0x02026DA6
SAVE_DEAD_START = 0x02026DA8
SAVE_DEAD_END = 0x02026DD4
MEMCPY = 0x02048CCE
WRITE_WRAPPER = 0x02004B02
READ_WRAPPER = 0x02004870
SLOTS = 16
RAW_RECORD_SIZE = 0xA3
PREFIX_SIZE = 0x9C
STORED_VOICE_BYTES = 0x9B
RECORD_BASE = 96
MANIFEST_INDEX = 112

EXPECTED = {
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_fwsc": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "s1c5_live_validation": "94fc5083ff1ce1061c474eba18a30ad3f10a277f85c84f6cee5a117c2593f152",
    "storage_evidence": "118652843f402c3c4f3eca04da9f1fea38f826bd964276008b039307ac61993e",
    "storage_report": "7867925da16e1c85a7c809dffa8127c371e863987b1570fdc1488460f921dbc7",
    "restore_evidence": "9b57beb9d9cff2a363b59844264f741aadbb4d311d9dd8afcb9f0b211e93041e",
    "restore_report": "c9ce9d4da638790c7e2803a1e85133cedfb8a069204d81ddbdb1bc5eba32b7c1",
    "s1c4_builder": "26fa5ca376cd89de9b403f933e011db56e48b298d45e3ef43be923397501e271",
    "compact_producer_report": "801e3088e08e62d6736c25f5fd39da948d33a847e591983f4139c3b24dadecc4",
    "compact_producer_evidence": "0e8d2c664f770889d6a714fff61a351652552fbd38e5aacf1ff444268c1aed3a",
    "save_branch_bytes": "04960000",
}


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shaf(path: Path) -> str:
    return sha(path.read_bytes())


def hx(value: int) -> str:
    return f"0x{value:08x}"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    req(spec is not None and spec.loader is not None, f"load module {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def input_gates() -> dict[str, Any]:
    paths = {
        "s1c5_app": S1C5 / "app.bin",
        "s1c5_fwsc": S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc",
        "s1c5_live_validation": S1C5 / "live-validation-20260804.md",
        "storage_evidence": STORAGE / "evidence.json",
        "storage_report": STORAGE / "report.md",
        "restore_evidence": RESTORE / "evidence.json",
        "restore_report": RESTORE / "report.md",
        "s1c4_builder": S1C4 / "build_s1c4_playback_note_v3_segmented_final.py",
        "compact_producer_report": FLASH / "S1C3-16slot-functional-v2-r3-reload" / "inputs" / "producer" / "report.md",
        "compact_producer_evidence": FLASH / "S1C3-16slot-functional-v2-r3-reload" / "inputs" / "producer" / "evidence.json",
    }
    gates: dict[str, Any] = {}
    for name, path in paths.items():
        actual = shaf(path)
        req(actual == EXPECTED[name], f"{name} hash")
        gates[name] = {"path": str(path.relative_to(ROOT)), "sha256": actual, "status": "PASS"}
    app = (S1C5 / "app.bin").read_bytes()
    req(app[SAVE_BRANCH - BASE:SAVE_BRANCH - BASE + 4].hex() == EXPECTED["save_branch_bytes"], "S1C5 SAVE no-write branch")
    gates["save_no_write_branch"] = {
        "address": hx(SAVE_BRANCH),
        "bytes": EXPECTED["save_branch_bytes"],
        "target": hx(SAVE_DEAD_END),
        "status": "PASS",
    }
    return gates


def exact_assembler_lower_bounds() -> dict[str, Any]:
    asm = load_module("s1c6_exact_pi32_tools", S1C4 / "build_s1c4_playback_note_v3_segmented_final.py")

    def part(name: str, data: bytes, reason: str) -> dict[str, Any]:
        return {"name": name, "bytes": len(data), "hex": data.hex(), "reason": reason}

    # ldw encoding is pinned from exact listing rows such as d1ec4476 = ldw r7,r4,#0x164.
    # It is included as a four-byte exact-width primitive because the accepted assembler
    # module does not expose ldw as a helper.
    ldw_width = 4
    ret_width = 2
    branch_check_width = 4

    selector_tailcall_parts = [
        part("note_off_adapter", asm.mov(3, 5), "normalize Note Off trigger"),
        part("goto_core", asm.word(0), "2-byte local goto lower bound"),
        part("note_on_adapter", asm.mov(3, 6), "normalize Note On trigger"),
        part("push_saved", asm.word(0x0479), "preserve r9..r4 and caller return"),
        part("save_dest", asm.mov(4, 0), "save destination"),
        part("default_note", asm.mov(5, 3), "fallback metadata = trigger"),
        part("channel_tmp", asm.mov(6, 9), "channel temp"),
        part("gate_channel", b"\0" * 4, "jne non-Ch10 to stock copy"),
        part("gate_low", b"\0" * 4, "jl below note 36 to stock copy"),
        part("gate_high", b"\0" * 4, "jge note 52 to stock copy"),
        part("slot_index", asm.add8(3, -36), "slot = trigger - 36"),
        part("tailcall_persistent_or_armed_helper", asm.call32(SEL_START, SAVE_DEAD_START), "tail-call external helper"),
        part("stock_restore_dest", asm.mov(0, 4), "stock fallback copy restores destination"),
        part("stock_memcpy", asm.call32(SEL_START, MEMCPY), "stock fallback memcpy"),
        part("stock_metadata_pointer", asm.add12(0, 4, PREFIX_SIZE), "return metadata pointer"),
        part("stock_metadata_store", asm.sb(5, 0), "store fallback note"),
        part("pop_return", asm.word(0x0459), "return to native caller"),
    ]
    selector_tailcall_bytes = sum(p["bytes"] for p in selector_tailcall_parts)

    raw_fallback_parts = [
        part("mov32_g", asm.mov32(7, 0x01C33260), "global object base"),
        {"name": "ldw_direct_view", "bytes": ldw_width, "hex": "d1ec7476", "reason": "*(g+0x164), exact-width ldw primitive"},
        part("mov32_reserved_offset", asm.mov32(6, 0x4000 + RECORD_BASE * RAW_RECORD_SIZE), "first reserved raw prefix offset"),
        part("slot_stride", asm.mul12(3, 3, RAW_RECORD_SIZE), "slot * 0xa3"),
        part("add_reserved_offset", asm.add(7, 6), "direct base + reserved offset"),
        part("add_slot_offset", asm.add(7, 3), "source = reserved slot prefix"),
        part("copy_dest", asm.mov(0, 4), "destination"),
        part("copy_source", asm.mov(1, 7), "source"),
        part("copy_len", asm.mov8(2, PREFIX_SIZE), "length 0x9c"),
        part("memcpy_call", asm.call32(SAVE_DEAD_START, MEMCPY), "copy prefix"),
        part("metadata_pointer_9b", asm.add12(0, 4, STORED_VOICE_BYTES), "point at copied note byte"),
        part("load_note", asm.lb(5, 0), "load Playback Note from copied byte 0x9b"),
        part("restore_3f", asm.mov8(6, 0x3F), "voice[0x9b] restore value"),
        part("store_3f", asm.sb(6, 0), "force destination[0x9b]=0x3f"),
        part("metadata_pointer_9c", asm.add12(0, 4, PREFIX_SIZE), "return metadata pointer"),
        part("store_metadata", asm.sb(5, 0), "store Playback Note metadata"),
        {"name": "return_or_pop", "bytes": ret_width, "hex": "0459", "reason": "return to native caller via saved selector frame"},
    ]
    raw_fallback_bytes = sum(p["bytes"] for p in raw_fallback_parts)

    manifest_note_extra_parts = [
        part("mov32_manifest_offset", asm.mov32(6, 0x4000 + MANIFEST_INDEX * RAW_RECORD_SIZE), "manifest record prefix offset"),
        part("add_manifest_base", asm.add(7, 6), "direct base + manifest offset"),
        part("manifest_slot", asm.add(7, 3), "manifest note byte + slot"),
        part("load_manifest_note", asm.lb(5, 7), "load note from manifest"),
    ]
    manifest_extra_bytes = sum(p["bytes"] for p in manifest_note_extra_parts)

    writer_payload_parts = [
        part("mov32_g", asm.mov32(7, 0x01C33260), "global object base"),
        {"name": "ldw_write_view", "bytes": ldw_width, "hex": "d1ec6076", "reason": "*(g+0x160), exact-width ldw primitive"},
        part("mov32_reserved_offset", asm.mov32(6, 0x4000 + RECORD_BASE * RAW_RECORD_SIZE), "first reserved raw prefix offset"),
        part("slot_stride", asm.mul12(3, 3, RAW_RECORD_SIZE), "slot * 0xa3"),
        part("add_reserved_offset", asm.add(7, 6), "write base + reserved offset"),
        part("add_slot_offset", asm.add(7, 3), "write address"),
        part("source_staging", asm.mov(0, 4), "source staging or resident voice prefix"),
        part("address_arg", asm.mov(1, 7), "storage address argument"),
        part("len_arg", asm.mov8(2, PREFIX_SIZE), "length 0x9c"),
        part("write_call", asm.call32(SAVE_DEAD_START, WRITE_WRAPPER), "call 0x02004b02"),
        {"name": "success_check", "bytes": branch_check_width, "hex": "00000000", "reason": "minimum compare/branch gate for return == 0x9c"},
        {"name": "return", "bytes": ret_width, "hex": "0459", "reason": "return lower bound"},
    ]
    writer_payload_bytes = sum(p["bytes"] for p in writer_payload_parts)
    readback_floor = 6 + 2 + 2 + 6 + branch_check_width  # mov scratch, len/address moves, read call, compare/branch lower bound
    manifest_write_floor = writer_payload_bytes  # one additional prefix write, before building manifest bytes
    insertion_floor = 6  # producer needs at least one call32 insertion in its already-full 188-byte body
    compact_successor = {
        "basis": "S1C3/S1C4 compact sequential producer with reset wrapper removed and reset folded or omitted",
        "compact_sequential_playback_producer_bytes": 142,
        "segmented_stub_bytes": 4,
        "slot0_signature_reset_fold_floor_bytes": 30,
        "selector_with_inline_raw_payload_fallback_floor_bytes": 128,
        "producer_call_to_save_helper_floor_bytes": insertion_floor,
        "owned_window_bytes": OWNED_END - SEL_START,
        "fits_if_direct_only_no_reset_no_manifest_no_readback": 128 + 142 + insertion_floor <= (OWNED_END - SEL_START),
        "direct_only_no_reset_no_manifest_no_readback_bytes": 128 + 142 + insertion_floor,
        "overrun_with_segmented_stub": 128 + 142 + insertion_floor + 4 - (OWNED_END - SEL_START),
        "overrun_with_slot0_reset_floor": 128 + 142 + insertion_floor + 30 - (OWNED_END - SEL_START),
        "overrun_with_defensible_readback_floor": 128 + 142 + insertion_floor + readback_floor - (OWNED_END - SEL_START),
        "decision": "BLOCK_AS_DEFENSIBLE_SUCCESSOR",
        "interpretation": "The compact-producer direction can make a direct-only raw16/no-readback experiment fit, but keeping segmented-final/reset behavior or adding required readback/manifest defensibility overruns the exact byte budget. The fitting variant also uses no 17th manifest and cannot be promoted as the requested defensible 17-record persistence successor.",
    }

    return {
        "tooling": {
            "source": str((S1C4 / "build_s1c4_playback_note_v3_segmented_final.py").relative_to(ROOT)),
            "sha256": EXPECTED["s1c4_builder"],
            "status": "reused exact PI32 helper encoders for mov/mov32/mov8/add/add12/mul12/lb/sb/call32/word",
        },
        "available_windows": {
            "s1c5_owned_window": {"start": hx(SEL_START), "end_exclusive": hx(OWNED_END), "bytes": OWNED_END - SEL_START, "current_selector": 88, "current_producer": 188, "current_tail": 2, "free_without_rewrite": 0},
            "save_no_write_dead_slice": {"start": hx(SAVE_DEAD_START), "end_exclusive": hx(SAVE_DEAD_END), "bytes": SAVE_DEAD_END - SAVE_DEAD_START, "requires_preserving_branch_at": hx(SAVE_BRANCH)},
        },
        "selector_tailcall_lower_bound": {"bytes": selector_tailcall_bytes, "parts": selector_tailcall_parts},
        "raw_payload_fallback_helper_lower_bound": {"bytes": raw_fallback_bytes, "parts": raw_fallback_parts, "decision_vs_save_dead_slice": "BLOCK" if raw_fallback_bytes > (SAVE_DEAD_END - SAVE_DEAD_START) else "PASS"},
        "manifest_note_extra_lower_bound": {"bytes": manifest_extra_bytes, "parts": manifest_note_extra_parts},
        "manifest_variant_helper_lower_bound": {"bytes": raw_fallback_bytes + manifest_extra_bytes, "decision_vs_save_dead_slice": "BLOCK"},
        "payload_write_helper_lower_bound_no_readback_no_manifest": {"bytes": writer_payload_bytes, "parts": writer_payload_parts, "decision_vs_save_dead_slice": "BLOCK" if writer_payload_bytes > (SAVE_DEAD_END - SAVE_DEAD_START) else "PASS_BUT_INSUFFICIENT"},
        "compact_successor_fit_after_boar_dm": compact_successor,
        "defensible_writer_required_extras": {
            "producer_call_insertion_floor_bytes": insertion_floor,
            "readback_verify_floor_bytes_per_write": readback_floor,
            "manifest_write_floor_bytes": manifest_write_floor,
            "needs_manifest_construction_or_16_note_snapshot": True,
            "needs_full_length_return_check": True,
            "needs_0x02004870_readback": True,
        },
    }


def storage_plan() -> dict[str, Any]:
    first = 0x4000 + RECORD_BASE * RAW_RECORD_SIZE
    manifest = 0x4000 + MANIFEST_INDEX * RAW_RECORD_SIZE
    return {
        "decision": "PASS_AS_DATA_FORMAT_ONLY",
        "record_reservation_policy": "reserve existing stock raw-record prefixes explicitly; they are not proven free records",
        "payload_records": SLOTS,
        "manifest_records": 1,
        "record_base_index": RECORD_BASE,
        "manifest_index": MANIFEST_INDEX,
        "payload_offset_range": [f"0x{first:04x}", f"0x{first + SLOTS * RAW_RECORD_SIZE:04x}"],
        "manifest_offset": f"0x{manifest:04x}",
        "payload_prefix_encoding": "raw[i][0x00..0x9a]=voice[0x00..0x9a], raw[i][0x9b]=playback_note; raw tails 0x9c..0xa2 preserved",
        "manifest_prefix_role": "magic/version/commit/record base/generation/payload CRC; tail preserved",
        "restore_rule": "copy prefix, load playback note from byte 0x9b, force destination voice[0x9b]=0x3f, return metadata note",
        "volatile_webmidi_preservation_rule": "if S1C5 RAM state is ARMED and selected slot valid, keep current RAM selector behavior; persistent fallback is only for not-armed state",
    }


def writer_probe() -> dict[str, Any]:
    result = subprocess.run([sys.executable, str(WRITER), "--json"], cwd=HERE, text=True, capture_output=True, check=False)
    req(result.returncode == 0, "offline persistence writer encoder")
    encoded = json.loads(result.stdout)
    req(encoded["record_count"] == 17 and encoded["payload_record_count"] == 16, "writer encodes 17 prefixes")
    req(encoded["writer_scope"]["persistent_storage_write_performed"] is False, "writer is offline only")
    return {
        "status": "PASS_OFFLINE_ENCODER_ONLY",
        "path": str(WRITER.relative_to(ROOT)),
        "sha256": shaf(WRITER),
        "record_count": encoded["record_count"],
        "canonical_payload_crc32": encoded["canonical_payload_crc32"],
        "record_base": encoded["record_base"],
        "manifest_index": encoded["manifest_index"],
        "device_accessed": False,
        "persistent_storage_write_performed": False,
    }


def build_evidence() -> dict[str, Any]:
    gates = input_gates()
    fit = exact_assembler_lower_bounds()
    writer = writer_probe()
    return {
        "format": "smk37-v15-s1c6-raw17-persistence-fit-block-v1",
        "decision": "BLOCK",
        "candidate_built": False,
        "scope": {
            "offline_only": True,
            "device_accessed": False,
            "midi_transport_opened": False,
            "flash_performed": False,
            "ota_performed": False,
            "reset_performed": False,
            "fwsc_emitted": False,
        },
        "goal": {
            "basis_commits": ["90080a5", "c1c06c1"],
            "basis_candidate": "official-v15/S1C5 Playback Register Return",
            "requested_successor": "persist current 16 patch voices plus per-pad Playback Notes across power cycles while preserving volatile WebMIDI updates",
        },
        "input_gates": gates,
        "storage_plan": storage_plan(),
        "offline_persistence_writer": writer,
        "fit_evidence": fit,
        "candidate_architecture_assessment": [
            {
                "name": "17 reserved raw-record prefixes",
                "decision": "PASS_AS_DATA_FORMAT_ONLY",
                "reason": "storage-s2 proves 16 payload prefixes plus a manifest prefix can encode the data while preserving raw tails",
            },
            {
                "name": "selector-side persistent fallback preserving volatile RAM updates",
                "decision": "BLOCK_AS_FLASH_CANDIDATE_TODAY",
                "reason": "architecturally promising, but the exact helper does not fit the only standalone disabled SAVE slice, and promoting split/noncontiguous code still leaves the mandatory writer unplaced and unverified",
            },
            {
                "name": "compact producer replacement with direct-only raw fallback",
                "decision": "BLOCK_AS_DEFENSIBLE_SUCCESSOR",
                "reason": "exact accounting shows a direct-only raw16/no-readback experiment can fit in 276/278 bytes, but adding segmented-final compatibility, slot0 reset, manifest/17th-record validation, or readback verification overruns; this is not the requested defensible persistence successor",
            },
            {
                "name": "producer-called persistence writer in disabled SAVE body",
                "decision": "BLOCK",
                "reason": "the exact-width lower bound for a single unchecked payload write already consumes the disabled SAVE slice, before producer call insertion, manifest update, return checks, 0x02004870 readback, CRC, or power-loss semantics",
            },
            {
                "name": "lazy restore helper in disabled SAVE body",
                "decision": "BLOCK",
                "reason": "a minimal direct raw-prefix copy-and-metadata helper is larger than the dead SAVE slice, and a defensible manifest-validating restore is larger still",
            },
        ],
        "blocking_findings": [
            "Data storage is feasible only with an explicit stock raw-prefix reservation policy, not with free stock records.",
            "The only always-disabled SAVE slice preserving UI SAVE no-write behavior is 44 bytes at 0x02026da8..0x02026dd4.",
            "The exact PI32 lower bound for direct raw fallback is larger than that slice; the manifest-note variant adds further bytes.",
            "A persistence writer that is defensible must check 0x02004b02 full-length returns and verify with 0x02004870 readback; the lower bound does not fit and the current S1C5 producer has no insertion slack.",
            "The compact-producer path was evaluated: a direct-only raw16/no-readback variant fits at 276/278 bytes, but any segmented-final, reset, readback, or manifest/17th-record defensibility requirement overruns.",
            "Emitting app/FWSC/OTA artifacts without an on-device writer would not satisfy power-cycle persistence of current WebMIDI updates and would misrepresent the candidate.",
        ],
        "emitted_artifacts": {
            "app_bin": False,
            "fwsc": False,
            "exact_ota": False,
            "rollback_bundle": False,
            "offline_prefix_encoder": True,
            "block_validator": True,
        },
        "promotion_requirements": [
            "Prove a larger owned executable placement or a split-control PI32 implementation with independent branch/call/return review.",
            "Place a writer that performs full-length write checks, 0x02004870 readback verification, manifest/CRC commit-last behavior, and failure reporting.",
            "Then build a scoped S1C5 child app/FWSC, exact OTA, rollback, and independent validator without device access.",
        ],
    }


def render_report(ev: dict[str, Any]) -> str:
    fit = ev["fit_evidence"]
    storage = ev["storage_plan"]
    writer = ev["offline_persistence_writer"]
    save = fit["available_windows"]["save_no_write_dead_slice"]
    raw = fit["raw_payload_fallback_helper_lower_bound"]
    manifest = fit["manifest_variant_helper_lower_bound"]
    writer_lb = fit["payload_write_helper_lower_bound_no_readback_no_manifest"]
    compact = fit["compact_successor_fit_after_boar_dm"]
    return f"""# S1C6 raw17 persistence successor fit-first result: BLOCK

## Decision

**BLOCK.** No app, FWSC, exact OTA, or rollback bundle is emitted.

The 17-record raw-prefix storage format is feasible as a data format, and an offline encoder is included, but the full requested successor is not defensible today because the on-device selector fallback and especially the persistence writer cannot be placed with exact S1C5 evidence.

## Input gates

- S1C5 app SHA-256: `{ev['input_gates']['s1c5_app']['sha256']}`.
- S1C5 FWSC SHA-256: `{ev['input_gates']['s1c5_fwsc']['sha256']}`.
- S1C5 live validation SHA-256: `{ev['input_gates']['s1c5_live_validation']['sha256']}`.
- storage-s2 report SHA-256: `{ev['input_gates']['storage_report']['sha256']}`.
- restore-s2 report SHA-256: `{ev['input_gates']['restore_report']['sha256']}`.

## Reserved raw-prefix format

- Payload records: `{storage['record_base_index']}..{storage['record_base_index'] + 15}`.
- Manifest record: `{storage['manifest_index']}`.
- Payload encoding: `{storage['payload_prefix_encoding']}`.
- Tail policy: preserve every raw tail byte `0x9c..0xa2`.
- Volatile WebMIDI rule: `{storage['volatile_webmidi_preservation_rule']}`.

Offline prefix encoder: `{writer['path']}`, SHA-256 `{writer['sha256']}`, CRC `{writer['canonical_payload_crc32']}`. It performs no device or persistent-storage write.

## Fit proof

| Item | Bytes | Decision |
|---|---:|---|
| S1C5 owned selector/producer window `0x0201e13e..0x0201e254` | {fit['available_windows']['s1c5_owned_window']['bytes']} | occupied by current S1C5 selector/producer/tail |
| Disabled SAVE dead slice `{save['start']}..{save['end_exclusive']}` | {save['bytes']} | only standalone placement while preserving SAVE no-write branch |
| Minimal selector tail-call skeleton | {fit['selector_tailcall_lower_bound']['bytes']} | must coexist with producer in owned window |
| Minimal direct raw-prefix fallback helper, no manifest validation | {raw['bytes']} | {raw['decision_vs_save_dead_slice']} vs SAVE slice |
| Manifest-note fallback variant | {manifest['bytes']} | {manifest['decision_vs_save_dead_slice']} vs SAVE slice |
| Single payload write helper, no readback and no manifest | {writer_lb['bytes']} | {writer_lb['decision_vs_save_dead_slice']} and still insufficient |
| Compact direct-only raw16/no-readback variant | {compact['direct_only_no_reset_no_manifest_no_readback_bytes']} | fits only by dropping segmented/reset/manifest/readback |
| Compact variant with segmented-final stub | +{compact['segmented_stub_bytes']} over base | overruns by {compact['overrun_with_segmented_stub']} byte(s) |
| Compact variant with slot0 reset floor | +{compact['slot0_signature_reset_fold_floor_bytes']} over base | overruns by {compact['overrun_with_slot0_reset_floor']} bytes |
| Compact variant with readback floor | +{fit['defensible_writer_required_extras']['readback_verify_floor_bytes_per_write']} over base | overruns by {compact['overrun_with_defensible_readback_floor']} bytes |

A defensible writer additionally needs at least one producer call insertion, full-length return checks, `0x02004870` readback, manifest/CRC construction, commit-last ordering, and failure reporting. Those requirements are not present in the lower bound above.

## Why artifacts are not emitted

An app/FWSC with only a raw fallback reader would not persist current WebMIDI updates. An app/FWSC without verified manifest validation and writer placement would risk consuming uninitialized or corrupt stock raw prefixes. Therefore release artifacts would be misleading.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block && shasum -a 256 -c SHA256SUMS)
```

## Unblock requirements

1. Prove larger owned executable placement, or a complete split-control exact PI32 implementation with independent return/branch review.
2. Fit and verify a writer using `0x02004b02` full-length checks and `0x02004870` readback.
3. Validate manifest/CRC commit-last semantics and volatile-RAM precedence.
4. Only then emit app/FWSC, exact OTA, and rollback artifacts.
"""


def write_sha256sums() -> None:
    names = ["README.md", "analyze.py", "evidence.json", "persistence_writer.py", "report.md", "validate.py", "validation.txt"]
    (HERE / "SHA256SUMS").write_text("\n".join(f"{shaf(HERE / name)}  {name}" for name in names) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    ev = build_evidence()
    evidence_text = json.dumps(ev, indent=2, sort_keys=True) + "\n"
    report = render_report(ev)
    readme = "# S1C6 raw17 persistence BLOCK\n\n" + "Status: **BLOCK, no app/FWSC/OTA emitted**. See `report.md` and `evidence.json`.\n"
    validation = "S1C6 raw17 persistence fit-first validation: BLOCK\nPASS input hashes\nPASS raw-prefix storage format and offline encoder\nPASS exact PI32 lower-bound accounting\nBLOCK app/FWSC/exact OTA/rollback emission\n"
    if args.check:
        req((HERE / "evidence.json").read_text() == evidence_text, "evidence.json deterministic")
        req((HERE / "report.md").read_text() == report, "report.md deterministic")
        req((HERE / "README.md").read_text() == readme, "README.md deterministic")
        req((HERE / "validation.txt").read_text() == validation, "validation.txt deterministic")
        print("PASS input hashes")
        print("PASS raw-prefix storage format and offline encoder")
        print("PASS exact PI32 lower-bound accounting")
        print("BLOCK app/FWSC/exact OTA/rollback emission")
        return
    (HERE / "evidence.json").write_text(evidence_text)
    (HERE / "report.md").write_text(report)
    (HERE / "README.md").write_text(readme)
    (HERE / "validation.txt").write_text(validation)
    write_sha256sums()
    print("wrote S1C6 raw17 persistence BLOCK evidence")


if __name__ == "__main__":
    main()
