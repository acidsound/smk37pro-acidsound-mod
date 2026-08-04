#!/usr/bin/env python3
"""Deterministic offline fit-first analysis for an S1C5 persistent default set.

This tool only reads repository artifacts. It never opens USB/MIDI, accesses a
device, builds an OTA image, or writes firmware/flash state.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FLASH = HERE.parent
S1C5 = FLASH / "S1C5-playback-register-return"
S1C4 = FLASH / "S1C4-playback-note-v3-segmented-final"
BANK_D = ROOT / "baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16"
CLEAN_DUMP = ROOT / "baselines/v15/device-dumps/v15-clean-baseline-a.bin"
PERSISTENCE = ROOT / "baselines/v15/analysis/patch-set-ui/persistence/report.md"
FACTORY = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/report.md"
APP_TAIL = ROOT / "baselines/v15/analysis/r03-owned-ram/app-tail-placement/report.md"
RAM_OWNERSHIP = ROOT / "baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md"

EXPECTED = {
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_fwsc": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "packet_manifest": "00b33cdef8cde252cc2fa8618c57e14c3d13cf2f961ff20b8de5ee2af698a5ff",
    "runtime_slots": "fdf7ebdf911041de64ebd80c3d807959b29034ef4e2fed35245b2dfe7b032270",
    "clean_dump": "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b",
    "persistence_report": "88309843407600fdbc9f9ac89e9e276103baf9b508cd310848f019f997440a9b",
    "factory_report": "1cd72971bf4db3bdf1dcdf113d5c795e0bb54f27af735b4ecda1319ef6b90d0d",
    "app_tail_report": "036eca79c6258a9ffff9f493874058a1876cbbe92f2cd76c27d06efe2f2c105c",
    "ram_ownership_report": "02a9727886da2643bf58f8f9b6dc65fa3c9cc6e34ba8fbaa4f4c1358d9ea691e",
    "s1c4_builder": "26fa5ca376cd89de9b403f933e011db56e48b298d45e3ef43be923397501e271",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
}


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shaf(path: Path) -> str:
    return sha(path.read_bytes())


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    req(spec is not None and spec.loader is not None, f"load module {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def input_gates() -> tuple[dict[str, Any], bytes]:
    paths = {
        "s1c5_app": S1C5 / "app.bin",
        "s1c5_fwsc": S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc",
        "packet_manifest": S1C5 / "inputs/packets/packet-manifest.json",
        "runtime_slots": BANK_D / "runtime-slots.bin",
        "clean_dump": CLEAN_DUMP,
        "persistence_report": PERSISTENCE,
        "factory_report": FACTORY,
        "app_tail_report": APP_TAIL,
        "ram_ownership_report": RAM_OWNERSHIP,
        "s1c4_builder": S1C4 / "build_s1c4_playback_note_v3_segmented_final.py",
    }
    gates: dict[str, Any] = {}
    for name, path in paths.items():
        actual = shaf(path)
        req(actual == EXPECTED[name], f"{name} hash")
        gates[name] = {
            "path": str(path.relative_to(ROOT)),
            "sha256": actual,
            "status": "PASS",
        }

    s1c5_builder = load_module("s2_s1c5_builder", S1C5 / "build_s1c5_playback_register_return.py")
    official_raw, _, official_app = s1c5_builder.app_from_fwsc(s1c5_builder.OFFICIAL_FWSC, True)
    req(sha(official_raw) == EXPECTED["official_fwsc"], "official FWSC extracted hash")
    req(sha(official_app) == EXPECTED["official_app"], "official app extracted hash")
    gates["official_fwsc"] = {
        "path": str(s1c5_builder.OFFICIAL_FWSC.relative_to(ROOT)),
        "sha256": sha(official_raw),
        "status": "PASS",
    }
    gates["official_app"] = {
        "path": "extracted from exact official FWSC",
        "sha256": sha(official_app),
        "status": "PASS",
    }
    return gates, official_app


def packet_and_table_evidence(official_app: bytes) -> dict[str, Any]:
    manifest_path = S1C5 / "inputs/packets/packet-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    runtime_slots = (BANK_D / "runtime-slots.bin").read_bytes()
    clean_dump = CLEAN_DUMP.read_bytes()
    s1c5_app = (S1C5 / "app.bin").read_bytes()

    req(manifest["packet_count"] == 16, "16 packet manifest")
    req(manifest["duplicate_playback_note_test"] == {"label": "C4", "slots": 16, "status": "PASS", "value": 60}, "all-C4 playback map")
    req(len(runtime_slots) == 16 * 0xA0, "runtime-slots stride table size")

    slots: list[dict[str, Any]] = []
    all_match = True
    all_absent = True
    for item in manifest["packets"]:
        packet = (S1C5 / "inputs/packets" / item["file"]).read_bytes()
        req(len(packet) == 163 and packet[:6] == bytes.fromhex("f0430000011b") and packet[-1] == 0xF7, f"packet framing slot {item['slot']}")
        payload = bytearray(packet[6:-1])
        req(payload[0x9B] == 60, f"packet playback byte slot {item['slot']}")
        stock_runtime = bytearray(payload)
        stock_runtime[0x9B] = 0x3F
        slot_off = item["slot"] * 0xA0
        table_voice = runtime_slots[slot_off:slot_off + 0x9C]
        matched = bytes(stock_runtime) == table_voice
        all_match &= matched
        hits = {
            "official_app": official_app.find(stock_runtime),
            "s1c5_app": s1c5_app.find(stock_runtime),
            "clean_dump": clean_dump.find(stock_runtime),
        }
        absent = all(v < 0 for v in hits.values())
        all_absent &= absent
        slots.append({
            "slot": item["slot"],
            "trigger_note": item["trigger_note"],
            "playback_note": item["playback_note"],
            "name": item["name"],
            "packet_sha256": sha(packet),
            "stock_runtime_sha256": sha(bytes(stock_runtime)),
            "matches_proven_runtime_slots_table": matched,
            "exact_stock_runtime_occurrences": {k: (None if v < 0 else v) for k, v in hits.items()},
        })

    req(all_match, "all packets match proven Bank D runtime table after restoring stock byte 0x9b")
    req(all_absent, "no exact expanded Bank D runtime record occurs in official app, S1C5 app, or clean dump")
    return {
        "packet_count": 16,
        "trigger_notes": [36, 51],
        "playback_notes": {"kind": "constant", "value": 60, "label": "C4"},
        "runtime_voice_bytes_each": 0x9C,
        "resident_stride_bytes_each": 0xA0,
        "expanded_payload_bytes": 16 * 0x9C,
        "resident_table_bytes": 16 * 0xA0,
        "packed_payload_floor_bytes": 16 * 0x80,
        "all_packets_match_proven_runtime_table": all_match,
        "exact_expanded_table_present_in_target_inputs": False,
        "scan_targets": ["official app", "exact S1C5 app", "clean baseline dump"],
        "slots": slots,
    }


def fit_evidence() -> dict[str, Any]:
    builder = load_module("s2_s1c4_builder", S1C4 / "build_s1c4_playback_note_v3_segmented_final.py")
    code = builder.build_code()
    selector = len(code["selector"])
    producer = len(code["producer"])
    tail = len(code["tail"])
    window = builder.OWNED_END - builder.SEL_START
    req((selector, producer, tail, window) == (88, 188, 2, 278), "exact S1C5 inherited code accounting")

    # Exact official loader spans from the exhaustive listing/factory-loader audit.
    directed_setup = 0x020056B4 - 0x02005682
    conversion_core = 0x02005766 - 0x020056B4
    exact_conversion_path = 0x02005766 - 0x02005682
    req((directed_setup, conversion_core, exact_conversion_path) == (50, 178, 228), "factory expansion span arithmetic")

    return {
        "owned_executable_window": {
            "start": "0x0201e13e",
            "end_exclusive": "0x0201e254",
            "bytes": window,
            "current_s1c5_selector_bytes": selector,
            "current_s1c5_producer_bytes": producer,
            "current_tail_bytes": tail,
            "free_bytes_without_replacing_current_functionality": 0,
            "bytes_if_host_producer_and_tail_are_reclaimed_but_selector_is_kept": producer + tail,
        },
        "official_factory_expansion_spans": {
            "source_destination_setup": {"start": "0x02005682", "end_exclusive": "0x020056b4", "bytes": directed_setup},
            "pure_128_to_156_conversion_core": {"start": "0x020056b4", "end_exclusive": "0x02005766", "bytes": conversion_core},
            "setup_plus_conversion": {"start": "0x02005682", "end_exclusive": "0x02005766", "bytes": exact_conversion_path},
        },
        "fit_attempts": [
            {
                "name": "keep exact S1C5 selector, reuse exact official conversion core only",
                "bytes": selector + conversion_core,
                "window_bytes": window,
                "remaining_bytes": window - selector - conversion_core,
                "missing_even_before_candidate": [
                    "caller-directed immutable source selection",
                    "destination/slot arithmetic",
                    "nonblocking writer serialization and recheck",
                    "valid-last publication",
                    "constant C4 playback metadata publication",
                ],
                "decision": "BLOCK",
            },
            {
                "name": "keep exact S1C5 selector, reuse exact official setup plus conversion",
                "bytes": selector + exact_conversion_path,
                "window_bytes": window,
                "overrun_bytes": selector + exact_conversion_path - window,
                "decision": "BLOCK",
            },
            {
                "name": "embed exact expanded 16-voice table",
                "data_bytes": 16 * 0x9C,
                "jlfs_preserving_append_capacity_bytes": 0,
                "decision": "BLOCK",
            },
            {
                "name": "embed packed 16-voice table and materialize lazily",
                "data_bytes": 16 * 0x80,
                "requires_conversion": True,
                "jlfs_preserving_append_capacity_bytes": 0,
                "decision": "BLOCK",
            },
        ],
        "interpretation": "The exact-stock-code fit attempt fails. This is not a theorem that no hand-optimized converter could ever be smaller; candidate promotion is independently blocked by the absence of a proven immutable exact source table and by zero safe app/JLFS data capacity.",
    }


def build_evidence() -> dict[str, Any]:
    gates, official_app = input_gates()
    packets = packet_and_table_evidence(official_app)
    fit = fit_evidence()
    return {
        "format": "smk37-v15-s2-persistent-default.block-evidence-v1",
        "decision": "BLOCK",
        "candidate_built": False,
        "scope": {
            "offline_only": True,
            "device_accessed": False,
            "midi_transport_opened": False,
            "flash_performed": False,
            "ota_performed": False,
            "reset_performed": False,
            "custom_persistent_write_designed": False,
        },
        "goal": {
            "basis": "exact current S1C5 app/package",
            "default_set": "Bank D patches 1..16 in trigger-note order 36..51",
            "playback_note_map": "all 16 Playback Note bytes are C4/60",
            "requested_lifecycle": "power-cycle default without host SysEx, preferring lazy first-use materialization",
        },
        "input_gates": gates,
        "packet_and_table_evidence": packets,
        "fit_evidence": fit,
        "source_matrix": [
            {
                "source": "stock packed/current Patch store via *(0x01c33260+0x164)",
                "benefit": "official loader-proven packed 0x80 records",
                "blockers": ["mutable through SAVE/default-load", "not an immutable exact default", "requires 128-to-156 materialization"],
                "decision": "BLOCK",
            },
            {
                "source": "product RAM/default-bank workspace at 0x01c0de20 + bank*0x49e3",
                "benefit": "official source for bank-image/default-bank save",
                "blockers": ["UI/product-owned dynamic workspace", "no session-stable immutable-table proof", "requires format decode/materialization"],
                "decision": "BLOCK",
            },
            {
                "source": "exact expanded 16-voice table embedded in app/JLFS",
                "benefit": "deterministic byte identity with the known packet set",
                "blockers": ["2496-byte payload", "0-byte JLFS-preserving append capacity", "exact records absent from official app/S1C5 app/clean dump"],
                "decision": "BLOCK",
            },
            {
                "source": "global factory loader 0x02005660 on first note",
                "benefit": "official materialization behavior",
                "blockers": ["hardcoded global selection/destination", "UI/helper/global side effects", "not caller-directed", "prohibited in MIDI Note hot path"],
                "decision": "BLOCK",
            },
        ],
        "blocking_findings": [
            "No proven immutable on-device table contains the exact 16 expanded Bank D runtime records.",
            "The two official record sources are mutable or UI/product-owned and require a converter.",
            "The exact official conversion path does not fit beside the exact S1C5 selector, and even the conversion core leaves only 12 bytes before required source, locking, publication, and playback-map logic.",
            "The application/JLFS layout has zero safe append capacity for either the 2496-byte expanded table or the 2048-byte packed table.",
            "Calling the global factory loader from first-note handling would introduce the specifically disallowed global/UI side effects.",
        ],
        "promotion_requirements": [
            "Prove an immutable exact Bank D source table address and lifetime, or prove a safe fixed-size in-app replacement region of sufficient size.",
            "Produce a caller-directed side-effect-free 128-to-156 materializer and exact PI32 fit within a proven executable region.",
            "Prove nonblocking first-use publication for Note On and matched Note Off identity without loader/storage work in the hot path after publication.",
            "Then build a child of exact S1C5 with deterministic package, rollback, validator, exact OTA gate, and independent review.",
        ],
        "emitted_artifacts": {
            "app_bin": False,
            "fwsc": False,
            "rollback_bundle": False,
            "exact_ota": False,
            "reason": "User required BLOCK evidence only when infeasible; emitting release/flash artifacts would misrepresent this result.",
        },
    }


def render_report(ev: dict[str, Any]) -> str:
    fit = ev["fit_evidence"]
    packets = ev["packet_and_table_evidence"]
    return f"""# S2 persistent-default fit-first result: BLOCK

## Decision

**BLOCK.** No firmware candidate, FWSC, rollback bundle, or exact OTA executable is emitted.

The exact current S1C5 baseline and its known 16-packet Bank D set are pinned and reproduced offline. The target mapping is Bank D patches 1..16 on Trigger Notes 36..51, with all 16 Playback Note values fixed to C4/60. The packet payloads normalize byte `0x9b` back to stock `0x3f` and then match the proven Bank D runtime table for all 16 slots.

A safe power-cycle default cannot be promoted from the present evidence without either an immutable exact source table or sufficient proven code/data placement for a side-effect-free materializer. Neither exists.

## Exact fit-first attempt

| Item | Bytes |
|---|---:|
| S1C5 owned executable window `0x0201e13e..0x0201e254` | {fit['owned_executable_window']['bytes']} |
| Exact inherited S1C5 selector | {fit['owned_executable_window']['current_s1c5_selector_bytes']} |
| Exact inherited host producer | {fit['owned_executable_window']['current_s1c5_producer_bytes']} |
| Tail | {fit['owned_executable_window']['current_tail_bytes']} |
| Official factory 128-to-156 conversion core `0x020056b4..0x02005766` | {fit['official_factory_expansion_spans']['pure_128_to_156_conversion_core']['bytes']} |
| Official source/destination setup plus conversion `0x02005682..0x02005766` | {fit['official_factory_expansion_spans']['setup_plus_conversion']['bytes']} |

Keeping the exact 88-byte S1C5 selector and reusing only the exact 178-byte official conversion core consumes 266 of 278 bytes, leaving 12 bytes. That excludes caller-directed immutable source selection, destination/slot arithmetic, nonblocking serialization/recheck, valid-last publication, and C4 playback metadata. Including the official setup reaches 316 bytes, 38 bytes beyond the window.

This is an exact-stock-code fit failure, not a claim that arbitrary hand-optimized code is mathematically impossible. Promotion is independently blocked by source provenance and zero safe app/JLFS capacity.

## Source decision matrix

| Source | Decision | Reason |
|---|---|---|
| `*(0x01c33260+0x164)` stock packed/current Patch store | BLOCK | Official and loader-proven, but mutable through SAVE/default-load and requires 128-to-156 conversion. It cannot guarantee the exact known default after prior user edits. |
| `0x01c0de20 + bank*0x49e3` product/default-bank workspace | BLOCK | Used by official bank-image save, but it is a dynamic UI/product workspace with no immutable lifetime/no-alias proof. |
| Embedded exact expanded table | BLOCK | {packets['expanded_payload_bytes']} payload bytes are required; JLFS-preserving append capacity is 0 bytes. |
| Embedded packed table | BLOCK | {packets['packed_payload_floor_bytes']} bytes plus converter are required; append capacity remains 0 bytes. |
| Call global loader `0x02005660` on first use | BLOCK | Hardcoded global selection/destination and UI/helper side effects. It is not a caller-directed materializer and is prohibited in the Note path. |

## Exact table scan

For each of the 16 stock-form 156-byte runtime records, exact-byte scans found no occurrence in:

- the extracted official v15 app;
- the exact S1C5 app;
- the clean baseline device dump.

The repository's `runtime-slots.bin` is a proven offline derivation, not an on-device table address. The target therefore cannot simply copy a resident exact table after boot.

## Why no release artifacts exist

The user required BLOCK evidence only if infeasible. Accordingly this directory intentionally contains no:

- `app.bin`;
- `.fwsc` package;
- rollback sectors;
- OTA uploader or exact OTA confirmation token;
- device/live sender.

Creating any of those would incorrectly imply a flashable candidate. No device, MIDI transport, OTA, reset, or flash operation was performed.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S2-persistent-default/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S2-persistent-default/validate.py
(cd baselines/v15/analysis/flash-candidates/S2-persistent-default && shasum -a 256 -c SHA256SUMS)
```

## Unblock requirements

1. Prove an immutable exact Bank D source table and lifetime, or a safe fixed-size in-app replacement region large enough for exact source data.
2. Produce a caller-directed, side-effect-free 128-to-156 materializer that fits a proven executable region.
3. Prove first-use concurrency/publication and matched Note On/Note Off identity without global loader or storage activity after publication.
4. Only then build an exact S1C5 child with deterministic FWSC, rollback, validator, exact OTA gate, and independent review.
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="verify committed generated artifacts instead of writing them")
    args = parser.parse_args()

    ev = build_evidence()
    report = render_report(ev)
    evidence_text = json.dumps(ev, indent=2, sort_keys=True) + "\n"
    if args.check:
        req((HERE / "evidence.json").read_text() == evidence_text, "evidence.json deterministic")
        req((HERE / "report.md").read_text() == report, "report.md deterministic")
        print("PASS exact S1C5 and 16-packet Bank D input gates")
        print("PASS all-C4 Playback Note map and runtime-table identity")
        print("PASS exact expanded-table absence scan")
        print("PASS exact-stock-code fit attempt")
        print("BLOCK persistent-default candidate: source provenance, code fit, and data placement")
        print("BLOCK app/FWSC/rollback/exact OTA/device/flash")
        return
    (HERE / "evidence.json").write_text(evidence_text)
    (HERE / "report.md").write_text(report)
    print("wrote evidence.json and report.md")


if __name__ == "__main__":
    main()
