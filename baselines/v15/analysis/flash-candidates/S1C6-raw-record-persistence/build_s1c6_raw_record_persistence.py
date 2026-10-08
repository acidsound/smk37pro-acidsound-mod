#!/usr/bin/env python3
"""S1C6 raw-record persistence successor candidate generator.

Offline only. This script never opens a device, sends MIDI, flashes, resets, or
produces an installable package unless the fit gates prove a safe executable
hook. Current result is a deterministic data/rollback candidate plus a BLOCK
firmware-fit decision.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import zlib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
S1C5 = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return"
PACKETS = S1C5 / "inputs/packets"
CLEAN_DUMP = ROOT / "baselines/v15/device-dumps/v15-clean-baseline-a.bin"
S1C5_CODE = ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/evidence.json"
STORAGE_REPORT = ROOT / "baselines/v15/analysis/persistence-s2/storage/report.md"
RESTORE_REPORT = ROOT / "baselines/v15/analysis/persistence-s2/restore/report.md"

RAW_TABLE_DUMP_OFFSET = 0xF8000
RAW_TABLE_MAPPED_OFFSET = 0x4000
RAW_RECORD_SIZE = 0xA3
VOICE_SIZE = 0x9C
VOICE_LAST_OFFSET = 0x9B
TAIL_OFFSET = 0x9C
TAIL_SIZE = RAW_RECORD_SIZE - TAIL_OFFSET
MAP_OFFSET = 0x20
SLOTS = 16

# Preferred reservation avoids the current S1C5 demo source records D1..D16.
# It still deliberately reserves allocated stock records, so firmware must treat
# the selected records as owned by S1C6 and no longer stock-editable.
PREFERRED_MANIFEST_INDEX = 95   # bank C, preset 32, immediately before Bank D.
PREFERRED_PAYLOAD_BASE_INDEX = 112  # bank D, presets 17..32.

EXPECTED_SHA256 = {
    "clean_dump": "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b",
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_code": "c2c057912c8ed2ecaed37a8158a836b81985207b8f34586820b376f28c167eec",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def req(condition: bool, message: str, checks: list[str]) -> None:
    if not condition:
        raise AssertionError(message)
    checks.append("PASS\t" + message)


def hx(value: int, width: int = 0) -> str:
    return f"0x{value:0{width}x}" if width else f"0x{value:x}"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_packets(checks: list[str]) -> tuple[list[bytes], list[int], list[dict[str, Any]]]:
    manifest = json.loads((PACKETS / "packet-manifest.json").read_text(encoding="utf-8"))
    req(manifest["packet_count"] == SLOTS, "S1C5 packet manifest has 16 slots", checks)
    req(manifest["duplicate_playback_note_test"]["value"] == 60, "current S1C5 Playback Notes are all C4/60", checks)
    voices: list[bytes] = []
    notes: list[int] = []
    rows: list[dict[str, Any]] = []
    for slot, item in enumerate(manifest["packets"]):
        packet = (PACKETS / item["file"]).read_bytes()
        req(len(packet) == 163 and packet[:6] == bytes.fromhex("f0430000011b") and packet[-1] == 0xF7,
            f"slot {slot} exact 163-byte SysEx framing", checks)
        req(sha(packet) == item["sha256"], f"slot {slot} packet hash matches manifest", checks)
        voice = bytearray(packet[6:-1])
        req(len(voice) == VOICE_SIZE, f"slot {slot} runtime voice is 0x9c bytes", checks)
        note = int(item["playback_note"])
        req(0 <= note <= 127 and packet[161] == note and voice[VOICE_LAST_OFFSET] == note,
            f"slot {slot} wire byte 161 carries Playback Note {note}", checks)
        # S1C5 producer persists voice byte 0x9b as the proven stock value and
        # carries Playback Note out-of-band in 0x01c46f20+slot.
        voice[VOICE_LAST_OFFSET] = 0x3F
        voices.append(bytes(voice))
        notes.append(note)
        rows.append({
            "slot": slot,
            "trigger_note": item["trigger_note"],
            "playback_note": note,
            "packet_file": item["file"],
            "packet_sha256": item["sha256"],
            "normalized_voice_sha256": sha(bytes(voice)),
            "name": item.get("name"),
        })
    return voices, notes, rows


def raw_record(dump: bytes, index: int) -> bytes:
    start = RAW_TABLE_DUMP_OFFSET + index * RAW_RECORD_SIZE
    return dump[start:start + RAW_RECORD_SIZE]


def build_records(voices: list[bytes], notes: list[int], checks: list[str]) -> dict[str, Any]:
    dump = CLEAN_DUMP.read_bytes()
    req(sha(dump) == EXPECTED_SHA256["clean_dump"], "clean v15 baseline dump hash", checks)
    out = HERE / "records"
    rollback = HERE / "rollback" / "reserved-stock-raw-records"
    for directory in (out, rollback):
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True, exist_ok=True)

    payload_indices = [PREFERRED_PAYLOAD_BASE_INDEX + i for i in range(SLOTS)]
    manifest_index = PREFERRED_MANIFEST_INDEX
    reserved_indices = [manifest_index] + payload_indices
    req(len(set(reserved_indices)) == 17, "preferred layout reserves exactly 17 distinct stock raw records", checks)
    req(all(0 <= i < 128 for i in reserved_indices), "all preferred raw record indices are inside stock 128-record table", checks)

    original_records = {idx: raw_record(dump, idx) for idx in reserved_indices}
    candidate_records: dict[int, bytes] = {}
    payload_crc = 0
    for slot, index in enumerate(payload_indices):
        base = bytearray(original_records[index])
        base[:VOICE_SIZE] = voices[slot]
        req(base[VOICE_LAST_OFFSET] == 0x3F, f"payload record {index} slot {slot} stores normalized voice byte 0x9b", checks)
        req(bytes(base[TAIL_OFFSET:]) == original_records[index][TAIL_OFFSET:], f"payload record {index} preserves seven-byte stock raw tail", checks)
        candidate_records[index] = bytes(base)
        payload_crc = zlib.crc32(bytes(base[:VOICE_SIZE]), payload_crc)

    manifest = bytearray(original_records[manifest_index])
    manifest[:VOICE_SIZE] = b"\x00" * VOICE_SIZE
    magic = b"S1C6RR17"
    manifest[0:8] = magic
    manifest[8] = 1  # format version
    manifest[9] = PREFERRED_PAYLOAD_BASE_INDEX
    manifest[10] = SLOTS
    manifest[11] = MAP_OFFSET
    manifest[12:16] = struct.pack("<I", 1)  # generation
    manifest[16:20] = struct.pack("<I", payload_crc & 0xFFFFFFFF)
    map_crc = zlib.crc32(bytes(notes)) & 0xFFFFFFFF
    manifest[20:24] = struct.pack("<I", map_crc)
    manifest[MAP_OFFSET:MAP_OFFSET + SLOTS] = bytes(notes)
    header_crc = zlib.crc32(bytes(manifest[:MAP_OFFSET + SLOTS])) & 0xFFFFFFFF
    manifest[24:28] = struct.pack("<I", header_crc)
    req(bytes(manifest[TAIL_OFFSET:]) == original_records[manifest_index][TAIL_OFFSET:], "manifest record preserves seven-byte stock raw tail", checks)
    req(manifest[MAP_OFFSET:MAP_OFFSET + SLOTS] == bytes(notes), "manifest/map record stores all 16 Playback Notes", checks)
    candidate_records[manifest_index] = bytes(manifest)

    # Simulate the direct mapped fallback the selector would use if a hook fit.
    restore_rows = []
    for slot, index in enumerate(payload_indices):
        restored_voice = candidate_records[index][:VOICE_SIZE]
        restored_note = candidate_records[manifest_index][MAP_OFFSET + slot]
        req(restored_voice == voices[slot], f"slot {slot} direct raw prefix restores normalized S1C5 voice", checks)
        req(restored_note == notes[slot], f"slot {slot} manifest restores Playback Note", checks)
        restore_rows.append({
            "slot": slot,
            "payload_record_index": index,
            "payload_dump_offset": hx(RAW_TABLE_DUMP_OFFSET + index * RAW_RECORD_SIZE, 6),
            "payload_mapped_offset": hx(RAW_TABLE_MAPPED_OFFSET + index * RAW_RECORD_SIZE),
            "payload_sha256": sha(candidate_records[index]),
            "tail_sha256": sha(candidate_records[index][TAIL_OFFSET:]),
            "restored_voice_sha256": sha(restored_voice),
            "playback_note": restored_note,
        })

    cand_blob = b"".join(candidate_records[idx] for idx in reserved_indices)
    orig_blob = b"".join(original_records[idx] for idx in reserved_indices)
    (out / "candidate-reserved-records.bin").write_bytes(cand_blob)
    (rollback / "official-original-reserved-records.bin").write_bytes(orig_blob)
    for idx in reserved_indices:
        (out / f"record-{idx:03d}-candidate.bin").write_bytes(candidate_records[idx])
        (rollback / f"record-{idx:03d}-official.bin").write_bytes(original_records[idx])

    rollback_manifest = {
        "format": "smk37-v15-s1c6-raw-record-persistence.rollback-v1",
        "offline_only": True,
        "device_accessed": False,
        "flash_performed": False,
        "reserved_record_indices": reserved_indices,
        "official_records_blob_sha256": sha(orig_blob),
        "candidate_records_blob_sha256": sha(cand_blob),
        "record_size": RAW_RECORD_SIZE,
        "rollback_restores_original_reserved_records": True,
        "files": [
            {"record_index": idx, "file": f"record-{idx:03d}-official.bin", "sha256": sha(original_records[idx])}
            for idx in reserved_indices
        ],
    }
    write_json(rollback / "manifest.json", rollback_manifest)

    return {
        "preferred_layout": {
            "name": "C32 manifest plus D17..D32 payload records",
            "manifest_record_index": manifest_index,
            "payload_base_record_index": PREFERRED_PAYLOAD_BASE_INDEX,
            "payload_record_indices": payload_indices,
            "reserved_record_indices": reserved_indices,
            "reservation_policy": "These 17 allocated stock raw records become S1C6-owned and must not be used for stock patch storage while the candidate is active.",
            "direct_mapped_source_formula": "payload = *(g+0x164) + 0x4000 + (112+slot)*0xa3; playback = *(g+0x164) + 0x4000 + 95*0xa3 + 0x20 + slot",
            "payload_base_mapped_offset": hx(RAW_TABLE_MAPPED_OFFSET + PREFERRED_PAYLOAD_BASE_INDEX * RAW_RECORD_SIZE),
            "manifest_map_mapped_offset": hx(RAW_TABLE_MAPPED_OFFSET + manifest_index * RAW_RECORD_SIZE + MAP_OFFSET),
        },
        "manifest_format": {
            "record_prefix_size": VOICE_SIZE,
            "magic": "S1C6RR17",
            "version_offset": 8,
            "payload_base_offset": 9,
            "count_offset": 10,
            "map_offset_offset": 11,
            "generation_offset": 12,
            "payload_crc32_offset": 16,
            "map_crc32_offset": 20,
            "header_crc32_offset": 24,
            "playback_note_map_offset": MAP_OFFSET,
            "playback_note_count": SLOTS,
            "tail_policy": "raw bytes 0x9c..0xa2 are preserved from stock records",
        },
        "records": restore_rows,
        "candidate_records_blob": {"file": "records/candidate-reserved-records.bin", "sha256": sha(cand_blob), "size": len(cand_blob)},
        "rollback": {"manifest": "rollback/reserved-stock-raw-records/manifest.json", "official_records_blob_sha256": sha(orig_blob)},
        "crc32": {"payload_crc32": hx(payload_crc & 0xFFFFFFFF, 8), "map_crc32": hx(map_crc, 8), "manifest_header_crc32": hx(header_crc, 8)},
    }


def fit_analysis(checks: list[str]) -> dict[str, Any]:
    code_ev = json.loads(S1C5_CODE.read_text(encoding="utf-8"))
    req(code_ev["owned_window"]["bytes"] == 278, "owned executable window remains exact 278 bytes", checks)
    req(code_ev["selector"]["bytes"] == 88, "current S1C5 selector is exact 88 bytes", checks)
    req(code_ev["producer"]["bytes"] == 188, "current S1C5 producer is exact 188 bytes", checks)
    req(code_ev["producer"]["armed_last_publishes_map"] is True, "current WebMIDI producer publishes ARMED last", checks)
    spare = code_ev["owned_window"]["bytes"] - code_ev["selector"]["bytes"] - code_ev["producer"]["bytes"]
    req(spare == 2, "preserving exact S1C5 selector and producer leaves only 2 bytes", checks)

    # Conservative lower bound for adding only the preferred direct-mapped fallback.
    # It excludes manifest magic/CRC validation, rollback/A-B generation choice,
    # state publication, and any new branch plumbing needed to integrate the path.
    primitive = [
        ("load global g pointer 0x01c33260", 6),
        ("ldw mapped raw base from [g+0x164]", 4),
        ("copy slot index for raw stride", 2),
        ("mul slot by raw stride 0xa3", 4),
        ("add mapped base to payload offset", 2),
        ("add preferred payload-base mapped offset 0x8750", 4),
        ("copy source pointer for manifest-map load", 2),
        ("add preferred manifest-map mapped offset 0x7c9d", 4),
        ("add slot to manifest-map pointer", 2),
        ("lb.z Playback Note from manifest map", 2),
    ]
    primitive_bytes = sum(x[1] for x in primitive)
    req(primitive_bytes == 32, "direct mapped raw-record fallback primitive lower bound is 32 bytes", checks)
    req(primitive_bytes > spare, "direct mapped fallback cannot fit while preserving exact S1C5 selector/producer", checks)

    selector_budget_with_producer = code_ev["owned_window"]["bytes"] - code_ev["producer"]["bytes"]
    req(selector_budget_with_producer == 90, "producer-preserving selector budget is 90 bytes", checks)
    current_selector = code_ev["selector"]["bytes"]
    raw_selector_lower_bound = current_selector + primitive_bytes
    req(raw_selector_lower_bound > selector_budget_with_producer,
        "volatile ARMED selector plus minimal raw fallback exceeds producer-preserving budget", checks)

    reclaimed_if_reset_removed = 42  # 0x0201e228..0x0201e252 from exact decode.
    req(reclaimed_if_reset_removed >= primitive_bytes, "removing reset wrapper would free enough bytes only by breaking current WebMIDI reset contract", checks)

    hooks = [
        {"address": "0x02005f9c", "classification": "revoked pre-USB storage-init loader callsite", "decision": "BLOCK"},
        {"address": "0x02005fa4", "classification": "post-storage but still pre-return boot initializer call", "decision": "BLOCK: no live proof and no wrapper placement"},
        {"address": "0x0201e46c/0x0201e4a0", "classification": "post-product SysEx reloads", "decision": "NOT autonomous across power cycle"},
        {"address": "0x0202422e", "classification": "UI bank/preset reload", "decision": "NOT every boot and mutates UI-selected patch state"},
    ]
    return {
        "decision": "BLOCK_FIRMWARE_FIT",
        "owned_window": code_ev["owned_window"],
        "preserve_exact_current": {
            "selector_bytes": current_selector,
            "producer_bytes": code_ev["producer"]["bytes"],
            "tail_spare_bytes": spare,
            "webmidi_producer_sha256": code_ev["producer"]["sha256"],
            "volatile_armed_path_sha256": code_ev["selector"]["sha256"],
        },
        "direct_mapped_fallback_lower_bound": {
            "bytes": primitive_bytes,
            "instructions": [{"purpose": p, "min_bytes": b} for p, b in primitive],
            "exclusions": [
                "manifest magic/version/count/CRC validation",
                "A/B or interrupted-update generation choice",
                "branch integration from state!=ARMED into fallback and back to metadata return",
                "destination byte 0x9b repair if using in-record note instead of manifest-map note",
            ],
        },
        "producer_preserving_selector_budget": selector_budget_with_producer,
        "volatile_armed_plus_raw_lower_bound": raw_selector_lower_bound,
        "rejected_optimization": {
            "remove_reset_wrapper_bytes": reclaimed_if_reset_removed,
            "reason": "The 0x0201e228 reset wrapper is the exact current direct WebMIDI entry and reset-before-first-packet behavior. Removing it does not preserve the requested producer.",
        },
        "alternate_hooks": hooks,
    }


def render_report(evidence: dict[str, Any]) -> str:
    layout = evidence["persistent_records"]["preferred_layout"]
    fit = evidence["fit_analysis"]
    rows = "\n".join(
        f"| {r['slot']} | {r['payload_record_index']} | `{r['payload_mapped_offset']}` | {r['playback_note']} | `{r['restored_voice_sha256']}` |"
        for r in evidence["persistent_records"]["records"]
    )
    primitive_rows = "\n".join(
        f"| {i['purpose']} | {i['min_bytes']} |"
        for i in fit["direct_mapped_fallback_lower_bound"]["instructions"]
    )
    hook_rows = "\n".join(
        f"| `{h['address']}` | {h['classification']} | {h['decision']} |"
        for h in fit["alternate_hooks"]
    )
    return f"""# S1C6 raw-record persistence successor candidate

Date: 2026-08-04 UTC. Scope is deterministic offline analysis and raw-record/rollback artifact generation only. No device, MIDI transport, flash, OTA, or reset action is performed.

## Decision

**DATA/ROLLBACK PASS, firmware hook BLOCK.**

The current S1C5 16 voices plus Playback Notes can be represented in 17 reserved stock raw records: 16 payload records plus one manifest/map record. The preferred reservation is **{layout['name']}**. The direct mapped read formula is:

```text
{layout['direct_mapped_source_formula']}
```

The generated records validate that a direct raw-prefix fallback would restore every normalized S1C5 voice and every Playback Note without using packed-record unpacking. The seven-byte raw tails are preserved from the stock records.

No installable firmware package is emitted because the executable fit gates fail. Preserving the exact volatile RAM ARMED selector path and exact WebMIDI producer leaves only **2 bytes** in the owned window, while the most optimistic direct-mapped raw fallback primitive alone needs **32 bytes** before manifest validation or branch integration. Replacing the selector while preserving the producer gives 90 bytes, but the current ARMED selector is already 88 bytes, so the lower bound is 120 bytes.

## Persistent raw-record candidate

| Slot | Payload record | Mapped payload offset from `*(g+0x164)` | Playback Note | Restored normalized voice SHA-256 |
|---:|---:|---:|---:|---|
{rows}

Manifest/map record index: **{layout['manifest_record_index']}**. Manifest map offset: `{layout['manifest_map_mapped_offset']}`.

Artifacts:

- `records/candidate-reserved-records.bin`: concatenated 17-record candidate image.
- `records/record-NNN-candidate.bin`: per-record candidate images.
- `rollback/reserved-stock-raw-records/manifest.json`: exact original reserved-record rollback manifest.
- `rollback/reserved-stock-raw-records/record-NNN-official.bin`: per-record stock rollback images.

## Fit lower bound

| Required primitive for raw fallback | Minimum bytes |
|---|---:|
{primitive_rows}

Total primitive lower bound: **{fit['direct_mapped_fallback_lower_bound']['bytes']} bytes**.

Excluded from that lower bound: manifest magic/version/count/CRC validation, A/B generation choice, interrupted-update behavior, branch integration, and destination byte repair for layouts that place Playback Note in `raw[0x9b]` instead of the manifest map.

## Hook review

| Hook/callsite | Classification | Decision |
|---|---|---|
{hook_rows}

Removing the exact reset wrapper would reclaim enough bytes on paper, but it is rejected because `0x0201e228` is the current direct WebMIDI reset entry. That would not preserve the requested producer.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C6-raw-record-persistence/build_s1c6_raw_record_persistence.py
python3 baselines/v15/analysis/flash-candidates/S1C6-raw-record-persistence/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C6-raw-record-persistence && shasum -a 256 -c SHA256SUMS)
```

Expected result: `S1C6 raw-record persistence offline validation PASS; firmware fit BLOCK`.
"""


def build() -> dict[str, Any]:
    checks: list[str] = []
    req(shaf(S1C5 / "app.bin") == EXPECTED_SHA256["s1c5_app"], "exact current S1C5 app hash", checks)
    req(shaf(S1C5_CODE) == EXPECTED_SHA256["s1c5_code"], "exact current S1C5 selector/producer evidence hash", checks)
    voices, notes, packet_rows = load_packets(checks)
    persistent = build_records(voices, notes, checks)
    fit = fit_analysis(checks)
    evidence = {
        "format": "smk37-v15-s1c6-raw-record-persistence.offline-candidate-v1",
        "decision": "DATA_ROLLBACK_PASS__FIRMWARE_FIT_BLOCK",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False, "fwsc_emitted": False},
        "basis": {
            "s1c5_candidate": str(S1C5.relative_to(ROOT)),
            "s1c5_app_sha256": EXPECTED_SHA256["s1c5_app"],
            "clean_dump_sha256": EXPECTED_SHA256["clean_dump"],
            "storage_report": str(STORAGE_REPORT.relative_to(ROOT)),
            "restore_report": str(RESTORE_REPORT.relative_to(ROOT)),
        },
        "current_s1c5_packets": packet_rows,
        "persistent_records": persistent,
        "fit_analysis": fit,
        "validation": checks,
    }
    write_json(HERE / "evidence.json", evidence)
    (HERE / "report.md").write_text(render_report(evidence), encoding="utf-8")
    (HERE / "README.md").write_text("# S1C6 raw-record persistence successor\n\nOffline deterministic candidate. Data and rollback records pass, but firmware hook fit is blocked while preserving the exact S1C5 volatile ARMED selector and WebMIDI producer. See `report.md`.\n", encoding="utf-8")
    (HERE / "validation.txt").write_text("S1C6 raw-record persistence offline validation PASS; firmware fit BLOCK\n" + "\n".join(checks) + "\n", encoding="utf-8")
    write_sha_inventory()
    return evidence


def write_sha_inventory() -> None:
    names = ["build_s1c6_raw_record_persistence.py", "validate.py", "README.md", "report.md", "evidence.json", "validation.txt"]
    files = [HERE / n for n in names if (HERE / n).exists()]
    for base in ["records", "rollback"]:
        root = HERE / base
        if root.exists():
            files.extend(p for p in sorted(root.rglob("*")) if p.is_file())
    (HERE / "SHA256SUMS").write_text("\n".join(f"{shaf(p)}  {p.relative_to(HERE)}" for p in files) + "\n", encoding="utf-8")


def validate_existing() -> None:
    checks: list[str] = []
    evidence = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))
    req(evidence["decision"] == "DATA_ROLLBACK_PASS__FIRMWARE_FIT_BLOCK", "evidence decision is expected PASS/BLOCK split", checks)
    req(evidence["scope"]["fwsc_emitted"] is False and evidence["scope"]["device_accessed"] is False, "offline-only scope retained", checks)
    blob = (HERE / evidence["persistent_records"]["candidate_records_blob"]["file"]).read_bytes()
    req(sha(blob) == evidence["persistent_records"]["candidate_records_blob"]["sha256"], "candidate record blob hash", checks)
    req(len(blob) == 17 * RAW_RECORD_SIZE, "candidate record blob is exactly 17 raw records", checks)
    rollback_manifest = json.loads((HERE / evidence["persistent_records"]["rollback"]["manifest"]).read_text(encoding="utf-8"))
    req(rollback_manifest["rollback_restores_original_reserved_records"] is True, "rollback manifest is affirmative", checks)
    req(evidence["fit_analysis"]["direct_mapped_fallback_lower_bound"]["bytes"] == 32, "raw fallback lower bound unchanged", checks)
    req(evidence["fit_analysis"]["preserve_exact_current"]["tail_spare_bytes"] == 2, "exact S1C5 preserved spare remains 2 bytes", checks)
    for line in (HERE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, rel = line.split("  ", 1)
        req(shaf(HERE / rel) == digest, f"SHA256SUMS entry {rel}", checks)
    print("S1C6 raw-record persistence offline validation PASS; firmware fit BLOCK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate-existing", action="store_true")
    args = parser.parse_args()
    if args.validate_existing:
        validate_existing()
    else:
        build()
        validate_existing()


if __name__ == "__main__":
    main()
