#!/usr/bin/env python3
"""Compile official-v15 factory voices into a 16-pad Ch10 patch set.

The user-facing bank and patch numbers are strictly 1-based:

- bank: 1..4 (A..D)
- patch: 1..32
- pad notes: any 16 distinct MIDI notes in 0..127

This is an offline host-side compiler. It does not modify firmware or access a
USB device. Every input full-flash dump is exact-SHA gated to the verified v15
baseline before any voice data is read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from build_v15_r01_hand_drum import DUMP_SHA256, DUMP_SIZE  # noqa: E402
from dx7_vmem import unpack_voice, voice_name  # noqa: E402

FORMAT = "smk37-v15-pad-patch-set-v1"
CATALOG_FORMAT = "smk37-v15-factory-voice-catalog-v1"
FACTORY_TABLE_OFFSET = 0xF4000
BANK_COUNT = 4
PATCHES_PER_BANK = 32
PACKED_VOICE_SIZE = 0x80
RUNTIME_VOICE_SIZE = 0x9C
SLOT_STRIDE = 0xA0
MIDI_NOTE_MIN = 0
MIDI_NOTE_MAX = 127
UNMAPPED_SLOT = 0xFF
PRODUCT_PACKET_HEADER = bytes.fromhex("f0430000011b")
PRODUCT_PACKET_SIZE = 163


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def load_dump(path: Path) -> bytes:
    data = path.read_bytes()
    require(len(data) == DUMP_SIZE, f"refusing dump size {len(data)}; expected {DUMP_SIZE}")
    require(sha256(data) == DUMP_SHA256, "refusing non-baseline official v15 full-flash dump")
    end = FACTORY_TABLE_OFFSET + BANK_COUNT * PATCHES_PER_BANK * PACKED_VOICE_SIZE
    require(end <= len(data), "factory voice table exceeds dump")
    return data


def packed_voice(dump: bytes, bank_1based: int, patch_1based: int) -> tuple[int, bytes]:
    require(1 <= bank_1based <= BANK_COUNT, f"bank must be 1..{BANK_COUNT}")
    require(1 <= patch_1based <= PATCHES_PER_BANK, f"patch must be 1..{PATCHES_PER_BANK}")
    index = (bank_1based - 1) * PATCHES_PER_BANK + (patch_1based - 1)
    offset = FACTORY_TABLE_OFFSET + index * PACKED_VOICE_SIZE
    data = dump[offset:offset + PACKED_VOICE_SIZE]
    require(len(data) == PACKED_VOICE_SIZE, "short packed factory voice")
    return offset, data


def decode_name(packed: bytes) -> str:
    return voice_name(packed)


def catalog(dump: bytes) -> dict[str, object]:
    voices: list[dict[str, object]] = []
    for bank in range(1, BANK_COUNT + 1):
        for patch in range(1, PATCHES_PER_BANK + 1):
            offset, packed = packed_voice(dump, bank, patch)
            runtime = unpack_voice(packed)
            require(len(runtime) == RUNTIME_VOICE_SIZE and runtime[-1] == 0x3F,
                    f"invalid runtime voice at bank {bank} patch {patch}")
            voices.append({
                "bank": bank,
                "bank_letter": chr(ord("A") + bank - 1),
                "patch": patch,
                "name": decode_name(packed),
                "packed_dump_offset": f"0x{offset:08x}",
                "packed_sha256": sha256(packed),
                "runtime_sha256": sha256(runtime),
            })
    return {
        "format": CATALOG_FORMAT,
        "source_dump_sha256": sha256(dump),
        "numbering": "bank and patch are 1-based; MIDI note is 0..127",
        "factory_table_offset": f"0x{FACTORY_TABLE_OFFSET:08x}",
        "voice_count": len(voices),
        "voices": voices,
    }


def load_config(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(value, dict), "config root must be an object")
    require(value.get("format") == FORMAT, f"config format must be {FORMAT}")
    slots = value.get("slots")
    require(isinstance(slots, list) and len(slots) == 16, "config must contain exactly 16 slots")
    notes: list[int] = []
    for index, slot in enumerate(slots):
        require(isinstance(slot, dict), f"slot {index} must be an object")
        note = slot.get("note")
        bank = slot.get("bank")
        patch = slot.get("patch")
        require(isinstance(note, int) and MIDI_NOTE_MIN <= note <= MIDI_NOTE_MAX,
                f"slot {index} note must be {MIDI_NOTE_MIN}..{MIDI_NOTE_MAX}")
        require(isinstance(bank, int) and 1 <= bank <= BANK_COUNT,
                f"slot {index} bank must be 1..{BANK_COUNT}")
        require(isinstance(patch, int) and 1 <= patch <= PATCHES_PER_BANK,
                f"slot {index} patch must be 1..{PATCHES_PER_BANK}")
        notes.append(note)
    require(len(set(notes)) == 16, "slots must contain 16 distinct MIDI notes")
    return value


def compile_set(dump: bytes, config: dict[str, object], output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    slots_in_config_order = config["slots"]
    runtime_image = bytearray()
    note_map = bytearray((UNMAPPED_SLOT,)) * 128
    packet_stream = bytearray()
    manifest_slots: list[dict[str, object]] = []

    for slot_index, slot in enumerate(slots_in_config_order):
        note = slot["note"]
        bank = slot["bank"]
        patch = slot["patch"]
        offset, packed = packed_voice(dump, bank, patch)
        runtime = unpack_voice(packed)
        require(len(runtime) == RUNTIME_VOICE_SIZE and runtime[-1] == 0x3F,
                f"invalid runtime voice for note {note}")
        name = decode_name(packed)
        expected_name = slot.get("expected_name")
        if expected_name is not None:
            require(expected_name == name,
                    f"note {note}: expected name {expected_name!r}, factory has {name!r}")

        packet = PRODUCT_PACKET_HEADER + runtime + b"\xF7"
        require(len(packet) == PRODUCT_PACKET_SIZE, "product packet size mismatch")
        packet_name = f"slot-{slot_index:02d}-note-{note:03d}-B{bank}-P{patch:02d}.syx"
        (output_dir / packet_name).write_bytes(packet)
        packet_stream += packet

        runtime_image += runtime
        runtime_image += bytes((1, 1, 0, 0))  # valid, generation, lock, reserved
        note_map[note] = slot_index
        require(len(runtime_image) == (slot_index + 1) * SLOT_STRIDE,
                "runtime slot stride mismatch")

        manifest_slots.append({
            "slot": slot_index,
            "note": note,
            "bank": bank,
            "bank_letter": chr(ord("A") + bank - 1),
            "patch": patch,
            "name": name,
            "packed_dump_offset": f"0x{offset:08x}",
            "packed_sha256": sha256(packed),
            "runtime_sha256": sha256(runtime),
            "packet_file": packet_name,
            "packet_size": len(packet),
            "packet_sha256": sha256(packet),
            "runtime_slot_offset": f"0x{slot_index * SLOT_STRIDE:04x}",
        })

    runtime_path = output_dir / "runtime-slots.bin"
    note_map_path = output_dir / "note-map.bin"
    stream_path = output_dir / "sequential-product-packets.syx"
    runtime_path.write_bytes(runtime_image)
    note_map_path.write_bytes(note_map)
    stream_path.write_bytes(packet_stream)
    require(len(runtime_image) == 16 * SLOT_STRIDE, "runtime image must be 0xa00 bytes")
    require(len(note_map) == 128, "note map must be 128 bytes")
    require(sum(value != UNMAPPED_SLOT for value in note_map) == 16,
            "note map must publish exactly 16 slots")
    require(len(packet_stream) == 16 * PRODUCT_PACKET_SIZE, "packet stream size mismatch")

    manifest = {
        "format": FORMAT,
        "artifact_scope": "offline host-side patch-set compilation only; no firmware or device access",
        "source_dump_sha256": sha256(dump),
        "set_name": config.get("set_name", "UNTITLED"),
        "numbering": {
            "bank": "1..4 (A..D)",
            "patch": "1..32",
            "midi_note": "0..127; exactly 16 distinct configured notes",
            "slot_index": "config order, 0..15; use this order for the 4x4 UI grid",
        },
        "layout": {
            "slot_count": 16,
            "runtime_voice_size": RUNTIME_VOICE_SIZE,
            "slot_stride": SLOT_STRIDE,
            "runtime_image_size": len(runtime_image),
            "note_map_size": len(note_map),
            "unmapped_note_value": UNMAPPED_SLOT,
            "metadata_per_slot": ["valid", "generation", "lock", "reserved"],
            "product_packet_size": PRODUCT_PACKET_SIZE,
            "sequential_packet_stream_size": len(packet_stream),
        },
        "runtime_image": {"file": runtime_path.name, "sha256": sha256(runtime_image)},
        "note_map": {"file": note_map_path.name, "sha256": sha256(note_map)},
        "sequential_packet_stream": {"file": stream_path.name, "sha256": sha256(packet_stream)},
        "slots": manifest_slots,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    files = sorted(path for path in output_dir.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (output_dir / "SHA256SUMS").write_text(
        "".join(f"{sha256(path.read_bytes())}  {path.name}\n" for path in files),
        encoding="utf-8",
    )
    return manifest


def write_catalog(dump: bytes, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog(dump), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    catalog_parser = subparsers.add_parser("catalog", help="write the 128-voice official v15 catalog")
    catalog_parser.add_argument("dump", type=Path)
    catalog_parser.add_argument("output", type=Path)

    build_parser = subparsers.add_parser("build", help="compile a 16-note patch-set config")
    build_parser.add_argument("dump", type=Path)
    build_parser.add_argument("config", type=Path)
    build_parser.add_argument("output_dir", type=Path)

    args = parser.parse_args()
    dump = load_dump(args.dump)
    if args.command == "catalog":
        write_catalog(dump, args.output)
        print(f"catalog PASS: 128 voices -> {args.output}")
        return 0

    config = load_config(args.config)
    manifest = compile_set(dump, config, args.output_dir)
    print(f"patch set PASS: {manifest['set_name']} -> {args.output_dir}")
    print(f"runtime image: {manifest['runtime_image']['sha256']}")
    print(f"packet stream: {manifest['sequential_packet_stream']['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
