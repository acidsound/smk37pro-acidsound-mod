#!/usr/bin/env python3
"""Read-only validator for the offline S1-C3 Bank D 1..16 packet set.

This script does not open MIDI/USB devices, build firmware/FWSC, flash, reset, or
send packets. It validates only committed files in this directory.
"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
SLOT_COUNT = 16
FIRST_NOTE = 36
BANK = 4
BANK_LETTER = "D"
RUNTIME_SIZE = 156
PACKET_SIZE = 163
SLOT_STRIDE = 0xA0
UNMAPPED = 0xFF
EXPECTED_PAD_NOTES = [40,41,42,43,48,49,50,51,36,37,38,39,44,45,46,47]
EXPECTED_PAD_SLOTS = [4,5,6,7,12,13,14,15,0,1,2,3,8,9,10,11]
EXPECTED_SLOT_TO_PAD = [9,10,11,12,1,2,3,4,13,14,15,16,5,6,7,8]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_path(path: Path) -> str:
    return sha(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def read_json(name: str) -> dict:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def validate_sha256sums() -> None:
    recorded = {}
    for line in (HERE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        recorded[rel] = digest
    actual = {}
    for path in sorted(p for p in HERE.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        rel = path.relative_to(HERE).as_posix()
        actual[rel] = sha_path(path)
    require(recorded == actual, "SHA256SUMS matches every artifact recursively")


def usb_midi_facts(sysex_len: int) -> tuple[int, int, str]:
    events = (sysex_len + 2) // 3
    remainder = sysex_len % 3
    if remainder == 0:
        final_cin = 0x07
    elif remainder == 1:
        final_cin = 0x05
    else:
        final_cin = 0x06
    return events, events * 4, f"{final_cin:02x}f70000"


def main() -> int:
    manifest = read_json("manifest.json")
    packet_set = read_json("packet-set-manifest.json")
    sender = read_json("sender-manifest.json")
    physical = read_json("physical-pad-permutation.json")
    config = read_json("config.json")

    for scope in (packet_set["scope"], sender["scope"]):
        require(scope["offline_only"] is True, "offline-only scope")
        for key in ("send_enabled", "device_accessed", "midi_transport_opened", "firmware_built", "fwsc_built", "flash_performed", "reset_performed"):
            require(scope[key] is False, f"blocked scope {key}")
    for verdict in (packet_set["verdict"], sender["verdict"]):
        require(verdict["offline_packet_set"] == "PASS", "offline PASS verdict")
        require(verdict["device_access_or_live_send"] == "BLOCK", "live send BLOCK verdict")
        require(verdict["firmware_or_flash"] == "BLOCK", "firmware BLOCK verdict")

    slots = manifest["slots"]
    packets = packet_set["packets"]
    sender_packets = sender["packets_in_order"]
    require(len(slots) == len(packets) == len(sender_packets) == SLOT_COUNT, "16 slots/packets")
    require(config["slots"] and len(config["slots"]) == SLOT_COUNT, "16 config slots")

    stream = bytearray()
    runtime_slots = (HERE / manifest["runtime_image"]["file"]).read_bytes()
    require(len(runtime_slots) == SLOT_COUNT * SLOT_STRIDE, "runtime-slots size")
    note_map = (HERE / manifest["note_map"]["file"]).read_bytes()
    require(len(note_map) == 128, "note-map size")

    for note in range(128):
        expected = note - FIRST_NOTE if FIRST_NOTE <= note < FIRST_NOTE + SLOT_COUNT else UNMAPPED
        require(note_map[note] == expected, f"note-map[{note}]")

    for index, (slot, pkt, spkt, cfg) in enumerate(zip(slots, packets, sender_packets, config["slots"])):
        note = FIRST_NOTE + index
        patch = index + 1
        require(slot["slot"] == pkt["slot"] == spkt["slot"] == index, f"slot {index}")
        require(slot["note"] == pkt["note"] == spkt["note"] == cfg["note"] == note, f"note {index}")
        require(slot["bank"] == pkt["bank"] == spkt["bank"] == cfg["bank"] == BANK, f"bank {index}")
        require(slot["bank_letter"] == pkt["bank_letter"] == spkt["bank_letter"] == BANK_LETTER, f"bank letter {index}")
        require(slot["patch"] == pkt["patch_1_based"] == spkt["patch_1_based"] == cfg["patch"] == patch, f"patch {index}")
        require(slot["name"] == pkt["name"] == spkt["name"] == cfg["expected_name"], f"name {index}")
        require(spkt["order"] == pkt["order"] == index + 1, f"order {index}")

        packet_path = HERE / slot["packet_file"]
        packet = packet_path.read_bytes()
        require(len(packet) == PACKET_SIZE, f"packet length {index}")
        require(packet.startswith(HEADER) and packet.endswith(TERM), f"packet framing {index}")
        runtime = packet[len(HEADER):-1]
        require(len(runtime) == RUNTIME_SIZE, f"runtime payload length {index}")
        require(sha(packet) == slot["packet_sha256"] == pkt["packet_sha256"] == spkt["packet_sha256"], f"packet hash {index}")
        require(sha(runtime) == slot["runtime_sha256"] == pkt["runtime_sha256"] == spkt["runtime_sha256"], f"runtime hash {index}")

        runtime_path = HERE / pkt["runtime_object_file"]
        require(runtime_path.read_bytes() == runtime, f"runtime object file {index}")
        start = index * SLOT_STRIDE
        require(runtime_slots[start:start + RUNTIME_SIZE] == runtime, f"runtime-slots payload {index}")
        require(runtime_slots[start + RUNTIME_SIZE:start + SLOT_STRIDE] == bytes([1, 1, 0, 0]), f"runtime-slots metadata {index}")
        stream += packet

    stream_path = HERE / manifest["sequential_packet_stream"]["file"]
    require(stream_path.read_bytes() == bytes(stream), "sequential-product-packets exact concatenation")
    require(sha(stream) == manifest["sequential_packet_stream"]["sha256"] == packet_set["aggregate_files"]["sequential_product_packets_sha256"], "sequential stream hash")
    require(sha(runtime_slots) == manifest["runtime_image"]["sha256"] == packet_set["aggregate_files"]["runtime_slots_sha256"], "runtime-slots hash")
    require(sha(note_map) == manifest["note_map"]["sha256"] == packet_set["aggregate_files"]["note_map_sha256"], "note-map hash")

    events, usb_bytes, final_event = usb_midi_facts(PACKET_SIZE)
    wire = sender["wire_packet_contract"]
    require(events == wire["usb_midi_events_per_packet"] == 55, "USB-MIDI events")
    require(usb_bytes == wire["usb_midi_bytes_per_packet"] == 220, "USB-MIDI bytes")
    require(final_event == wire["usb_midi_final_event_hex"] == "05f70000", "USB-MIDI final event")

    require(physical["source_commit"] == "2a23cf5", "physical permutation source commit")
    require(physical["pad_1_to_16_note_sequence"] == EXPECTED_PAD_NOTES, "Pad 1..16 note sequence")
    require(physical["pad_1_to_16_note_ordered_slot_sequence"] == EXPECTED_PAD_SLOTS, "Pad 1..16 slot sequence")
    require(physical["slot_0_to_15_physical_pad_sequence"] == EXPECTED_SLOT_TO_PAD, "slot->physical Pad sequence")

    validate_sha256sums()
    print("PASS offline exact Bank D 1..16 packet set")
    print("PASS 16 runtime objects: 156 bytes each, hashes pinned")
    print("PASS 16 direct Yamaha product SysEx packets: 163 bytes each, order pinned")
    print("PASS note-ordered slots 0..15 -> notes 36..51 and physical Pad permutation from 2a23cf5")
    print("BLOCK device access, firmware/FWSC, flash/reset, MIDI transport, live send")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
