#!/usr/bin/env python3
"""Read-only validator for the official-v15/H2 patch-set data-model report.

The validator hashes and inspects existing evidence only. It never builds firmware,
invokes an uploader, opens USB, or accesses a device. --write-output writes only
validation.txt beside this script.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EVIDENCE = HERE / "evidence.json"
REPORT = HERE / "report.md"
OUTPUT = HERE / "validation.txt"
RUNTIME_BASE = 0x02000000


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL\t{message}")


def app_bytes(data: bytes, address: int, size: int) -> bytes:
    offset = address - RUNTIME_BASE
    require(0 <= offset <= len(data) - size, f"address outside app: 0x{address:08x}")
    return data[offset:offset + size]


def listing_rows(path: Path, addresses: set[int]) -> dict[int, str]:
    found: dict[int, str] = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                address = int(line.split("\t", 1)[0], 16)
            except (ValueError, IndexError):
                continue
            if address in addresses:
                found[address] = line.rstrip("\n")
    return found


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode_u16_7bit(value: int) -> bytes:
    require(0 <= value <= 0xFFFF, "u16 seven-bit encoding input out of range")
    return bytes((value & 0x7F, (value >> 7) & 0x7F, (value >> 14) & 0x03))


def build_dev_packet(command: int, set_id: int, body: bytes) -> bytes:
    require(0 <= command < 0x80, "command is not seven-bit")
    require(1 <= set_id < 0x80, "set_id is not 1..127")
    require(len(body) < 0x4000, "body too large for 14-bit length")
    require(all(value < 0x80 for value in body), "body contains non-seven-bit data")
    length = bytes((len(body) & 0x7F, (len(body) >> 7) & 0x7F))
    protected = b"SMK" + bytes((0x0F, 0x01, command, set_id, 0x00)) + length + body
    crc = encode_u16_7bit(crc16_ccitt_false(protected))
    return bytes((0xF0, 0x7D)) + protected + crc + bytes((0xF7,))


def validate() -> str:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    report = REPORT.read_text(encoding="utf-8")
    require(evidence["format"] == "smk37-v15-h2-per-note-patch-set-data-model-v1", "evidence format")
    require(evidence["decision"] == {
        "data_model": "PASS",
        "firmware_candidate": "BLOCK",
        "reason": evidence["decision"]["reason"],
    }, "decision fields")
    require(not any((
        evidence["scope"]["v12_assumptions"],
        evidence["scope"]["firmware_candidate_created"],
        evidence["scope"]["flash_performed"],
        evidence["scope"]["device_accessed"],
    )), "scope must remain read-only, no-v12, and no-candidate")

    inputs = {item["id"]: item for item in evidence["inputs"]}
    require(len(inputs) == len(evidence["inputs"]) == 18, "input inventory count/uniqueness")
    for item in evidence["inputs"]:
        path = ROOT / item["path"]
        require(path.is_file(), f"missing input {item['path']}")
        require(sha256(path) == item["sha256"], f"SHA-256 mismatch {item['path']}")

    official = (ROOT / inputs["official_app"]["path"]).read_bytes()
    h2 = (ROOT / inputs["h2_app"]["path"]).read_bytes()
    expected_official = {
        0x0201C5FE: bytes.fromhex("79e1f030"),
        0x0201C616: bytes.fromhex("82fd7b06"),
        0x0201C62E: bytes.fromhex("1d41"),
        0x0201C63E: bytes.fromhex("80ff8ac60200"),
        0x0201C648: bytes.fromhex("8d40"),
        0x0201C652: bytes.fromhex("82fd5d06"),
        0x0201C66A: bytes.fromhex("1d42"),
        0x0201C670: bytes.fromhex("1e41"),
        0x0201C67C: bytes.fromhex("80ff4cc60200"),
        0x0201C686: bytes.fromhex("8e40"),
    }
    for address, expected in expected_official.items():
        require(app_bytes(official, address, len(expected)) == expected, f"official bytes 0x{address:08x}")
    expected_h2 = {
        0x0201C63E: bytes.fromhex("80fffa1a0000"),
        0x0201C67C: bytes.fromhex("80ffee1a0000"),
        0x0201E148: bytes.fromhex("c4ffbc65c401"),
        0x0201E156: bytes.fromhex("c1ff2065c401"),
        0x0201E188: bytes.fromhex("c1ff2065c401"),
    }
    for address, expected in expected_h2.items():
        require(app_bytes(h2, address, len(expected)) == expected, f"H2 bytes 0x{address:08x}")

    qpath = ROOT / inputs["quarkslab_listing"]["path"]
    kpath = ROOT / inputs["kagaimiq_listing"]["path"]
    addresses = set(expected_official)
    qrows = listing_rows(qpath, addresses)
    krows = listing_rows(kpath, {0x0201C62E, 0x0201C670})
    require(set(qrows) == addresses, "Quarkslab dispatcher row coverage")
    require("and r9,r3,#0xffffff0f" in qrows[0x0201C5FE], "channel nibble row")
    require("r5,[r1 + 0x1]" in qrows[0x0201C62E], "Note Off note load row")
    require("r6,[r1 + 0x1]" in qrows[0x0201C670], "Note On note load row")
    require("r5,[r1 + 0x1]" in krows[0x0201C62E], "independent Note Off note row")
    require("r6,[r1 + 0x1]" in krows[0x0201C670], "independent Note On note row")

    manifest = json.loads((ROOT / inputs["h2_manifest"]["path"]).read_text(encoding="utf-8"))
    policy = manifest["h2_policy"]
    require(policy["producer_owned_destination"] == "0x01c46520..0x01c465bc", "H2 owned destination")
    require(policy["valid"] == "0x01c465bc", "H2 valid address")
    require(policy["lock"] == "0x01c465bd", "H2 lock address")
    require(policy["copy_size"] == 156, "H2 copy size")
    require(policy["stock_fallback_r0_restore"] is True, "H2 fallback r0 restore")
    require(policy["stock_fallback_preserves_original_r1_r2"] is True, "H2 fallback r1/r2")
    live = (ROOT / inputs["h2_live"]["path"]).read_text(encoding="utf-8")
    for marker in ("verdict: **H2 LIVE PASS**", "Ch10 Note Off: **normal**", "first-Pad reboot: **none**"):
        require(marker in live, f"H2 live marker {marker}")

    packet = (ROOT / inputs["live_runtime_packet"]["path"]).read_bytes()
    require(len(packet) == 163, "official runtime packet total length")
    require(packet[:6] == bytes.fromhex("f0430000011b"), "official runtime packet header")
    require(packet[-1] == 0xF7, "official runtime packet terminator")
    payload = packet[6:-1]
    require(len(payload) == 156, "official runtime payload length")
    require(max(payload) == 114 and all(value < 0x80 for value in payload), "official runtime payload seven-bit bound")

    design = evidence["design"]
    counts = design["slot_counts"]
    require(counts["midi_note_keys"] == 128, "128 note keys")
    require(counts["resident_patch_slots"] == 16, "16 resident patch slots")
    require(counts["runtime_bytes_per_slot"] == 156, "156 bytes per slot")
    require(counts["payload_bytes_total"] == 16 * 156 == 2496, "payload byte arithmetic")

    ram = design["ram_layout"]
    base = int(ram["base"], 16)
    end = int(ram["end_exclusive"], 16)
    slot_end = int(ram["slot_region"]["end_exclusive"], 16)
    header_start = int(ram["header_region"]["start"], 16)
    heap_end = int(evidence["proved_facts"]["official_memory"]["heap_end"], 16)
    h2_heap_begin = int(evidence["proved_facts"]["official_memory"]["h2_heap_begin"], 16)
    require(end - base == ram["size"] == 0xA90, "RAM total size")
    require(slot_end - base == 16 * 0xA0 == 0xA00, "slot region arithmetic")
    require(header_start == slot_end and end - header_start == 0x90, "header placement")
    require(base + 0x9C == int(evidence["proved_facts"]["h2"]["valid"], 16), "slot0 H2 valid compatibility")
    require(base + 0x9D == int(evidence["proved_facts"]["h2"]["lock"], 16), "slot0 H2 lock compatibility")
    require(end == int(ram["proposed_heap_begin"], 16), "new heap begin")
    require(heap_end - end == ram["remaining_heap_arena_size"] == 0x38D80, "remaining heap arithmetic")
    require(end - h2_heap_begin == ram["additional_reservation_beyond_h2"] == 0x9F0, "additional H2 reservation")
    require(16 * 156 + 128 + 16 + 4 == ram["functional_floor"] == 0xA54, "functional floor")
    max_source = base + 15 * 0xA0
    require(max_source == int(design["bounds"]["maximum_slot_source"], 16), "maximum slot source")
    require(max_source + 0x9C == int(design["bounds"]["maximum_slot_voice_end_exclusive"], 16), "maximum voice end")
    require(max_source + 0x9C <= slot_end, "maximum slot copy stays in slot region")

    midi = evidence["proved_facts"]["midi_and_pads"]
    require(midi["safe_note_domain"] == [0, 127], "MIDI note domain")
    require(midi["observed_physical_message_hex"] == "992466", "physical Pad observation")
    require(midi["observed_note_decimal"] == 36 and midi["known_physical_pad_note_count"] == 1, "known Pad mapping bound")
    require(midi["all_16_pad_notes_enumerated"] is False, "Pad enumeration remains open")
    require(midi["contiguous_36_to_51_assumption_allowed"] is False, "no contiguous Pad assumption")

    protocol = design["update_protocol"]
    require(protocol["fixed_overhead_bytes_excluding_body"] == 16, "packet fixed overhead")
    begin = build_dev_packet(0x01, 1, bytes((16, 0)))
    put_slot = build_dev_packet(0x02, 1, bytes((0,)) + payload)
    put_map = build_dev_packet(0x03, 1, bytes((0x7F,)) * 128)
    canonical = bytes((0x7F,)) * 128 + payload * 16
    commit = build_dev_packet(0x04, 1, encode_u16_7bit(crc16_ccitt_false(canonical)))
    built = {"BEGIN": begin, "PUT_SLOT": put_slot, "PUT_MAP": put_map, "COMMIT": commit}
    commands = {item["name"]: item for item in protocol["commands"]}
    for name, packet_bytes in built.items():
        require(len(packet_bytes) == commands[name]["total_length"], f"{name} packet length")
        require(packet_bytes[:7] == bytes.fromhex(protocol["prefix_hex"]), f"{name} prefix")
        require(packet_bytes[-1] == 0xF7, f"{name} terminator")
        require(all(value < 0x80 for value in packet_bytes[1:-1]), f"{name} seven-bit bytes")
    require(len(put_slot) == 173 and len(put_map) == 144, "principal update packet sizes")

    required_report_markers = (
        "**128 MIDI note keys**",
        "**16 resident patch payload slots**",
        "Only Note 36",
        "0x01c46520..0x01c46fb0",
        "state == ARMED",
        "fill once and immutable after commit",
        "not proof of 16-note audio polyphony",
        "Data-model design: PASS. Firmware implementation: BLOCKED",
        "This analysis created no firmware candidate",
    )
    for marker in required_report_markers:
        require(marker in report, f"report marker {marker}")

    blockers = {item["id"]: item["status"] for item in evidence["implementation_gates"]}
    require(blockers == {
        "pad-enumeration": "BLOCK",
        "note-register-abi": "BLOCK",
        "heap-headroom": "BLOCK",
        "code-placement": "BLOCK",
        "sysex-ingress": "BLOCK",
        "memory-ordering": "BLOCK",
        "polyphony-stress": "BLOCK",
        "persistence": "OUT_OF_SCOPE",
    }, "implementation gate set")

    lines = [
        "PASS\tscope\tofficial-v15 static evidence plus recorded live-proven H2; no v12; no candidate; no flash; no device",
        f"PASS\tinput-sha256\t{len(inputs)} exact inputs",
        "PASS\tdispatcher\tCh10=r9==9; Note Off note candidate r5; Note On note candidate r6; copy=0x9c",
        "PASS\th2-contract\tvoice=0x01c46520 valid=0x01c465bc lock=0x01c465bd corrected fallback",
        "PASS\truntime-packet\t163 bytes; 156-byte seven-bit payload; SHA-256 6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27",
        "PASS\tslot-counts\t128 MIDI note keys; 16 resident patch slots; one proven physical note mapping",
        "PASS\tram-layout\t0x01c46520..0x01c46fb0 size 0x0a90; slot0 H2-compatible; heap arithmetic closed",
        "PASS\tlookup\tO(1) direct map; explicit note/slot/valid bounds; stock fallback",
        "PASS\tconcurrency\tnonblocking producer lock; ARMED-last; immutable after commit; consumers do not lock",
        "PASS\tpacket-model\tBEGIN=18 PUT_SLOT=173 PUT_MAP=144 COMMIT=19; seven-bit envelope and CRC-16",
        "PASS\tpolyphony-boundary\t16 indexed records are not treated as 16-note polyphony proof",
        "PASS\tdecision\tdata model PASS; firmware candidate BLOCKED by eight explicit gates",
        "OVERALL\tPASS",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-output", action="store_true", help="write deterministic validation.txt in this directory")
    parser.add_argument("--check-output", action="store_true", help="compare deterministic output with validation.txt")
    args = parser.parse_args()
    output = validate()
    if args.write_output:
        OUTPUT.write_text(output, encoding="utf-8")
    if args.check_output:
        require(OUTPUT.is_file(), "validation.txt missing")
        require(OUTPUT.read_text(encoding="utf-8") == output, "validation.txt is stale")
    print(output, end="")


if __name__ == "__main__":
    main()
