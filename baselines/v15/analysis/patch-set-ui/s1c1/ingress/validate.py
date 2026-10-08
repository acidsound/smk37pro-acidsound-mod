#!/usr/bin/env python3
"""Reproduce the official-v15/H2 S1-C1 guarded-ingress audit.

Read-only by default. This validator hashes and inspects existing artifacts and
exercises a pure Python protocol/state model. It never builds firmware, opens a
device, invokes an uploader, or writes outside this evidence directory.
"""
from __future__ import annotations

import argparse
import copy
import csv
import gzip
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
EVIDENCE_PATH = HERE / "evidence.json"
REPORT_PATH = HERE / "report.md"
OUTPUT_PATH = HERE / "validation.txt"
RUNTIME_BASE = 0x02000000

PREFIX = bytes.fromhex("f07d534d4b0f01")
YAMAHA_PREFIX = bytes.fromhex("f043")
CMD_LOAD0 = 0x11
CMD_LOAD1_COMMIT = 0x12
VOICE_SIZE = 156
PACKET_OVERHEAD = 16
LOAD0_BODY = 157
LOAD1_BODY = 160
LOAD0_TOTAL = 173
LOAD1_TOTAL = 176
EMPTY = 0
LOADING = 1
ARMED = 2


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL\t{message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def app_bytes(data: bytes, address: int, size: int) -> bytes:
    offset = address - RUNTIME_BASE
    require(0 <= offset <= len(data) - size, f"address outside app: 0x{address:08x}")
    return data[offset:offset + size]


def rows_at(path: Path, addresses: set[int]) -> dict[int, dict[str, str]]:
    found: dict[int, dict[str, str]] = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            try:
                address = int(row["address"], 16)
            except (KeyError, ValueError):
                continue
            if address in addresses:
                found[address] = row
    return found


def rows_between(path: Path, start: int, end: int) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            try:
                address = int(row["address"], 16)
            except (KeyError, ValueError):
                continue
            if start <= address <= end:
                found.append(row)
    return found


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def encode_crc(value: int) -> bytes:
    require(0 <= value <= 0xFFFF, "CRC value out of range")
    return bytes((value & 0x7F, (value >> 7) & 0x7F, (value >> 14) & 0x03))


def decode_crc(data: bytes) -> int | None:
    if len(data) != 3 or any(value >= 0x80 for value in data) or data[2] > 3:
        return None
    return data[0] | (data[1] << 7) | (data[2] << 14)


def build_packet(command: int, tx: int, body: bytes, flags: int = 0) -> bytes:
    require(len(body) < 0x4000, "body too large")
    require(all(value < 0x80 for value in body), "body must be seven-bit")
    length = bytes((len(body) & 0x7F, (len(body) >> 7) & 0x7F))
    protected = b"SMK" + bytes((0x0F, 0x01, command, tx, flags)) + length + body
    return bytes((0xF0, 0x7D)) + protected + encode_crc(crc16_ccitt_false(protected)) + b"\xF7"


def canonical_set_bytes(tx: int, note0: int, voice0: bytes, note1: int, voice1: bytes) -> bytes:
    return bytes((0x01, tx, note0)) + voice0 + bytes((note1,)) + voice1


def build_load0(tx: int, note0: int, voice0: bytes, flags: int = 0) -> bytes:
    require(len(voice0) == VOICE_SIZE, "voice0 size")
    return build_packet(CMD_LOAD0, tx, bytes((note0,)) + voice0, flags)


def build_load1(tx: int, note0: int, voice0: bytes, note1: int, voice1: bytes,
                set_crc_override: bytes | None = None, flags: int = 0) -> bytes:
    require(len(voice0) == len(voice1) == VOICE_SIZE, "voice size")
    set_crc = set_crc_override
    if set_crc is None:
        set_crc = encode_crc(crc16_ccitt_false(canonical_set_bytes(tx, note0, voice0, note1, voice1)))
    return build_packet(CMD_LOAD1_COMMIT, tx, bytes((note1,)) + voice1 + set_crc, flags)


@dataclass(eq=True)
class OwnedState:
    state: int = EMPTY
    valid0: int = 0
    valid1: int = 0
    lock: int = 0
    tx: int = 0
    note0: int = 0
    note1: int = 0
    voice0: bytes = field(default_factory=lambda: bytes(VOICE_SIZE))
    voice1: bytes = field(default_factory=lambda: bytes(VOICE_SIZE))


def parse_private(message: bytes) -> tuple[str, dict[str, object] | None]:
    if len(message) < len(PREFIX) or message[:len(PREFIX)] != PREFIX:
        return "DELEGATE", None
    if len(message) < PACKET_OVERHEAD:
        return "REJECT_LENGTH", None
    if message[-1] != 0xF7:
        return "REJECT_TERMINATOR", None
    if any(value >= 0x80 for value in message[1:-1]):
        return "REJECT_7BIT", None

    command, tx, flags = message[7], message[8], message[9]
    body_length = message[10] | (message[11] << 7)
    if len(message) != PACKET_OVERHEAD + body_length:
        return "REJECT_LENGTH", None
    if tx == 0 or tx >= 0x80:
        return "REJECT_TX", None
    if flags != 0:
        return "REJECT_FLAGS", None
    expected_body_length = {CMD_LOAD0: LOAD0_BODY, CMD_LOAD1_COMMIT: LOAD1_BODY}.get(command)
    if expected_body_length is None:
        return "REJECT_COMMAND", None
    if body_length != expected_body_length:
        return "REJECT_LENGTH", None
    expected_total = {CMD_LOAD0: LOAD0_TOTAL, CMD_LOAD1_COMMIT: LOAD1_TOTAL}[command]
    if len(message) != expected_total:
        return "REJECT_LENGTH", None

    body_end = 12 + body_length
    body = message[12:body_end]
    encoded_packet_crc = message[body_end:body_end + 3]
    packet_crc = decode_crc(encoded_packet_crc)
    if packet_crc is None:
        return "REJECT_CRC_ENCODING", None
    if packet_crc != crc16_ccitt_false(message[2:body_end]):
        return "REJECT_PACKET_CRC", None
    return "PRIVATE", {"command": command, "tx": tx, "body": body}


def apply_message(state: OwnedState, message: bytes) -> str:
    disposition, parsed = parse_private(message)
    if disposition != "PRIVATE":
        return disposition
    assert parsed is not None
    command = int(parsed["command"])
    tx = int(parsed["tx"])
    body = bytes(parsed["body"])

    if state.lock != 0:
        return "REJECT_BUSY"

    if command == CMD_LOAD0:
        note0, voice0 = body[0], body[1:]
        if note0 > 0x7F or len(voice0) != VOICE_SIZE:
            return "REJECT_BOUNDS"
        if state.state != EMPTY or state.valid0 != 0 or state.valid1 != 0:
            return "REJECT_STATE"
        state.lock = 1
        try:
            if state.state != EMPTY or state.valid0 != 0 or state.valid1 != 0:
                return "REJECT_STATE"
            state.state = LOADING
            state.tx = tx
            state.note0 = note0
            state.voice0 = voice0
            state.valid0 = 1
            return "ACCEPT_LOAD0"
        finally:
            state.lock = 0

    note1 = body[0]
    voice1 = body[1:1 + VOICE_SIZE]
    encoded_set_crc = body[1 + VOICE_SIZE:]
    if note1 > 0x7F or len(voice1) != VOICE_SIZE:
        return "REJECT_BOUNDS"
    set_crc = decode_crc(encoded_set_crc)
    if set_crc is None:
        return "REJECT_SET_CRC_ENCODING"

    state.lock = 1
    try:
        if state.state != LOADING or state.tx != tx or state.valid0 != 1 or state.valid1 != 0:
            return "REJECT_STATE"
        if note1 == state.note0:
            return "REJECT_DUPLICATE_NOTE"
        expected_set_crc = crc16_ccitt_false(
            canonical_set_bytes(tx, state.note0, state.voice0, note1, voice1)
        )
        if set_crc != expected_set_crc:
            return "REJECT_SET_CRC"
        state.note1 = note1
        state.voice1 = voice1
        state.valid1 = 1
        state.state = ARMED
        return "ACCEPT_ARMED"
    finally:
        state.lock = 0


def assert_no_change(state: OwnedState, message: bytes, expected_prefix: str = "REJECT") -> str:
    before = copy.deepcopy(state)
    result = apply_message(state, message)
    require(result.startswith(expected_prefix), f"expected {expected_prefix}, got {result}")
    require(state == before, f"state changed on {result}")
    return result


def mutate(message: bytes, index: int, value: int) -> bytes:
    data = bytearray(message)
    data[index] = value
    return bytes(data)


def validate() -> str:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    report = REPORT_PATH.read_text(encoding="utf-8")
    require(evidence["format"] == "smk37-v15-h2-s1c1-guarded-ingress-audit-v1", "evidence format")
    scope = evidence["scope"]
    require(scope["official_v15_only"] and scope["h2_only"], "official/H2 scope")
    require(not any((scope["v12_used"], scope["firmware_built"], scope["device_accessed"],
                     scope["flash_performed"], scope["guessed_handler_addresses"])), "read-only scope")

    inputs = {item["id"]: item for item in evidence["inputs"]}
    require(len(inputs) == len(evidence["inputs"]) == 7, "input inventory")
    for item in evidence["inputs"]:
        path = ROOT / item["path"]
        require(path.is_file(), f"missing input {item['path']}")
        require(sha256(path) == item["sha256"], f"SHA-256 mismatch {item['path']}")

    official = (ROOT / inputs["official_app"]["path"]).read_bytes()
    h2 = (ROOT / inputs["h2_app"]["path"]).read_bytes()
    qpath = ROOT / inputs["quarkslab_listing"]["path"]
    kpath = ROOT / inputs["kagaimiq_listing"]["path"]

    exact_common = {
        0x0201E254: bytes.fromhex("7904041619d64a40"),
        0x0202D182: bytes.fromhex("91f942fc"),
        0x0202D1F6: bytes.fromhex("a8815116bfea2b8804856016bfea2788"),
        0x0202D202: bytes.fromhex("bfea2788"),
    }
    for address, expected in exact_common.items():
        require(app_bytes(official, address, len(expected)) == expected, f"official bytes 0x{address:08x}")
        require(app_bytes(h2, address, len(expected)) == expected, f"H2-preserved bytes 0x{address:08x}")

    expected_h2 = {
        0x0201C63E: bytes.fromhex("80fffa1a0000"),
        0x0201C67C: bytes.fromhex("80ffee1a0000"),
        0x0201E468: bytes.fromhex("bfea9bfe"),
        0x0201E46C: bytes.fromhex("bfeaf838"),
        0x0201E49C: bytes.fromhex("bfea81fe"),
        0x0201E4A0: bytes.fromhex("bfeade38"),
        0x0200001E: bytes.fromhex("c2ffeccb0300"),
        0x0205E9F8: bytes.fromhex("c5ffc065c401"),
    }
    for address, expected in expected_h2.items():
        require(app_bytes(h2, address, len(expected)) == expected, f"H2 bytes 0x{address:08x}")

    required_q = {
        0x0201E256: "mov r4,r0",
        0x0201E258: "mov r9,r1",
        0x0201E25A: "r2,[r4 + 0x0]",
        0x0201E3EE: "[r7 + 0x206]",
        0x0201E3F8: "[r7 + 0x104]",
        0x0201E448: "r8,r6,#0xfa0",
        0x0201E44E: "r6,r9,#-0x6",
        0x0201E456: "call 0x02048cce",
        0x0201E462: "r0,#0xf7",
        0x0201E468: "call 0x0201e13e",
        0x0201E46C: "call 0x02005660",
        0x0201E480: "r1,#0xf7",
        0x0201E484: "r5,#0x9e",
        0x0201E49C: "call 0x0201e13e",
        0x0201E4A0: "call 0x02005660",
        0x0202D182: "r1,0xfe",
        0x0202D1B4: "r1,r10,r5",
        0x0202D200: "mov r0,r6",
        0x0202D202: "call 0x0201e254",
        0x0201C62E: "r5,[r1 + 0x1]",
        0x0201C670: "r6,[r1 + 0x1]",
    }
    qrows = rows_at(qpath, set(required_q))
    require(set(qrows) == set(required_q), "Quarkslab row coverage")
    for address, needle in required_q.items():
        require(needle in qrows[address]["text"], f"Quarkslab row 0x{address:08x}")
    krows = rows_at(kpath, {0x0201C62E, 0x0201C670})
    require("r5,[r1 + 0x1]" in krows[0x0201C62E]["text"], "Kagaimiq Note Off row")
    require("r6,[r1 + 0x1]" in krows[0x0201C670]["text"], "Kagaimiq Note On row")

    direct_rows = rows_between(qpath, 0x0201E40E, 0x0201E470)
    direct_text = "\n".join(row["text"] for row in direct_rows).lower()
    require("r6,r9,#-0x6" in direct_text, "direct copy length expression")
    require("r9,#0xa3" not in direct_text and "r9,0xa3" not in direct_text,
            "direct path unexpectedly contains exact 0xa3 gate")

    packet = (ROOT / inputs["live_packet"]["path"]).read_bytes()
    require(len(packet) == 163, "live packet total length")
    require(packet[:6] == bytes.fromhex("f0430000011b"), "live packet header")
    require(packet[-1] == 0xF7, "live packet terminator")
    payload = packet[6:-1]
    require(len(payload) == VOICE_SIZE, "live runtime payload length")
    require(all(value < 0x80 for value in payload), "live runtime payload seven-bit")
    require(payload[-1] == 0x3F, "live runtime payload final byte")
    require(sum(payload) & 0x7F == 8, "live runtime payload sum evidence")
    require((sum(payload) & 0x7F) != 0, "guessed Yamaha sum unexpectedly passes")

    h2_manifest = json.loads((ROOT / inputs["h2_manifest"]["path"]).read_text(encoding="utf-8"))
    require(h2_manifest["layout"]["end"] == "0x0201e1ec", "H2 cave used end")
    require(h2_manifest["h2_policy"]["copy_size"] == 156, "H2 copy size")
    require(h2_manifest["h2_policy"]["lock"] == "0x01c465bd", "H2 lock")
    require(h2_manifest["h2_policy"]["valid"] == "0x01c465bc", "H2 valid")
    require(h2_manifest["h2_policy"]["stock_fallback_r0_restore"] is True, "H2 fallback r0")
    require(h2_manifest["h2_policy"]["stock_fallback_preserves_original_r1_r2"] is True,
            "H2 fallback r1/r2")

    ram = evidence["ram"]
    base = int(ram["base"], 16)
    end = int(ram["end_exclusive"], 16)
    official_heap = int(ram["official_heap_begin"], 16)
    h2_heap = int(ram["h2_heap_begin"], 16)
    proposed_heap = int(ram["proposed_heap_begin"], 16)
    heap_end = int(ram["heap_end"], 16)
    require(end - base == ram["total_size"] == 0x140, "two-slot reservation")
    require(proposed_heap == end, "heap starts after reservation")
    require(proposed_heap - h2_heap == ram["additional_beyond_h2"] == 0xA0, "H2 RAM delta")
    require(heap_end - official_heap == ram["official_heap_size"] == 0x39810, "official heap")
    require(heap_end - h2_heap == ram["h2_remaining_heap"] == 0x39770, "H2 heap")
    require(heap_end - proposed_heap == ram["proposed_remaining_heap"] == 0x396D0, "S1-C1 heap")

    code = evidence["code"]
    start = int(code["h2_replacement_start"], 16)
    bound = int(code["h2_replacement_end_exclusive"], 16)
    used_end = int(code["h2_used_end_exclusive"], 16)
    require(bound - start == code["h2_replacement_capacity"] == 278, "H2 cave capacity")
    require(used_end - start == code["h2_used_bytes"] == 174, "H2 cave use")
    require(bound - used_end == code["remaining_audited_bytes"] == 104, "H2 cave remainder")
    require(code["placement_gate"] == "BLOCK" and not code["second_owned_executable_region"],
            "placement remains blocked")

    voice0 = payload
    voice1_data = bytearray(payload)
    voice1_data[0] ^= 0x01
    voice1 = bytes(voice1_data)
    tx, note0, note1 = 37, 36, 45
    load0 = build_load0(tx, note0, voice0)
    load1 = build_load1(tx, note0, voice0, note1, voice1)
    require(len(load0) == LOAD0_TOTAL == 173, "LOAD0 length")
    require(len(load1) == LOAD1_TOTAL == 176, "LOAD1 length")
    require(len(load0) < 0xFE and len(load1) < 0xFE, "packets below assembly threshold")
    require(PACKET_OVERHEAD + 2 + 2 * VOICE_SIZE + 3 == 333 > 0xFE, "one-message floor")

    state = OwnedState()
    require(apply_message(state, packet) == "DELEGATE", "Yamaha live packet delegates")
    require(state == OwnedState(), "Yamaha delegation changed private state")
    require(apply_message(state, bytes.fromhex("f04310000000f7")) == "DELEGATE", "Yamaha parameter packet delegates")
    require(state == OwnedState(), "Yamaha parameter delegation changed private state")
    require(apply_message(state, bytes.fromhex("f07e7f0601f7")) == "DELEGATE", "non-private SysEx delegates")

    negative_state = OwnedState()
    assert_no_change(negative_state, load0[:-1], "REJECT")
    assert_no_change(negative_state, load0 + b"\xF7", "REJECT")
    assert_no_change(negative_state, mutate(load0, 9, 1), "REJECT")
    assert_no_change(negative_state, build_load0(0, note0, voice0), "REJECT")
    assert_no_change(negative_state, build_packet(0x13, tx, b""), "REJECT")
    assert_no_change(negative_state, mutate(load0, 12, 0x80), "REJECT")
    assert_no_change(negative_state, mutate(load0, 20, load0[20] ^ 1), "REJECT")
    bad_length = bytearray(load0)
    bad_length[10] ^= 1
    assert_no_change(negative_state, bytes(bad_length), "REJECT")
    busy = OwnedState(lock=1)
    assert_no_change(busy, load0, "REJECT_BUSY")
    h2_claimed = OwnedState(valid0=1, voice0=voice0)
    assert_no_change(h2_claimed, load0, "REJECT_STATE")

    require(apply_message(state, load0) == "ACCEPT_LOAD0", "LOAD0 acceptance")
    require(state.state == LOADING and state.valid0 == 1 and state.valid1 == 0, "LOAD0 state")
    require(state.tx == tx and state.note0 == note0 and state.voice0 == voice0, "LOAD0 data")

    assert_no_change(state, load0, "REJECT_STATE")
    wrong_tx = build_load1(tx + 1, note0, voice0, note1, voice1)
    assert_no_change(state, wrong_tx, "REJECT_STATE")
    duplicate = build_load1(tx, note0, voice0, note0, voice1)
    assert_no_change(state, duplicate, "REJECT_DUPLICATE_NOTE")
    bad_set_crc = encode_crc(crc16_ccitt_false(canonical_set_bytes(tx, note0, voice0, note1, voice1)) ^ 1)
    assert_no_change(state, build_load1(tx, note0, voice0, note1, voice1, bad_set_crc), "REJECT_SET_CRC")
    assert_no_change(state, build_load1(tx, note0, voice0, note1, voice1, bytes((0, 0, 4))),
                     "REJECT_SET_CRC_ENCODING")
    corrupt_load1 = mutate(load1, 50, load1[50] ^ 1)
    assert_no_change(state, corrupt_load1, "REJECT_PACKET_CRC")

    require(apply_message(state, load1) == "ACCEPT_ARMED", "LOAD1/COMMIT acceptance")
    require(state.state == ARMED and state.valid0 == state.valid1 == 1, "ARMED state")
    require(state.note0 == note0 and state.note1 == note1, "armed notes")
    require(state.voice0 == voice0 and state.voice1 == voice1, "armed voices")
    armed = copy.deepcopy(state)
    assert_no_change(state, load0, "REJECT_STATE")
    assert_no_change(state, load1, "REJECT_STATE")
    require(state == armed, "armed immutability")

    # Every single-bit change after the fixed private prefix must be rejected and
    # must not alter EMPTY state. CRC-16 detects all single-bit errors here.
    bitflip_checks = 0
    for original in (load0, load1):
        for index in range(len(PREFIX), len(original)):
            for bit in range(8):
                changed = original[index] ^ (1 << bit)
                candidate = mutate(original, index, changed)
                trial = OwnedState()
                result = apply_message(trial, candidate)
                require(result.startswith("REJECT"), f"bit flip accepted at {index}:{bit} ({result})")
                require(trial == OwnedState(), f"bit flip mutated state at {index}:{bit}")
                bitflip_checks += 1

    required_report_markers = [
        "**Protocol and two-slot publication design: PASS. Firmware implementation: BLOCK.**",
        "The direct path does not prove `r9 == 0xa3`",
        "LOAD0`, 173 bytes",
        "LOAD1_COMMIT`, 176 bytes",
        "0x01c46520..0x01c465bc",
        "0x01c46660",
        "Exact official-v15 stock pack/SAVE semantics",
        "Host ACK/NAK",
    ]
    for marker in required_report_markers:
        require(marker in report, f"report marker {marker}")

    lines = [
        "S1-C1 guarded ingress validation",
        "RESULT\tPASS",
        f"PASS\tinputs\t{len(inputs)} exact official-v15/H2 artifacts SHA-256 gated",
        "PASS\tparser-path\t0x0202d202 completed-message ABI; 0x0201e254 r0/r1 -> r4/r9",
        "PASS\taccepted-packet\t163 bytes; 156-byte seven-bit runtime payload; no inherited exact-length/checksum claim",
        "PASS\tstock-separation\tprivate F0 7D SMK; Yamaha F0 43 delegates unchanged to H2",
        "PASS\ttransaction\tLOAD0=173 LOAD1_COMMIT=176; one-message floor=333 > 0xfe",
        "PASS\tram\t0x01c46520..0x01c46660 size=0x140; H2 delta=0xa0",
        "PASS\tstate-machine\tEMPTY->LOADING->ARMED; valid/ARMED last; immutable after ARMED",
        f"PASS\trejection-model\t{bitflip_checks} single-bit packet mutations plus length/state/bounds/CRC/replay cases",
        f"PASS\tvectors\tLOAD0 sha256={hashlib.sha256(load0).hexdigest()} LOAD1 sha256={hashlib.sha256(load1).hexdigest()}",
        "BLOCK\timplementation\texecutable placement, exact code size, heap headroom, note ABI, ACK/NAK",
        "BLOCK\tofficial-stock-pack-save\tH2 parent semantics are preserved, not official persistent pack/SAVE semantics",
        "SCOPE\tno firmware build; no device; no flash; no v12; no guessed handler address",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-output", action="store_true")
    args = parser.parse_args()
    output = validate()
    if args.write_output:
        OUTPUT_PATH.write_text(output, encoding="utf-8")
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
