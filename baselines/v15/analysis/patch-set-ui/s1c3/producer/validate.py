#!/usr/bin/env python3
"""Offline validator for the S1-C3 sequential 16-packet producer design.

This validator is intentionally read-only. It checks the S1-C2 source artifact
hashes, the S1-C3 packet/order contract, RAM layout arithmetic, publication
state-machine invariants, and explicit PASS/BLOCK verdicts. It does not build
firmware, open USB/MIDI, flash, reset, or create a sender.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
EVIDENCE = HERE / "evidence.json"

HEADER = bytes.fromhex("f0430000011b")
TERM = 0xF7
BASE = 0x01C46520
STRIDE = 0xA0
VOICE = 0x9C
SLOTS = 16
FIRST_NOTE = 36
DIRECT_TOTAL = 163
USB_MIDI_EVENT = 4

EXPECTED_INPUT_HASHES = {
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/report.md": "d5702f534ee8ab6e07f76f33bf57bd0800c75cb12f1f7bbaf8cbe263872c1a03",
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/evidence.json": "97c1cc6ff3bdb3e469fbedf0c577fcee33036a5ea0d685beb5bd71bb177ca81c",
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/app-manifest.json": "15e9626b16820d2ba4b14a5bbb6310d1924af0bd7fe9c09ab77aca705d2c7a43",
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/host_sender_dry_run.py": "1ddabc4390810d3d94c7152fad963fb8ed8a970fce0e8d9a71c91f8c9757a75f",
    "tools/smk37_v15_s1c2_send.c": "b0cbdda2428518d0363364268b15cdfa98367c2af98d0d660e60a272e8939e0d",
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/host/packets/slot0-note36-direct-product-163.bin": "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27",
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/host/packets/slot1-note45-direct-product-163.bin": "c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d",
    "baselines/v15/analysis/patch-set-ui/data-model/report.md": "cb56e93fdaa355a21ab2c3e59ba778ec13a45647eaac98a654b19df82288df24",
    "baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/report.md": "9420aac5108549d10fb0a39dc8ce894eedb233e0cb96113e2756621f433050d0",
    "baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer/report.md": "bc25c10cfbbd2fa7e5f41d64b3b255d6c5e5caacdd978a410f39dc1a450ab44f",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def parse_hex_int(value: str) -> int:
    return int(value, 16)


def parse_range(value: str) -> tuple[int, int]:
    left, right = value.split("..", 1)
    return parse_hex_int(left), parse_hex_int(right)


def usb_midi_packetized_len(sysex_len: int) -> tuple[int, int, int]:
    events = (sysex_len + 2) // 3
    remaining = sysex_len % 3
    if remaining == 0:
        cin = 0x07
    elif remaining == 1:
        cin = 0x05
    else:
        cin = 0x06
    return events, events * USB_MIDI_EVENT, cin


def simulate_state_machine(packet_count: int) -> dict[str, Any]:
    state = 0
    loaded = 0
    valid = [0] * SLOTS
    log: list[str] = []
    for packet_index in range(packet_count):
        if state == 2 or loaded == SLOTS:
            log.append(f"packet{packet_index + 1}:reject")
            continue
        if state == 0:
            require(loaded == 0, "EMPTY requires loaded_count 0")
            state = 1
        require(state == 1, "mutation only while LOADING")
        slot = loaded
        valid[slot] = 0
        # copy 0x9c bytes would occur here
        valid[slot] = 1
        loaded = slot + 1
        if slot == SLOTS - 1:
            require(all(item == 1 for item in valid), "all valids before ARMED")
            require(loaded == SLOTS, "loaded_count 16 before ARMED")
            state = 2
            log.append(f"packet{packet_index + 1}:slot{slot}:valid-last:armed-last")
        else:
            log.append(f"packet{packet_index + 1}:slot{slot}:valid-last")
    return {"state": state, "loaded_count": loaded, "valid": valid, "log": log}


def main() -> int:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    require(evidence["scope"]["offline_only"] is True, "offline-only scope")
    for forbidden in ("firmware_built", "fwsc_built", "device_accessed", "midi_transport_opened", "flash_performed", "reset_performed"):
        require(evidence["scope"][forbidden] is False, f"no {forbidden}")
    require(evidence["verdict"]["offline_design"] == "PASS", "offline PASS verdict")
    require(evidence["verdict"]["firmware_candidate_or_live_send"] == "BLOCK", "firmware/live BLOCK verdict")

    for rel, digest in EXPECTED_INPUT_HASHES.items():
        path = ROOT / rel
        require(path.exists(), f"input exists: {rel}")
        require(sha256_file(path) == digest, f"input sha256: {rel}")

    basis = evidence["s1c2_live_pass_basis"]
    producer = basis["producer"]
    require(producer["entry"] == "0x0201e1a2", "S1-C2 producer entry")
    require(producer["segmented_stub"] == "0x0201e232", "S1-C2 segmented stub")
    require(producer["bytes"] == 148, "S1-C2 producer bytes")
    require(producer["owned_range_bytes"] == 178, "owned executable range")
    require(producer["remaining_margin_bytes"] == 30, "S1-C2 byte margin")
    require(producer["bytes"] + producer["remaining_margin_bytes"] == producer["owned_range_bytes"], "producer byte arithmetic")

    routes = basis["call_routes"]
    require(routes["direct_callsite"] == "0x0201e468" and routes["direct_call_bytes"] == "bfea9bfe", "direct route pinned")
    require(routes["segmented_callsite"] == "0x0201e49c" and routes["segmented_call_bytes"] == "bfeac9fe", "segmented route pinned to stub")
    require(routes["direct_reload_bytes"] == "bfeaf838", "direct reload intact")
    require(routes["segmented_reload_bytes"] == "bfeade38", "segmented reload intact")

    wire = evidence["wire_contract"]
    require(wire["accepted_route"] == "direct_product_only", "direct-only accepted route")
    require(wire["rejected_route"] == "segmented_product_callsite_routes_to_no_mutation_stub", "segmented reject")
    require(bytes.fromhex(wire["sys_ex_header_hex"]) == HEADER, "header bytes")
    require(int(wire["terminator_hex"], 16) == TERM, "terminator byte")
    require(wire["direct_total_length_bytes"] == DIRECT_TOTAL, "direct packet length")
    require(wire["voice_payload_bytes"] == VOICE, "voice payload size")
    require(len(HEADER) + VOICE + 1 == DIRECT_TOTAL, "SysEx framing arithmetic")
    require(int(wire["completed_message_r9_required"], 16) == DIRECT_TOTAL, "r9 length gate")
    events, bytes_out, cin = usb_midi_packetized_len(DIRECT_TOTAL)
    require(events == wire["usb_midi_event_count_per_packet"], "USB-MIDI event count")
    require(bytes_out == wire["usb_midi_bytes_per_packet"], "USB-MIDI byte count")
    require(cin == int(wire["final_usb_midi_cin"], 16), "USB-MIDI final CIN")

    host_order = wire["host_order"]
    require(len(host_order) == SLOTS, "host has 16 packets")
    for expected_slot, item in enumerate(host_order):
        require(item["order"] == expected_slot + 1, f"order {expected_slot}")
        require(item["slot"] == expected_slot, f"slot {expected_slot}")
        require(item["note"] == FIRST_NOTE + expected_slot, f"note {expected_slot}")

    ram = evidence["ram_layout"]
    require(parse_hex_int(ram["base"]) == BASE, "RAM base")
    require(ram["slot_count"] == SLOTS, "RAM slot count")
    require(parse_hex_int(ram["slot_stride"]) == STRIDE, "slot stride")
    require(parse_hex_int(ram["voice_size"]) == VOICE, "voice size")
    require(parse_hex_int(ram["end_exclusive"]) == BASE + SLOTS * STRIDE, "RAM end")
    require(ram["total_bytes"] == SLOTS * STRIDE, "RAM total bytes")
    require(ram["publication_bytes"]["global_lock"] == "0x01c465bd", "H2 lock preserved")
    require(ram["publication_bytes"]["loaded_count"] == "0x01c465be", "loaded_count byte")
    require(ram["publication_bytes"]["state"] == "0x01c465bf", "state byte")
    require(ram["states"] == {"EMPTY": 0, "LOADING": 1, "ARMED": 2}, "state values")
    require(ram["placement_status"] == "BLOCK_UNTIL_HEAP_HEADROOM_PROVEN", "heap placement block retained")

    previous_end = BASE
    for slot, item in enumerate(ram["slot_ranges"]):
        expected_base = BASE + slot * STRIDE
        voice_start, voice_end = parse_range(item["voice"])
        valid = parse_hex_int(item["valid"])
        require(item["slot"] == slot, f"slot range id {slot}")
        require(item["note"] == FIRST_NOTE + slot, f"slot note {slot}")
        require(voice_start == expected_base, f"slot base {slot}")
        require(voice_end == expected_base + VOICE, f"slot voice end {slot}")
        require(valid == expected_base + VOICE, f"slot valid {slot}")
        require(voice_start >= previous_end, f"slot non-overlap {slot}")
        previous_end = expected_base + STRIDE
    require(previous_end == BASE + SLOTS * STRIDE, "slot range final end")

    sim16 = simulate_state_machine(16)
    require(sim16["state"] == 2, "16th packet arms")
    require(sim16["loaded_count"] == 16, "loaded_count after 16")
    require(all(item == 1 for item in sim16["valid"]), "all slots valid after 16")
    require(sim16["log"][-1].endswith("armed-last"), "ARMED last on slot15")
    sim17 = simulate_state_machine(17)
    require(sim17["log"][-1] == "packet17:reject", "later packet rejected")

    pi32 = evidence["pi32_abi_and_budget"]
    require(pi32["must_fit_range"] == "0x0201e1a2..0x0201e254", "PI32 fit range")
    require(pi32["must_fit_bytes"] == 178, "PI32 fit bytes")
    require(pi32["s1c2_current_bytes"] == 148, "PI32 S1-C2 current bytes")
    require(pi32["s1c2_current_margin_bytes"] == 30, "PI32 S1-C2 margin")
    require(pi32["code_budget_status"] == "BLOCK_UNTIL_EXACT_ASSEMBLED_PI32_BYTES_FIT_178_BYTES", "PI32 budget block retained")
    require(len(pi32["s1c3_minimum_new_capabilities"]) >= 6, "S1-C3 capability deltas listed")

    print("S1-C3 sequential 16-packet producer offline validation: PASS")
    print("Explicit firmware/live verdict: BLOCK")
    print("Checked: S1-C2 exact basis, host protocol, RAM layout, state machine, ABI/budget gates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
