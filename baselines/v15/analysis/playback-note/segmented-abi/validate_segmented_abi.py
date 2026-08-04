#!/usr/bin/env python3
"""Offline verifier for the v15/S1-C4 segmented-final SysEx ABI.

Reads only pinned repo artifacts. Does not open USB/MIDI, flash, OTA, or reset.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = 0x02000000
STAGE_BASE = 0x01C37FD0
STAGE_ROOT = 0x01C37030
STAGE_ADDEND = 0x0FA0
PRODUCT_PAYLOAD_LEN = 0x9C
SEGMENTED_ACCEPT_TOTAL = 0x9E
DIRECT_SYSEX_LEN = 0xA3
HEADER_LEN = 6
PLAYBACK_PAYLOAD_OFFSET = 0x9B
PLAYBACK_WIRE_OFFSET = HEADER_LEN + PLAYBACK_PAYLOAD_OFFSET
S1C4 = ROOT / "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v2-failclosed"
S1C3 = ROOT / "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload"
CODE = ROOT / "baselines/v15/analysis/playback-note/candidate-v2-failclosed"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"

EXPECTED_SHA = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c3_app": "7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b",
    "s1c4_app": "66ac465cc058682ee015e0f1b980da6593b09ac345f4f7d5abd6396077b46b25",
    "s1c4_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "s1c4_selector": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "s1c4_producer": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
}
EXPECTED_ROWS = {
    0x0201E254: ("7904", "push", "push {rets,r9,r8,r7,r6,r5,r4}"),
    0x0201E256: ("0416", "mov", "mov r4,r0"),
    0x0201E258: ("19d6", "mov", "mov r9,r1"),
    0x0201E3F8: ("50ee7401", "lb.z", "lb.z r0,[r7 + 0x104]"),
    0x0201E3FC: ("c6ff3070c301", "mov", "mov r6,#0x1c37030"),
    0x0201E402: ("00f83604", "je", "je r0,0x2,0x0201e472"),
    0x0201E57A: ("4021", "mov", "mov r0,#0x1"),
    0x0201E580: ("00e1a06f", "add", "add r0,r6,#0xfa0"),
    0x0201E584: ("4986", "add", "add r1,r4,#0x6"),
    0x0201E586: ("34e1fa9f", "add", "add r4,r9,#-0x6"),
    0x0201E58A: ("4216", "mov", "mov r2,r4"),
    0x0201E58C: ("80ff3ca70200", "call", "call 0x02048cce"),
    0x0201E592: ("50ed7d49", "sh", "sh r4,[r7 + 0x9c]"),
    0x0201E472: ("50ed7c09", "lh.z", "lh.z r0,[r7 + 0x9c]"),
    0x0201E476: ("b4e04019", "add", "add r1,r4,r9"),
    0x0201E47A: ("b4f00059", "add", "add r5,r0,r9"),
    0x0201E47E: ("195f", "_lb.z", "_lb.z r1,[r1 + -0x1]"),
    0x0201E480: ("91f849ee", "jne", "jne r1,#0xf7"),
    0x0201E484: ("95f8583c", "jne", "jne r5,#0x9e"),
    0x0201E488: ("06e1a06f", "add", "add r6,r6,#0xfa0"),
    0x0201E48C: ("6018", "add", "add r0,r6"),
    0x0201E48E: ("32e1fe9f", "add", "add r2,r9,#-0x2"),
    0x0201E492: ("4116", "mov", "mov r1,r4"),
    0x0201E494: ("80ff34a80200", "call", "call 0x02048cce"),
    0x0201E49A: ("6016", "mov", "mov r0,r6"),
    0x0201E49C: ("bfea4ffe", "call", "call 0x0201e13e"),
    0x0201E4A0: ("bfeade38", "call", "call 0x02005660"),
    0x0201E4A4: ("2489", "goto", "goto 0x0201e538"),
    0x0201E538: ("4020", "mov", "mov r0,#0x0"),
    0x0201E53A: ("52ee7401", "sb", "sb r0,[r7 + 0x14]"),
}

S1C4_PRODUCER_ROWS = {
    0x0201E1E8: "producer.staging_last_pointer",
    0x0201E1EC: "producer.playback_load",
    0x0201E1EE: "producer.playback_store",
    0x0201E1F2: "producer.restore_staging_last",
    0x0201E1FA: "producer.memcpy_call",
    0x0201E202: "producer.restore_slot_last",
    0x0201E208: "producer.valid_store",
    0x0201E20E: "producer.count_store",
    0x0201E218: "producer.armed_store",
    0x0201E224: "producer.segmented_stub_push",
    0x0201E226: "producer.segmented_stub_return",
    0x0201E228: "producer.reset_push_saved",
    0x0201E24A: "producer.reset_call_producer",
}

def sha_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def app_off(addr: int) -> int:
    return addr - BASE

def short_call(at: int, target: int) -> bytes:
    half = ((target - (at + 4)) // 2) & 0xFFFF
    return b"\xbf\xea" + struct.pack("<H", half)

def short_target(at: int, blob: bytes) -> int:
    return ((at + 4 + struct.unpack("<H", blob[2:4])[0] * 2) & 0xFFFF) | (at & 0xFFFF0000)

def load_listing_rows() -> dict[int, dict[str, str]]:
    wanted = set(EXPECTED_ROWS)
    rows: dict[int, dict[str, str]] = {}
    with gzip.open(LISTING, "rt", errors="replace") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            if addr in wanted:
                rows[addr] = {
                    "address": f"0x{addr:08x}",
                    "bytes": parts[1],
                    "mnemonic": parts[3],
                    "text": parts[4],
                    "flow": parts[5],
                }
    missing = sorted(wanted - set(rows))
    if missing:
        raise AssertionError("missing listing rows: " + ", ".join(f"0x{x:08x}" for x in missing))
    for addr, (hexbytes, mnemonic, text) in EXPECTED_ROWS.items():
        row = rows[addr]
        if row["bytes"] != hexbytes or row["mnemonic"] != mnemonic or row["text"] != text:
            raise AssertionError(f"row mismatch at 0x{addr:08x}: {row}")
    return rows

def validate_hashes_and_callsites() -> dict[str, object]:
    official = OFFICIAL_APP.read_bytes()
    s1c3 = (S1C3 / "app.bin").read_bytes()
    s1c4 = (S1C4 / "app.bin").read_bytes()
    combined = (CODE / "combined.bin").read_bytes()
    selector = (CODE / "selector.bin").read_bytes()
    producer = (CODE / "producer.bin").read_bytes()
    checks = {
        "official_app": sha_bytes(official),
        "s1c3_app": sha_bytes(s1c3),
        "s1c4_app": sha_bytes(s1c4),
        "s1c4_combined": sha_bytes(combined),
        "s1c4_selector": sha_bytes(selector),
        "s1c4_producer": sha_bytes(producer),
    }
    for key, got in checks.items():
        if got != EXPECTED_SHA[key]:
            raise AssertionError(f"{key} sha mismatch: {got}")
    callsites = {
        "official_direct": (0x0201E468, official[app_off(0x0201E468):app_off(0x0201E468)+4], 0x0201E13E),
        "official_segmented": (0x0201E49C, official[app_off(0x0201E49C):app_off(0x0201E49C)+4], 0x0201E13E),
        "s1c3_direct": (0x0201E468, s1c3[app_off(0x0201E468):app_off(0x0201E468)+4], 0x0201E226),
        "s1c3_segmented": (0x0201E49C, s1c3[app_off(0x0201E49C):app_off(0x0201E49C)+4], 0x0201E222),
        "s1c4_direct": (0x0201E468, s1c4[app_off(0x0201E468):app_off(0x0201E468)+4], 0x0201E228),
        "s1c4_segmented_current": (0x0201E49C, s1c4[app_off(0x0201E49C):app_off(0x0201E49C)+4], 0x0201E224),
    }
    decoded = {}
    for name, (addr, blob, expected_target) in callsites.items():
        target = short_target(addr, blob)
        if target != expected_target:
            raise AssertionError(f"{name} target 0x{target:08x} != 0x{expected_target:08x}")
        decoded[name] = {"address": f"0x{addr:08x}", "bytes": blob.hex(), "target": f"0x{target:08x}"}
    decoded["s1c4_segmented_safe_retarget_to_reset_wrapper"] = {
        "address": "0x0201e49c",
        "bytes": short_call(0x0201E49C, 0x0201E228).hex(),
        "target": "0x0201e228",
        "status": "not applied by this evidence pass",
    }
    for rel in ["decode.tsv", "evidence.json"]:
        if not (CODE / rel).exists():
            raise AssertionError(f"missing {CODE / rel}")
    decode = (CODE / "decode.tsv").read_text().splitlines()
    by_addr = {}
    for line in decode[1:]:
        parts = line.split("\t")
        if len(parts) >= 4:
            by_addr[int(parts[0], 16)] = parts
    producer_rows = {}
    for addr, name in S1C4_PRODUCER_ROWS.items():
        parts = by_addr.get(addr)
        if not parts or parts[3] != name:
            raise AssertionError(f"missing producer decode row {name} at 0x{addr:08x}")
        producer_rows[f"0x{addr:08x}"] = {"bytes": parts[2], "name": parts[3], "asm": parts[4], "meaning": parts[5] if len(parts) > 5 else ""}
    return {"sha256": checks, "callsites": decoded, "s1c4_producer_rows": producer_rows}

def model_split(previous_len: int, playback_value: int) -> dict[str, object]:
    if not (0 <= previous_len <= PRODUCT_PAYLOAD_LEN):
        raise ValueError("previous_len outside staged payload range")
    if not (0 <= playback_value <= 127):
        raise ValueError("playback_value outside MIDI byte range")
    payload = bytearray((i * 17 + 3) & 0x7F for i in range(PRODUCT_PAYLOAD_LEN))
    payload[PLAYBACK_PAYLOAD_OFFSET] = playback_value
    direct = bytes.fromhex("f0430000011b") + bytes(payload) + b"\xf7"
    assert len(direct) == DIRECT_SYSEX_LEN and direct[PLAYBACK_WIRE_OFFSET] == playback_value
    current_len = SEGMENTED_ACCEPT_TOTAL - previous_len
    final_chunk = bytes(payload[previous_len:]) + b"\x00\xf7"
    assert len(final_chunk) == current_len
    stage = bytearray(b"\xee" * PRODUCT_PAYLOAD_LEN)
    stage[:previous_len] = payload[:previous_len]
    # Exact official final copy: memcpy(stage + previous, final_chunk, current_len - 2).
    if final_chunk[-1] != 0xF7 or previous_len + current_len != SEGMENTED_ACCEPT_TOTAL:
        raise AssertionError("modeled final gates failed")
    stage[previous_len:previous_len + current_len - 2] = final_chunk[:current_len - 2]
    if bytes(stage) != bytes(payload):
        raise AssertionError("segmented stage did not reconstruct product payload")
    return {
        "previous_len": previous_len,
        "final_chunk_len_r9": current_len,
        "final_copy_len_r2": current_len - 2,
        "accepted_total_previous_plus_r9": previous_len + current_len,
        "assembled_stage_payload_len": len(stage),
        "direct_wire_playback_offset": PLAYBACK_WIRE_OFFSET,
        "stage_playback_offset": PLAYBACK_PAYLOAD_OFFSET,
        "playback_value": playback_value,
        "stage_byte_0x9b": stage[PLAYBACK_PAYLOAD_OFFSET],
        "playback_byte_source": "initial chunk" if previous_len > PLAYBACK_PAYLOAD_OFFSET else "final chunk",
    }

def build_evidence() -> dict[str, object]:
    rows = load_listing_rows()
    artifact_checks = validate_hashes_and_callsites()
    splits = [model_split(prev, val) for prev, val in [(0, 36), (1, 37), (80, 64), (155, 127), (156, 0)]]
    evidence = {
        "format": "smk37-v15-playback-note-segmented-abi-evidence-v1",
        "decision": "PASS_STATIC_ABI_PROVEN_CURRENT_S1C4_SEGMENTED_ROUTE_BLOCKED",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False},
        "stage": {"root": "0x01c37030", "addend": "0x0fa0", "base": "0x01c37fd0", "product_payload_len": PRODUCT_PAYLOAD_LEN, "playback_payload_offset": PLAYBACK_PAYLOAD_OFFSET, "direct_wire_playback_offset": PLAYBACK_WIRE_OFFSET},
        "handler_register_abi": {
            "entry": {"r0": "incoming chunk pointer", "r1": "incoming chunk length", "r4": "saved chunk pointer", "r9": "saved chunk length", "r7": "0x01c33260 object/control base", "r6": "0x01c37030 before +0x0fa0 stage addend"},
            "initial_segmented": {"gate": "F0 43 00 09 20 00 reaches 0x0201e57a", "copy": "memcpy(0x01c37fd0, chunk+6, r9-6)", "published_offset": "sh (r9-6), [r7+0x9c]", "no_product_call": True},
            "final_segmented": {"state_gate": "[r7+0x104] == 2 branches to 0x0201e472", "previous_len": "r0 = lh.z [r7+0x9c]", "terminal_gate": "*(r4+r9-1) == 0xf7", "length_gate": "previous_len + r9 == 0x9e", "copy": "memcpy(0x01c37fd0 + previous_len, r4, r9 - 2)", "producer_call_arg": "r0 = 0x01c37fd0", "r9_at_product_call": "final chunk length, not 0xa3 and not total", "reload_after_product": "0x0201e4a0 -> 0x02005660", "cleanup_after_reload": "goto 0x0201e538 clears segmented state then returns"},
        },
        "official_listing_rows": rows,
        **artifact_checks,
        "split_models": splits,
        "safe_publication": {
            "requirement": "publish from assembled stage[0x9b], never from r4/r9/final chunk offsets",
            "why": "official final ABI has already reconstructed 0x9c payload bytes at 0x01c37fd0 and passes r0=stage; r9 is final chunk length only",
            "s1c4_producer_satisfies_stage_read_order": True,
            "current_blocker": "S1-C4 v2 failclosed routes 0x0201e49c to 0x0201e224 no-mutation stub, so split accepted final packets cannot publish playback byte",
            "minimal_safe_retarget": "0x0201e49c short call bytes bfeac4fe -> reset wrapper 0x0201e228; this preserves reset lifecycle and then calls producer 0x0201e196",
            "not_done_here": "No firmware/package was modified or flashed by this investigation",
        },
        "blockers": [
            "Current committed S1-C4 v2 package is fail-closed for segmented final because 0x0201e49c targets the stub at 0x0201e224.",
            "A future flashable fix needs deterministic rebuild/review/rollback of a package with segmented callsite 0x0201e49c retargeted to reset wrapper 0x0201e228 or an equivalently reviewed segmented-safe entry.",
            "This static pass proves the firmware ABI once the official segmented-final path is entered. It does not live-prove Chrome/CoreMIDI scheduling or device state that selects that path."
        ],
    }
    return evidence

def write_outputs(evidence: dict[str, object]) -> None:
    (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    lines = [
        "segmented-final ABI validation PASS",
        f"stage_base={evidence['stage']['base']} payload_len=0x{PRODUCT_PAYLOAD_LEN:x} playback_payload_offset=0x{PLAYBACK_PAYLOAD_OFFSET:x} direct_wire_offset={PLAYBACK_WIRE_OFFSET}",
        "official_final_copy=memcpy(stage+previous_len, r4, r9-2); gate previous_len+r9==0x9e; product call r0=stage",
        "current_s1c4_segmented_call=0x0201e49c bfeac2fe -> 0x0201e224 stub BLOCKS split publication",
        "safe_retarget_candidate=0x0201e49c bfeac4fe -> 0x0201e228 reset wrapper; not applied here",
    ]
    (HERE / "validation.txt").write_text("\n".join(lines) + "\n")
    tracked = ["validate_segmented_abi.py", "evidence.json", "validation.txt", "report.md"]
    sums = []
    for name in tracked:
        p = HERE / name
        if p.exists():
            sums.append(f"{sha_path(p)}  {name}")
    (HERE / "SHA256SUMS").write_text("\n".join(sums) + "\n")

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write evidence.json, validation.txt, and SHA256SUMS")
    args = ap.parse_args()
    evidence = build_evidence()
    if args.write:
        write_outputs(evidence)
    print("segmented-final ABI validation PASS")
    print("current S1-C4 segmented route: 0x0201e49c bfeac2fe -> 0x0201e224 stub")
    print("safe retarget candidate: 0x0201e49c bfeac4fe -> 0x0201e228 reset wrapper, not applied")

if __name__ == "__main__":
    main()
